#include "pn532.h"
#include "esphome/core/log.h"

// Based on:
// - https://cdn-shop.adafruit.com/datasheets/PN532C106_Application+Note_v1.2.pdf
// - https://www.nxp.com/docs/en/nxp/application-notes/AN133910.pdf
// - https://www.nxp.com/docs/en/nxp/application-notes/153710.pdf

namespace esphome {
namespace pn532 {

static const char *TAG = "pn532";

void format_uid(char *buf, const uint8_t *uid, uint8_t uid_length) {
  int offset = 0;
  for (uint8_t i = 0; i < uid_length; i++) {
    const char *format = "%02X";
    if (i + 1 < uid_length)
      format = "%02X-";
    offset += sprintf(buf + offset, format, uid[i]);
  }
}

void PN532::set_card_type(const std::string &card_type) { this->card_type_ = card_type; }
std::string PN532::get_card_type() {
  if (this->card_type_.length() > 0)
    return this->card_type_;
  return "classic";
}

void PN532::setup() {
  ESP_LOGCONFIG(TAG, "Setting up PN532...");
  this->spi_setup();

  gi_PN532.pn_is_ready_ = this->is_ready_;
  gi_PN532.pn_pn532_write_command_ = this->pn532_write_command_;
  gi_PN532.pn_enable = this->enable;
  gi_PN532.pn_write_byte = this->write_byte;
  gi_PN532.pn_read_array = this->read_array;
  gi_PN532.pn_disable = this->disable;
  gi_PN532.pn_read_byte = this->read_byte;

  // Wake the chip up from power down
  // 1. Enable the SS line for at least 2ms
  // 2. Send a dummy command to get the protocol synced up
  //    (this may time out, but that's ok)
  // 3. Send SAM config command with normal mode without waiting for ready bit (IRQ not initialized yet)
  // 4. Probably optional, send SAM config again, this time checking ACK and return value
  this->cs_->digital_write(false);
  delay(10);

  // send dummy firmware version command to get synced up
  this->pn532_write_command_check_ack_({0x02});  // get firmware version command
  // do not actually read any data, this should be OK according to datasheet

  this->pn532_write_command_({
      0x14,  // SAM config command
      0x01,  // normal mode
      0x14,  // zero timeout (not in virtual card mode)
      0x01,
  });

  // do not wait for ready bit, this is a dummy command
  delay(2);

  // Try to read ACK, if it fails it might be because there's data from a previous power cycle left
  this->read_ack_();
  // do not wait for ready bit for return data
  delay(5);

  // read data packet for wakeup result
  auto wakeup_result = this->pn532_read_data_();
  if (wakeup_result.size() != 1) {
    this->error_code_ = WAKEUP_FAILED;
    this->mark_failed();
    return;
  }

  // Set max retries
  bool ret = this->pn532_write_command_check_ack_({
      0x32,         // Reconfigure command
      0x05,         // Config item 5 : Max retries
      0xFF,         // MxRtyATR (default = 0xFF)
      0x01,         // MxRtyPSL (default = 0x01)
      0x03,         // Max retries
  });

  if (!ret) {
    this->error_code_ = RETRY_COMMAND_FAILED;
    this->mark_failed();
    return;
  }

  auto retry_result = this->pn532_read_data_();
  if (retry_result.size() != 1) {
    ESP_LOGV(TAG, "Invalid MAX RETRY result: (%u)", retry_result.size());  // NOLINT
    for (auto dat : retry_result) {
      ESP_LOGV(TAG, " 0x%02X", dat);
    }
    this->error_code_ = RETRY_COMMAND_FAILED;
    this->mark_failed();
    return;
  }

  // Set up SAM (secure access module)
  uint8_t sam_timeout = std::min(255u, this->update_interval_ / 50);
  ret = this->pn532_write_command_check_ack_({
      0x14,         // SAM config command
      0x01,         // normal mode
      sam_timeout,  // timeout as multiple of 50ms (actually only for virtual card mode, but shouldn't matter)
      0x01,         // Enable IRQ
  });

  if (!ret) {
    this->error_code_ = SAM_COMMAND_FAILED;
    this->mark_failed();
    return;
  }

  auto sam_result = this->pn532_read_data_();
  if (sam_result.size() != 1) {
    ESP_LOGV(TAG, "Invalid SAM result: (%u)", sam_result.size());  // NOLINT
    for (auto dat : sam_result) {
      ESP_LOGV(TAG, " 0x%02X", dat);
    }
    this->error_code_ = SAM_COMMAND_FAILED;
    this->mark_failed();
    return;
  }

  // Initialize key
  if (get_card_type() == "ev1_des")
    gi_PiccMasterKey_DES.SetKeyData(SECRET_PICC_MASTER_KEY, sizeof(SECRET_PICC_MASTER_KEY), CARD_KEY_VERSION);
  else if (get_card_type() == "ev1_aes")
    gi_PiccMasterKey_AES.SetKeyData(SECRET_PICC_MASTER_KEY, sizeof(SECRET_PICC_MASTER_KEY), CARD_KEY_VERSION);
}

bool PN532::ReadCard(uint8_t* u8_UID, kCard* pk_Card)
{
    memset(pk_Card, 0, sizeof(kCard));
  
    if (!gi_PN532.ReadPassiveTargetID(u8_UID, &pk_Card->u8_UidLength, &pk_Card->e_CardType))
    {
        pk_Card->b_PN532_Error = true;
        return false;
    }

    if (pk_Card->e_CardType == CARD_DesRandom) // The card is a Desfire card in random ID mode
    {
      if (get_card_type() == "classic") {
        // random ID not supported for classic cards
        return false;
      }
      if (!AuthenticatePICC(&pk_Card->u8_KeyVersion))
        return false;
        
      // replace the random ID with the real UID
      if (!gi_PN532.GetRealCardID(u8_UID))
        return false;

      pk_Card->u8_UidLength = 7; // random ID is only 4 bytes
    }
    return true;
}

bool PN532::AuthenticatePICC(byte* pu8_KeyVersion)
{
  if (!gi_PN532.SelectApplication(0x000000)) // PICC level
      return false;

  if (!gi_PN532.GetKeyVersion(0, pu8_KeyVersion)) // Get version of PICC master key
      return false;

  // The factory default key has version 0, while a personalized card has key version CARD_KEY_VERSION
  if (*pu8_KeyVersion == CARD_KEY_VERSION)
  {
    if (get_card_type() == "ev1_des") {
      if (!gi_PN532.Authenticate(0, &gi_PiccMasterKey_DES))
        return false;
    } else if (get_card_type() == "ev1_des") {
      if (!gi_PN532.Authenticate(0, &gi_PiccMasterKey_AES))
        return false;
    } else {
      // unknown card type
      return false;
    }
  }
  else // The card is still in factory default state
  {
      if (!gi_PN532.Authenticate(0, &gi_PN532.DES2_DEFAULT_KEY))
          return false;
  }
  return true;
}

bool PN532::GenerateDesfireSecrets(uint8_t* user_id, DESFireKey* pi_AppMasterKey, byte u8_StoreValue[16])
{
    // The buffer is initialized to zero here
    byte u8_Data[24] = {0}; 
    // Copy the 7 byte card UID into the buffer
    memcpy(u8_Data, user_id, 7);

    // XOR the user name and the random data that are stored in EEPROM over the buffer.
    // s8_Name[NAME_BUF_SIZE] contains for example { 'P', 'e', 't', 'e', 'r', 0, 0xDE, 0x45, 0x70, 0x5A, 0xF9, 0x11, 0xAB }
//    int B=0;
//    for (int N=0; N<NAME_BUF_SIZE; N++)
//    {
//        u8_Data[B++] ^= pk_User->s8_Name[N];
//        if (B > 15) B = 0; // Fill the first 16 bytes of u8_Data, the rest remains zero.
//    }

    byte u8_AppMasterKey[24];
    DES i_3KDes;
    if (!i_3KDes.SetKeyData(SECRET_APPLICATION_KEY, sizeof(SECRET_APPLICATION_KEY), 0) || // set a 24 byte key (168 bit)
        !i_3KDes.CryptDataCBC(CBC_SEND, KEY_ENCIPHER, u8_AppMasterKey, u8_Data, 24))
        return false;
    if (!i_3KDes.SetKeyData(SECRET_STORE_VALUE_KEY, sizeof(SECRET_STORE_VALUE_KEY), 0) || // set a 16 byte key (128 bit)
        !i_3KDes.CryptDataCBC(CBC_SEND, KEY_ENCIPHER, u8_StoreValue, u8_Data, 16))
        return false;
    // If the key is an AES key only the first 16 bytes will be used
    if (!pi_AppMasterKey->SetKeyData(u8_AppMasterKey, sizeof(u8_AppMasterKey), CARD_KEY_VERSION))
        return false;
    return true;
}

bool PN532::CheckDesfireSecret(uint8_t* user_id)
{
  DES i_AppMasterKey_DES;
  AES i_AppMasterKey_AES;
  byte u8_StoreValue[16];
  if (get_card_type() == "ev1_des") {
    if (!GenerateDesfireSecrets(user_id, &i_AppMasterKey_DES, u8_StoreValue))
      return false;
  } else if (get_card_type() == "ev1_des") {
    if (!GenerateDesfireSecrets(user_id, &i_AppMasterKey_AES, u8_StoreValue))
      return false;
  } else {
    // unknown card type
    return false;
  }
  if (!gi_PN532.SelectApplication(0x000000)) // PICC level
    return false;
  byte u8_Version; 
  if (!gi_PN532.GetKeyVersion(0, &u8_Version))
    return false;
  if (u8_Version != CARD_KEY_VERSION)
    return false;
  if (!gi_PN532.SelectApplication(CARD_APPLICATION_ID))
    return false;
  if (get_card_type() == "ev1_des") {
    if (!gi_PN532.Authenticate(0, &i_AppMasterKey_DES))
      return false;
  } else if (get_card_type() == "ev1_des") {
    if (!gi_PN532.Authenticate(0, &i_AppMasterKey_AES))
      return false;
  } else {
    // unknown card type
    return false;
  }
  // Read the 16 byte secret from the card
  byte u8_FileData[16];
  if (!gi_PN532.ReadFileData(CARD_FILE_ID, 0, 16, u8_FileData))
    return false;
  if (memcmp(u8_FileData, u8_StoreValue, 16) != 0)
    return false;
  return true;
}

void PN532::update() {
  for (auto *obj : this->binary_sensors_)
    obj->on_scan_end();
  union 
  {
      uint64_t  u64;      
      byte      u8[8];
  } user_id;
  kCard k_Card;
  if (!ReadCard(user_id.u8, &k_Card))
  {
      if (gi_PN532.GetLastPN532Error() == 0x01)
      {
        ESP_LOGW(TAG, "DESfire timeout!");
        this->status_set_warning();
        return;
      }
      else if (k_Card.b_PN532_Error) // Another error from PN532 -> reset the chip
      {
//            InitReader(true); // flash red LED for 2.4 seconds
        ESP_LOGW(TAG, "PN532 communication error!");
        this->status_set_warning();
        return;
      }
      else // e.g. Error while authenticating with master key
      {
        ESP_LOGW(TAG, "Error authenticating with master key!");
        this->status_set_warning();
        return;
      }
      ESP_LOGW(TAG, "Other error!");
      this->status_set_warning();
      return;
  }
  // no card detected
  if (k_Card.u8_UidLength == 0) 
      last_uid.u64 = 0;
  // same card as before
  if (last_uid.u64 == user_id.u64) 
    return;
  // classic card (insecure)
  if ((k_Card.e_CardType & CARD_Desfire) == 0)
    return;
  if (k_Card.e_CardType == CARD_DesRandom) // random ID Desfire card
  {
      // random card with default key
      if (k_Card.u8_KeyVersion != CARD_KEY_VERSION)
        return;
  }
  else // default Desfire card
  {
    if (!CheckDesfireSecret(user_id.u8))
    {
      if (gi_PN532.GetLastPN532Error() == 0x01) // Prints additional error message and blinks the red LED
        return;
      // card is not personalized
      return;
    }
  }
  last_uid.u64 = user_id.u64;
  last_uid_len = k_Card.u8_UidLength;
  this->status_clear_warning();
  this->requested_read_ = true;
}
void PN532::loop() {
  if (!this->requested_read_ || !this->is_ready_())
    return;

  this->requested_read_ = false;

  bool report = true;
  // 1. Go through all triggers
  for (auto *trigger : this->triggers_)
    trigger->process(last_uid.u8, last_uid_len);

  // 2. Find a binary sensor
  for (auto *tag : this->binary_sensors_) {
    if (tag->process(last_uid.u8, last_uid_len)) {
      // 2.1 if found, do not dump
      report = false;
    }
  }

  if (report) {
    char buf[32];
    format_uid(buf, last_uid.u8, last_uid_len);
    ESP_LOGD(TAG, "Found new tag '%s'", buf);
  }
}

float PN532::get_setup_priority() const { return setup_priority::DATA; }

void PN532::pn532_write_command_(const std::vector<uint8_t> &data) {
  this->enable();
  delay(2);
  // First byte, communication mode: Write data
  this->write_byte(0x01);

  // Preamble
  this->write_byte(0x00);

  // Start code
  this->write_byte(0x00);
  this->write_byte(0xFF);

  // Length of message, TFI + data bytes
  const uint8_t real_length = data.size() + 1;
  // LEN
  this->write_byte(real_length);
  // LCS (Length checksum)
  this->write_byte(~real_length + 1);

  // TFI (Frame Identifier, 0xD4 means to PN532, 0xD5 means from PN532)
  this->write_byte(0xD4);
  // calculate checksum, TFI is part of checksum
  uint8_t checksum = 0xD4;

  // DATA
  for (uint8_t dat : data) {
    this->write_byte(dat);
    checksum += dat;
  }

  // DCS (Data checksum)
  this->write_byte(~checksum + 1);
  // Postamble
  this->write_byte(0x00);

  this->disable();
}

bool PN532::pn532_write_command_check_ack_(const std::vector<uint8_t> &data) {
  // 1. write command
  this->pn532_write_command_(data);

  // 2. wait for readiness
  if (!this->wait_ready_())
    return false;

  // 3. read ack
  if (!this->read_ack_()) {
    ESP_LOGV(TAG, "Invalid ACK frame received from PN532!");
    return false;
  }

  return true;
}

std::vector<uint8_t> PN532::pn532_read_data_() {
  this->enable();
  delay(2);
  // Read data (transmission from the PN532 to the host)
  this->write_byte(0x03);

  // sometimes preamble is not transmitted for whatever reason
  // mostly happens during startup.
  // just read the first two bytes and check if that is the case
  uint8_t header[6];
  this->read_array(header, 2);
  if (header[0] == 0x00 && header[1] == 0x00) {
    // normal packet, preamble included
    this->read_array(header + 2, 4);
  } else if (header[0] == 0x00 && header[1] == 0xFF) {
    // weird packet, preamble skipped; make it look like a normal packet
    header[0] = 0x00;
    header[1] = 0x00;
    header[2] = 0xFF;
    this->read_array(header + 3, 3);
  } else {
    // invalid packet
    this->disable();
    ESP_LOGV(TAG, "read data invalid preamble!");
    return {};
  }

  bool valid_header = (header[0] == 0x00 &&                                                      // preamble
                       header[1] == 0x00 &&                                                      // start code
                       header[2] == 0xFF && static_cast<uint8_t>(header[3] + header[4]) == 0 &&  // LCS, len + lcs = 0
                       header[5] == 0xD5  // TFI - frame from PN532 to system controller
  );
  if (!valid_header) {
    this->disable();
    ESP_LOGV(TAG, "read data invalid header!");
    return {};
  }

  std::vector<uint8_t> ret;
  // full length of message, including TFI
  const uint8_t full_len = header[3];
  // length of data, excluding TFI
  uint8_t len = full_len - 1;
  if (full_len == 0)
    len = 0;

  ret.resize(len);
  this->read_array(ret.data(), len);

  uint8_t checksum = 0xD5;
  for (uint8_t dat : ret)
    checksum += dat;
  checksum = ~checksum + 1;

  uint8_t dcs = this->read_byte();
  if (dcs != checksum) {
    this->disable();
    ESP_LOGV(TAG, "read data invalid checksum! %02X != %02X", dcs, checksum);
    return {};
  }

  if (this->read_byte() != 0x00) {
    this->disable();
    ESP_LOGV(TAG, "read data invalid postamble!");
    return {};
  }
  this->disable();

#ifdef ESPHOME_LOG_HAS_VERY_VERBOSE
  ESP_LOGVV(TAG, "PN532 Data Frame: (%u)", ret.size());  // NOLINT
  for (uint8_t dat : ret) {
    ESP_LOGVV(TAG, "  0x%02X", dat);
  }
#endif

  return ret;
}
bool PN532::is_ready_() {
  this->enable();
  // First byte, communication mode: Read state
  this->write_byte(0x02);
  // PN532 returns a single data byte,
  // "After having sent a command, the host controller must wait for bit 0 of Status byte equals 1
  // before reading the data from the PN532."
  bool ret = this->read_byte() == 0x01;
  this->disable();

  if (ret) {
    ESP_LOGVV(TAG, "Chip is ready!");
  }
  return ret;
}
bool PN532::read_ack_() {
  ESP_LOGVV(TAG, "Reading ACK...");
  this->enable();
  delay(2);
  // "Read data (transmission from the PN532 to the host) "
  this->write_byte(0x03);

  uint8_t ack[6];
  memset(ack, 0, sizeof(ack));

  this->read_array(ack, 6);
  this->disable();

  bool matches = (ack[0] == 0x00 &&                    // preamble
                  ack[1] == 0x00 &&                    // start of packet
                  ack[2] == 0xFF && ack[3] == 0x00 &&  // ACK packet code
                  ack[4] == 0xFF && ack[5] == 0x00     // postamble
  );
  ESP_LOGVV(TAG, "ACK valid: %s", YESNO(matches));
  return matches;
}
bool PN532::wait_ready_() {
  uint32_t start_time = millis();
  while (!this->is_ready_()) {
    if (millis() - start_time > 100) {
      ESP_LOGE(TAG, "Timed out waiting for readiness from PN532!");
      return false;
    }
    yield();
  }
  return true;
}

bool PN532::is_device_msb_first() { return false; }
void PN532::dump_config() {
  ESP_LOGCONFIG(TAG, "PN532:");
  switch (this->error_code_) {
    case NONE:
      break;
    case WAKEUP_FAILED:
      ESP_LOGE(TAG, "Wake Up command failed!");
      break;
    case SAM_COMMAND_FAILED:
      ESP_LOGE(TAG, "SAM command failed!");
      break;
    case RETRY_COMMAND_FAILED:
      ESP_LOGE(TAG, "RETRY command failed!");
      break;
  }

  LOG_PIN("  CS Pin: ", this->cs_);
  LOG_UPDATE_INTERVAL(this);
  if (!this->get_card_type().empty()) {
    ESP_LOGCONFIG(TAG, "  Card Type: '%s'", this->get_card_type().c_str());
  }

  for (auto *child : this->binary_sensors_) {
    LOG_BINARY_SENSOR("  ", "Tag", child);
  }
}

bool PN532BinarySensor::process(const uint8_t *data, uint8_t len) {
  if (len != this->uid_.size())
    return false;

  for (uint8_t i = 0; i < len; i++) {
    if (data[i] != this->uid_[i])
      return false;
  }

  this->publish_state(true);
  this->found_ = true;
  return true;
}
void PN532Trigger::process(const uint8_t *uid, uint8_t uid_length) {
  char buf[32];
  format_uid(buf, uid, uid_length);
  this->trigger(std::string(buf));
}

}  // namespace pn532
}  // namespace esphome
