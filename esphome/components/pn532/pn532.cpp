#include "pn532.h"
#include "esphome/core/log.h"

// Based on:
// - https://cdn-shop.adafruit.com/datasheets/PN532C106_Application+Note_v1.2.pdf
// - https://www.nxp.com/docs/en/nxp/application-notes/AN133910.pdf
// - https://www.nxp.com/docs/en/nxp/application-notes/153710.pdf
// - https://www.codeproject.com/Articles/1096861/DIY-electronic-RFID-Door-Lock-with-Battery-Backup

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

PN532::PN532() 
    : mi_CmacBuffer(mu8_CmacBuffer_Data, sizeof(mu8_CmacBuffer_Data))
{
    mpi_SessionKey       = NULL;
    mu8_LastAuthKeyNo    = NOT_AUTHENTICATED;
    mu8_LastPN532Error   = 0;    
    mu32_LastApplication = 0x000000; // No application selected

    // The PICC master key on an empty card is a simple DES key filled with 8 zeros
    const byte ZERO_KEY[24] = {0};
    DES2_DEFAULT_KEY.SetKeyData(ZERO_KEY,  8, 0); // simple DES
    DES3_DEFAULT_KEY.SetKeyData(ZERO_KEY, 24, 0); // triple DES
    AES_DEFAULT_KEY.SetKeyData(ZERO_KEY, 16, 0);
}

void PN532::set_card_type(const std::string &card_type) { this->card_type_ = card_type; }
std::string PN532::get_card_type() {
  if (this->card_type_.length() > 0)
    return this->card_type_;
  return "classic";
}

void PN532::set_master_key(const std::string &master_key) { 
    for (int i = 0; i < master_key.length() / 2; i++)
        this->SECRET_PICC_MASTER_KEY[i] = (byte)strtol(master_key.substr(i * 2, 2).c_str(), NULL, 16);
}

void PN532::set_application_key(const std::string &application_key) { 
    for (int i = 0; i < application_key.length() / 2; i++)
        this->SECRET_APPLICATION_KEY[i] = (byte)strtol(application_key.substr(i * 2, 2).c_str(), NULL, 16);
}

void PN532::set_value_key(const std::string &value_key) { 
    for (int i = 0; i < value_key.length() / 2; i++)
        this->SECRET_STORE_VALUE_KEY[i] = (byte)strtol(value_key.substr(i * 2, 2).c_str(), NULL, 16);
}

void PN532::set_application_id(const std::string &application_id) { 
    this->CARD_APPLICATION_ID = (uint32_t)strtol(application_id.c_str(), NULL, 16);
}

void PN532::set_file_id(const byte file_id) { 
    this->CARD_FILE_ID = file_id;
}

void PN532::set_key_version(const byte key_version) { 
    this->CARD_KEY_VERSION = key_version;
}

void PN532::setup() {
  ESP_LOGCONFIG(TAG, "Setting up PN532...");
  this->spi_setup();

  // Wake the chip up from power down
  // 1. Enable the SS line for at least 2ms
  // 2. Send a dummy command to get the protocol synced up
  //    (this may time out, but that's ok)
  // 3. Send SAM config command with normal mode without waiting for ready bit (IRQ not initialized yet)
  // 4. Probably optional, send SAM config again, this time checking ACK and return value
  this->cs_->digital_write(false);
  delay(10);

  // send dummy firmware version command to get synced up
  this->pn532_write_command_check_ack_({
      PN532_COMMAND_GETFIRMWAREVERSION
  });
  // do not actually read any data, this should be OK according to datasheet

  this->pn532_write_command_({
      PN532_COMMAND_SAMCONFIGURATION,
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
      PN532_COMMAND_RFCONFIGURATION,
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
      PN532_COMMAND_SAMCONFIGURATION,
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

bool PN532::ReadPacket(byte* buff, byte len)
{ 
    if (!this->wait_ready_())
        return false;

    this->enable();
    delay(2);
    this->write_byte(PN532_SPI_DATAREAD);
    this->read_array(buff, len);
    this->disable();
    return true;
}

byte PN532::ReadData(byte* buff, byte len) 
{ 
    byte RxBuffer[PN532_PACKBUFFSIZE];
        
    const byte MIN_PACK_LEN = 2 /*start bytes*/ + 2 /*length + length checksum */ + 1 /*checksum*/;
    if (len < MIN_PACK_LEN || len > PN532_PACKBUFFSIZE)
    {
        ESP_LOGE(TAG, "ReadData(): len is invalid");
        return 0;
    }
    
    if (!ReadPacket(RxBuffer, len))
        return 0; // timeout

    // The following important validity check was completely missing in Adafruit code (added by Elmü)
    // PN532 documentation says (chapter 6.2.1.6): 
    // Before the start code (0x00 0xFF) there may be any number of additional bytes that must be ignored.
    // After the checksum there may be any number of additional bytes that must be ignored.
    // This function returns ONLY the pure data bytes:
    // any leading bytes -> skipped (never seen, but documentation says to ignore them)
    // preamble   0x00   -> skipped (optional, the PN532 does not send it always!!!!!)
    // start code 0x00   -> skipped
    // start code 0xFF   -> skipped
    // length            -> skipped
    // length checksum   -> skipped
    // data[0...n]       -> returned to the caller (first byte is always 0xD5)
    // checksum          -> skipped
    // postamble         -> skipped (optional, the PN532 may not send it!)
    // any bytes behind  -> skipped (never seen, but documentation says to ignore them)

    const char* Error = NULL;
    int Brace1 = -1;
    int Brace2 = -1;
    int dataLength = 0;
    do
    {
        int startCode = -1;
        for (int i=0; i<=len-MIN_PACK_LEN; i++)
        {
            if (RxBuffer[i]   == PN532_STARTCODE1 && 
                RxBuffer[i+1] == PN532_STARTCODE2)
            {
                startCode = i;
                break;
            }
        }

        if (startCode < 0)
        {
            Error = "ReadData() -> No Start Code\r\n";
            break;
        }
        
        int pos = startCode + 2;
        dataLength      = RxBuffer[pos++];
        int lengthCheck = RxBuffer[pos++];
        if ((dataLength + lengthCheck) != 0x100)
        {
            Error = "ReadData() -> Invalid length checksum\r\n";
            break;
        }
    
        if (len < startCode + MIN_PACK_LEN + dataLength)
        {
            Error = "ReadData() -> Packet is longer than requested length\r\n";
            break;
        }

        Brace1 = pos;
        for (int i=0; i<dataLength; i++)
        {
            buff[i] = RxBuffer[pos++]; // copy the pure data bytes in the packet
        }
        Brace2 = pos;

        // All returned data blocks must start with PN532TOHOST (0xD5)
        if (dataLength < 1 || buff[0] != PN532_PN532TOHOST) 
        {
            Error = "ReadData() -> Invalid data (no PN532TOHOST)\r\n";
            break;
        }
    
        byte checkSum = 0;
        for (int i=startCode; i<pos; i++)
        {
            checkSum += RxBuffer[i];
        }
    
        if (checkSum != (byte)(~RxBuffer[pos]))
        {
            Error = "ReadData() -> Invalid checksum\r\n";
            break;
        }
    }
    while(false); // This is not a loop. Avoids using goto by using break.

    ESP_LOGV(TAG, "Response: %s", BufToHexMsg(RxBuffer, len, Brace1, Brace2));
    
    if (Error)
    {
        ESP_LOGE(TAG, "%s", Error);
        return 0;
    }

    return dataLength;
}

bool PN532::ReadPassiveTargetID(byte* u8_UidBuffer, byte* pu8_UidLength, eCardType* pe_CardType) 
{
    ESP_LOGD(TAG, "ReadPassiveTargetID()");
      
    *pu8_UidLength = 0;
    *pe_CardType   = CARD_Unknown;
    memset(u8_UidBuffer, 0, 8);
      
    if (!pn532_write_command_check_ack_({
        PN532_COMMAND_INLISTPASSIVETARGET,
        1,  // read data of 1 card (The PN532 can read max 2 targets at the same time)
        CARD_TYPE_106KB_ISO14443A // This function currently does not support other card types.
    }))
        return false; // Error (no valid ACK received or timeout)
  
    /* 
    ISO14443A card response:
    mu8_PacketBuffer Description
    -------------------------------------------------------
    b0               D5 (always) (PN532_PN532TOHOST)
    b1               4B (always) (PN532_COMMAND_INLISTPASSIVETARGET + 1)
    b2               Amount of cards found
    b3               Tag number (always 1)
    b4,5             SENS_RES (ATQA = Answer to Request Type A)
    b6               SEL_RES  (SAK  = Select Acknowledge)
    b7               UID Length
    b8..Length       UID (4 or 7 bytes)
    nn               ATS Length     (Desfire only)
    nn..Length-1     ATS data bytes (Desfire only)
    */ 
    byte len = ReadData(mu8_PacketBuffer, 28);
    if (len < 3 || mu8_PacketBuffer[1] != PN532_COMMAND_INLISTPASSIVETARGET + 1)
    {
        ESP_LOGE(TAG, "ReadPassiveTargetID failed");
        return false;
    }   

    byte cardsFound = mu8_PacketBuffer[2]; 
    ESP_LOGD(TAG, "Cards found: %d", cardsFound); 
    if (cardsFound != 1)
        return true; // no card found -> this is not an error!

    byte u8_IdLength = mu8_PacketBuffer[7];
    if (u8_IdLength != 4 && u8_IdLength != 7)
    {
        ESP_LOGW(TAG, "Card has unsupported UID length: %d", u8_IdLength); 
        return true; // unsupported card found -> this is not an error!
    }   

    memcpy(u8_UidBuffer, mu8_PacketBuffer + 8, u8_IdLength);    
    *pu8_UidLength = u8_IdLength;

    // See "Mifare Identification & Card Types.pdf" in the ZIP file
    uint16_t u16_ATQA = ((uint16_t)mu8_PacketBuffer[4] << 8) | mu8_PacketBuffer[5];
    byte     u8_SAK   = mu8_PacketBuffer[6];

    
    ESP_LOGD(TAG, "Card UID: %s", BufToHexMsg(u8_UidBuffer, u8_IdLength));

    // Examples:              ATQA    SAK  UID length
    // MIFARE Mini            00 04   09   4 bytes
    // MIFARE Mini            00 44   09   7 bytes
    // MIFARE Classic 1k      00 04   08   4 bytes
    // MIFARE Classic 4k      00 02   18   4 bytes
    // MIFARE Ultralight      00 44   00   7 bytes
    // MIFARE DESFire Default 03 44   20   7 bytes
    // MIFARE DESFire Random  03 04   20   4 bytes
    // See "Mifare Identification & Card Types.pdf"
    ESP_LOGD(TAG, "Card Type: ATQA= 0x%04X, SAK= 0x%02X", u16_ATQA, u8_SAK);
    if (u8_IdLength == 7 && u8_UidBuffer[0] != 0x80 && u16_ATQA == 0x0344 && u8_SAK == 0x20) {
        *pe_CardType = CARD_Desfire;
        ESP_LOGD(TAG, "Card Type: Desfire Default");
    }
    else if (u8_IdLength == 4 && u8_UidBuffer[0] == 0x80 && u16_ATQA == 0x0304 && u8_SAK == 0x20) {
        *pe_CardType = CARD_DesRandom;
        ESP_LOGD(TAG, "Card Type: Desfire RandomID");
    }

    return true;
}

bool PN532::ReadCard(kCard* pk_Card)
{
    memset(pk_Card, 0, sizeof(kCard));
  
    if (!this->ReadPassiveTargetID((byte*)&pk_Card->Uid.u8, &pk_Card->u8_UidLength, &pk_Card->e_CardType))
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
      if (!this->GetRealCardID((byte*)&pk_Card->Uid.u8))
        return false;

      pk_Card->u8_UidLength = 7; // random ID is only 4 bytes
    }
    return true;
}

bool PN532::AuthenticatePICC(byte* pu8_KeyVersion)
{
  if (!this->SelectApplication(0x000000)) // PICC level
      return false;

  if (!this->GetKeyVersion(0, pu8_KeyVersion)) // Get version of PICC master key
      return false;

  // The factory default key has version 0, while a personalized card has key version CARD_KEY_VERSION
  if (*pu8_KeyVersion == CARD_KEY_VERSION)
  {
    if (get_card_type() == "ev1_des") {
      if (!this->Authenticate(0, &gi_PiccMasterKey_DES))
        return false;
    } else if (get_card_type() == "ev1_des") {
      if (!this->Authenticate(0, &gi_PiccMasterKey_AES))
        return false;
    } else {
      // unknown card type
      return false;
    }
  }
  else // The card is still in factory default state
  {
      if (!this->Authenticate(0, &this->DES2_DEFAULT_KEY))
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
  } else if (get_card_type() == "ev1_aes") {
    if (!GenerateDesfireSecrets(user_id, &i_AppMasterKey_AES, u8_StoreValue))
      return false;
  } else {
    // unknown card type
    return false;
  }
  if (!this->SelectApplication(0x000000)) // PICC level
    return false;
  byte u8_Version; 
  if (!this->GetKeyVersion(0, &u8_Version))
    return false;
  if (u8_Version != CARD_KEY_VERSION)
    return false;
  if (!this->SelectApplication(CARD_APPLICATION_ID))
    return false;
  if (get_card_type() == "ev1_des") {
    if (!this->Authenticate(0, &i_AppMasterKey_DES))
      return false;
  } else if (get_card_type() == "ev1_aes") {
    if (!this->Authenticate(0, &i_AppMasterKey_AES))
      return false;
  } else {
    // unknown card type
    return false;
  }
  // Read the 16 byte secret from the card
  byte u8_FileData[16];
  if (!this->ReadFileData(CARD_FILE_ID, 0, 16, u8_FileData))
    return false;
  if (memcmp(u8_FileData, u8_StoreValue, 16) != 0)
    return false;
  return true;
}

bool PN532::CreateApplication(uint32_t u32_AppID, DESFireKeySettings e_Settg, byte u8_KeyCount, DESFireKeyType e_KeyType)
{
    ESP_LOGD(TAG, "CreateApplication(App= 0x%06X, KeyCount= %d, Type= %s)", (unsigned int)u32_AppID, u8_KeyCount, DESFireKey::GetKeyTypeAsString(e_KeyType));

    if (e_KeyType == DF_KEY_INVALID)
    {
        ESP_LOGE("Invalid key type");
        return false;
    }

    TX_BUFFER(i_Params, 5);
    if (!i_Params.AppendUint24(u32_AppID)) {
        ESP_LOGE(TAG, "Buffer Overflow");
    }
    if (!i_Params.AppendUint8 (e_Settg)) {
        ESP_LOGE(TAG, "Buffer Overflow");
    }
    if (!i_Params.AppendUint8 (u8_KeyCount | e_KeyType)) {
        ESP_LOGE(TAG, "Buffer Overflow");
    }

    return (0 == DataExchange(DF_INS_CREATE_APPLICATION, &i_Params, NULL, 0, NULL, MAC_TmacRmac));
}

bool PN532::DeleteApplicationIfExists(uint32_t u32_AppID)
{
    uint32_t u32_IDlist[28];
    byte     u8_AppCount;
    if (!GetApplicationIDs(u32_IDlist, &u8_AppCount))
        return false;

    bool b_Found = false;
    for (byte i=0; i<u8_AppCount; i++)
    {
        if (u32_IDlist[i] == u32_AppID)
            b_Found = true;
    }
    if (!b_Found)
        return true;

    return DeleteApplication(u32_AppID);
}

bool PN532::DeleteApplication(uint32_t u32_AppID)
{
    ESP_LOGD(TAG, "DeleteApplication(0x%06X)", (unsigned int)u32_AppID);

    TX_BUFFER(i_Params, 3);
    if (!i_Params.AppendUint24(u32_AppID)) {
        ESP_LOGE(TAG, "Buffer Overflow");
    }

    return (0 == DataExchange(DF_INS_DELETE_APPLICATION, &i_Params, NULL, 0, NULL, MAC_TmacRmac));
}

bool PN532::GetApplicationIDs(uint32_t u32_IDlist[28], byte* pu8_AppCount)
{
    ESP_LOGD(TAG, "GetApplicationIDs()");

    memset(u32_IDlist, 0, 28 * sizeof(uint32_t));

    RX_BUFFER(i_RxBuf, 28*3); // 3 byte per application
    byte* pu8_Ptr = i_RxBuf;

    DESFireStatus e_Status;
    int s32_Read1 = DataExchange(DF_INS_GET_APPLICATION_IDS, NULL, pu8_Ptr, MAX_FRAME_SIZE, &e_Status, MAC_TmacRmac);
    if (s32_Read1 < 0)
        return false;

    // If there are more than 19 applications, they will be sent in two frames
    int s32_Read2 = 0;
    if (e_Status == ST_MoreFrames)
    {
        pu8_Ptr += s32_Read1;
        s32_Read2 = DataExchange(DF_INS_ADDITIONAL_FRAME, NULL, pu8_Ptr, 28 * 3 - s32_Read1, NULL, MAC_Rmac);
        if (s32_Read2 < 0)
            return false;
    }

    if (!i_RxBuf.SetSize (s32_Read1 + s32_Read2)) {
        ESP_LOGE(TAG, "Buffer Overflow");
    };
    *pu8_AppCount = (s32_Read1 + s32_Read2) / 3;

    // Convert 3 byte array -> 4 byte array
    for (byte i=0; i<*pu8_AppCount; i++)
    {
        u32_IDlist[i] = i_RxBuf.ReadUint24();
    }

    if (*pu8_AppCount == 0)
        ESP_LOGD(TAG, "No Application ID's.");
    else for (byte i=0; i<*pu8_AppCount; i++)
        ESP_LOGD(TAG, "Application %2d: 0x%06X", i, (unsigned int)u32_IDlist[i]);
    return true;
}

bool PN532::StoreDesfireSecret(uint8_t* user_id)
{
    if (CARD_APPLICATION_ID == 0x000000 || CARD_KEY_VERSION == 0)
        return false; // severe errors in Secrets.h -> abort
  
    DES i_AppMasterKey_DES;
    AES i_AppMasterKey_AES;
    byte u8_StoreValue[16];
    if (get_card_type() == "ev1_des") {
        if (!GenerateDesfireSecrets(user_id, &i_AppMasterKey_DES, u8_StoreValue))
            return false;
    } else if (get_card_type() == "ev1_aes") {
        if (!GenerateDesfireSecrets(user_id, &i_AppMasterKey_AES, u8_StoreValue))
            return false;
    } else {
        // unknown card type
        return false;
    }

    // First delete the application (The current application master key may have changed after changing the user name for that card)
    if (!DeleteApplicationIfExists(CARD_APPLICATION_ID))
        return false;

    // Create the new application with default settings (we must still have permission to change the application master key later)
    if (get_card_type() == "ev1_des") {
        if (!CreateApplication(CARD_APPLICATION_ID, KS_FACTORY_DEFAULT, 1, i_AppMasterKey_DES.GetKeyType()))
            return false;
    } else if (get_card_type() == "ev1_aes") {
        if (!CreateApplication(CARD_APPLICATION_ID, KS_FACTORY_DEFAULT, 1, i_AppMasterKey_AES.GetKeyType()))
            return false;
    } else {
        // unknown card type
        return false;
    }

    // After this command all the following commands will apply to the application (rather than the PICC)
    if (!SelectApplication(CARD_APPLICATION_ID))
        return false;


    // Authentication with the application's master key is required
    // Change the master key of the application
    // A key change always requires a new authentication with the new key
    if (get_card_type() == "ev1_des") {
        if (!Authenticate(0, &DES3_DEFAULT_KEY))
            return false;
        if (!ChangeKey(0, &i_AppMasterKey_DES, NULL))
            return false;
        if (!Authenticate(0, &i_AppMasterKey_DES))
            return false;
    } else if (get_card_type() == "ev1_aes") {
        if (!Authenticate(0, &AES_DEFAULT_KEY))
            return false;
        if (!ChangeKey(0, &i_AppMasterKey_AES, NULL))
            return false;
        if (!Authenticate(0, &i_AppMasterKey_AES))
            return false;
    } else {
        // unknown card type
        return false;
    }

    // After this command the application's master key and it's settings will be frozen. They cannot be changed anymore.
    // To read or enumerate any content (files) in the application the application master key will be required.
    // Even if someone knows the PICC master key, he will neither be able to read the data in this application nor to change the app master key.
    if (!ChangeKeySettings(KS_CHANGE_KEY_FROZEN))
        return false;

    // --------------------------------------------

    // Create Standard Data File with 16 bytes length
    DESFireFilePermissions k_Permis;
    k_Permis.e_ReadAccess         = AR_KEY0;
    k_Permis.e_WriteAccess        = AR_KEY0;
    k_Permis.e_ReadAndWriteAccess = AR_KEY0;
    k_Permis.e_ChangeAccess       = AR_KEY0;
    if (!CreateStdDataFile(CARD_FILE_ID, &k_Permis, 16))
        return false;

    // Write the StoreValue into that file
    if (!WriteFileData(CARD_FILE_ID, 0, 16, u8_StoreValue))
        return false;       
  
    return true;
}

bool PN532::WriteFileData(byte u8_FileID, int s32_Offset, int s32_Length, const byte* u8_DataBuffer)
{
    ESP_LOGD(TAG, "WriteFileData(ID= %d, Offset= %d, Length= %d)", u8_FileID, s32_Offset, s32_Length);

    // With intention this command does not use DF_INS_ADDITIONAL_FRAME because the CMAC must be calculated over all frames sent.
    // When writing a lot of data this could lead to a buffer overflow in mi_CmacBuffer.
    while (s32_Length > 0)
    {
        int s32_Count = min(s32_Length, MAX_FRAME_SIZE - 8); // DF_INS_WRITE_DATA + u8_FileID + s32_Offset + s32_Count = 8 bytes
              
        TX_BUFFER(i_Params, MAX_FRAME_SIZE); 
        if (!i_Params.AppendUint8 (u8_FileID)) {
            ESP_LOGE(TAG, "Buffer Overflow");
        }
        if (!i_Params.AppendUint24(s32_Offset)) { // only the low 3 bytes are used
            ESP_LOGE(TAG, "Buffer Overflow");
        }
        if (!i_Params.AppendUint24(s32_Count)) { // only the low 3 bytes are used
            ESP_LOGE(TAG, "Buffer Overflow");
        }
        if (!i_Params.AppendBuf(u8_DataBuffer, s32_Count)) {
            ESP_LOGE(TAG, "Buffer Overflow");
        }

        DESFireStatus e_Status;
        int s32_Read = DataExchange(DF_INS_WRITE_DATA, &i_Params, NULL, 0, &e_Status, MAC_TmacRmac);
        if (e_Status != ST_Success || s32_Read != 0)
            return false; // ST_MoreFrames is not allowed here!

        s32_Length    -= s32_Count;
        s32_Offset    += s32_Count;
        u8_DataBuffer += s32_Count;
    }
    return true;
}

bool PN532::CreateStdDataFile(byte u8_FileID, DESFireFilePermissions* pk_Permis, int s32_FileSize)
{
    ESP_LOGD(TAG, "CreateStdDataFile(ID= %d, Size= %d)", u8_FileID, s32_FileSize);

    uint16_t u16_Permis = pk_Permis->Pack();
  
    TX_BUFFER(i_Params, 7);
    if (!i_Params.AppendUint8 (u8_FileID)) {
        ESP_LOGE(TAG, "Buffer Overflow");
    }
    if (!i_Params.AppendUint8 (CM_PLAIN)) {
        ESP_LOGE(TAG, "Buffer Overflow");
    }
    if (!i_Params.AppendUint16(u16_Permis)) {
        ESP_LOGE(TAG, "Buffer Overflow");
    }
    if (!i_Params.AppendUint24(s32_FileSize)) { // only the low 3 bytes are used
        ESP_LOGE(TAG, "Buffer Overflow");
    }

    return (0 == DataExchange(DF_INS_CREATE_STD_DATA_FILE, &i_Params, NULL, 0, NULL, MAC_TmacRmac));

}

bool PN532::ChangeKeySettings(DESFireKeySettings e_NewSettg)
{
    ESP_LOGD(TAG, "ChangeKeySettings(0x%02X)", e_NewSettg);

    TX_BUFFER(i_Params, 16);
    if (!i_Params.AppendUint8(e_NewSettg)) {
        ESP_LOGE(TAG, "Buffer Overflow");
    }

    // The TX CMAC must not be calculated here because a CBC encryption operation has already been executed
    return (0 == DataExchange(DF_INS_CHANGE_KEY_SETTINGS, &i_Params, NULL, 0, NULL, MAC_TcryptRmac));
}

bool PN532::ChangeKey(byte u8_KeyNo, DESFireKey* pi_NewKey, DESFireKey* pi_CurKey)
{
    ESP_LOGD(TAG, "ChangeKey(KeyNo= %d)", u8_KeyNo);

    if (mu8_LastAuthKeyNo == NOT_AUTHENTICATED)
    {
        ESP_LOGE(TAG, "Not authenticated");
        return false;
    }

    ESP_LOGD(TAG, "SessKey IV: %s", BufToHexMsg(mpi_SessionKey->GetIV(), mpi_SessionKey->GetBlockSize()));
    ESP_LOGD(TAG, "New Key: %s (%s)", BufToHexMsg(pi_NewKey->Data(), pi_NewKey->GetKeySize(16)), DESFireKey::GetKeyTypeAsString(pi_NewKey->GetKeyType(), pi_NewKey->GetKeySize()));

    if (!DESFireKey::CheckValid(pi_NewKey)) {
        ESP_LOGE(TAG, "Invalid key");
        return false;
    }

    TX_BUFFER(i_Cryptogram, 40);
    i_Cryptogram.AppendBuf(pi_NewKey->Data(), pi_NewKey->GetKeySize(16));

    bool b_SameKey = (u8_KeyNo == mu8_LastAuthKeyNo);  // false -> change another key than the one that was used for authentication

    // The type of key can only be changed for the PICC master key.
    // Applications must define their key type in CreateApplication().
    if (mu32_LastApplication == 0x000000)
        u8_KeyNo |= pi_NewKey->GetKeyType();

    // The following if() applies only to application keys.
    // For the PICC master key b_SameKey is always true because there is only ONE key (#0) at the PICC level.
    if (!b_SameKey) 
    {
        if (!DESFireKey::CheckValid(pi_CurKey)) {
            ESP_LOGE(TAG, "Invalid key");
            return false;
        }

        ESP_LOGD(TAG, "Cur Key: %s (%s)", BufToHexMsg(pi_CurKey->Data(), pi_CurKey->GetKeySize(16)), DESFireKey::GetKeyTypeAsString(pi_CurKey->GetKeyType(), pi_CurKey->GetKeySize()));

        // The current key and the new key must be XORed        
        for (int B = 0; B < pi_CurKey->GetKeySize(16); B++)
            i_Cryptogram[B] ^= pi_CurKey->Data()[B];
    }

    // While DES stores the key version in bit 0 of the key bytes, AES transmits the version separately
    if (pi_NewKey->GetKeyType() == DF_KEY_AES)
    {
        if (!i_Cryptogram.AppendUint8(pi_NewKey->GetKeyVersion())) {
            ESP_LOGE(TAG, "Buffer Overflow");
        }
    }

    byte u8_Command[] = { DF_INS_CHANGE_KEY, u8_KeyNo };   
    uint32_t u32_Crc = CalcCrc32(u8_Command, 2, i_Cryptogram, i_Cryptogram.GetCount());
    if (!i_Cryptogram.AppendUint32(u32_Crc)) {
        ESP_LOGE(TAG, "Buffer Overflow");
    }

    ESP_LOGD(TAG, "CRC Crypto: 0x", u32_Crc);

    if (!b_SameKey)
    {
        uint32_t u32_CrcNew = CalcCrc32(pi_NewKey->Data(), pi_NewKey->GetKeySize(16));
        if (!i_Cryptogram.AppendUint32(u32_CrcNew)) {
            ESP_LOGE(TAG, "Buffer Overflow");
        }

    	ESP_LOGD(TAG, "CRC New Key: 0x", u32_CrcNew);
    }

    // Get the padded length of the Cryptogram to be encrypted
    int s32_CryptoLen = 24;
    if (i_Cryptogram.GetCount() > 24) s32_CryptoLen = 32;
    if (i_Cryptogram.GetCount() > 32) s32_CryptoLen = 40;

    // For a blocksize of 16 byte (AES) the data length 24 is not valid -> increase to 32
    s32_CryptoLen = mpi_SessionKey->CalcPaddedBlockSize(s32_CryptoLen);

    byte u8_Cryptogram_enc[40] = {0}; // encrypted cryptogram
    if (!mpi_SessionKey->CryptDataCBC(CBC_SEND, KEY_ENCIPHER, u8_Cryptogram_enc, i_Cryptogram, s32_CryptoLen))
        return false;

    ESP_LOGD(TAG, "Cryptogram: %s", BufToHexMsg(i_Cryptogram, s32_CryptoLen));
    ESP_LOGD(TAG, "Cryptog_enc: %s", BufToHexMsg(u8_Cryptogram_enc, s32_CryptoLen));

    TX_BUFFER(i_Params, 41);
    if (!i_Params.AppendUint8(u8_KeyNo)) {
        ESP_LOGE(TAG, "Buffer Overflow");
    }
    if (!i_Params.AppendBuf  (u8_Cryptogram_enc, s32_CryptoLen)) {
        ESP_LOGE(TAG, "Buffer Overflow");
    }

    // If the same key has been changed the session key is no longer valid. (Authentication required)
    if (b_SameKey) mu8_LastAuthKeyNo = NOT_AUTHENTICATED;

    return (0 == DataExchange(DF_INS_CHANGE_KEY, &i_Params, NULL, 0, NULL, MAC_Rmac));
}

void PN532::update() {
  for (auto *obj : this->binary_sensors_)
    obj->on_scan_end();
  kCard k_Card;
  if (!ReadCard(&k_Card))
  {
      if (this->GetLastPN532Error() == 0x01)
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
      last_card.Uid.u64 = 0;
  // same card as before
  if (last_card.Uid.u64 == k_Card.Uid.u64) 
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
    if (!CheckDesfireSecret(k_Card.Uid.u8))
    {
      if (this->GetLastPN532Error() == 0x01) // Prints additional error message and blinks the red LED
        return;
      // card is not personalized
      return;
    }
  }
  last_card.Uid.u64 = k_Card.Uid.u64;
  last_card.u8_UidLength = k_Card.u8_UidLength;
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
    trigger->process(last_card.Uid.u8, last_card.u8_UidLength);

  // 2. Find a binary sensor
  for (auto *tag : this->binary_sensors_) {
    if (tag->process(last_card.Uid.u8, last_card.u8_UidLength)) {
      // 2.1 if found, do not dump
      report = false;
    }
  }

  if (report) {
    char buf[32];
    format_uid(buf, last_card.Uid.u8, last_card.u8_UidLength);
    ESP_LOGD(TAG, "Found new tag '%s'", buf);
  }
}

float PN532::get_setup_priority() const { return setup_priority::DATA; }

void PN532::pn532_write_command_(const std::vector<uint8_t> &data) {
  this->enable();
  delay(2);
  // First byte, communication mode: Write data
  this->write_byte(PN532_SPI_DATAWRITE);

  // Preamble
  this->write_byte(PN532_PREAMBLE);

  // Start code
  this->write_byte(PN532_STARTCODE1);
  this->write_byte(PN532_STARTCODE2);

  // Length of message, TFI + data bytes
  const uint8_t real_length = data.size() + 1;
  // LEN
  this->write_byte(real_length);
  // LCS (Length checksum)
  this->write_byte(~real_length + 1);

  // TFI (Frame Identifier, 0xD4 means to PN532, 0xD5 means from PN532)
  this->write_byte(PN532_HOSTTOPN532);
  // calculate checksum, TFI is part of checksum
  uint8_t checksum = PN532_HOSTTOPN532;

  // DATA
  for (uint8_t dat : data) {
    this->write_byte(dat);
    checksum += dat;
  }

  // DCS (Data checksum)
  this->write_byte(~checksum + 1);
  // Postamble
  this->write_byte(PN532_POSTAMBLE);

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
  this->write_byte(PN532_SPI_DATAREAD);

  // sometimes preamble is not transmitted for whatever reason
  // mostly happens during startup.
  // just read the first two bytes and check if that is the case
  uint8_t header[6];
  this->read_array(header, 2);
  if (header[0] == PN532_PREAMBLE && header[1] == PN532_STARTCODE1) {
    // normal packet, preamble included
    this->read_array(header + 2, 4);
  } else if (header[0] == PN532_STARTCODE1 && header[1] == PN532_STARTCODE2) {
    // weird packet, preamble skipped; make it look like a normal packet
    header[0] = PN532_PREAMBLE;
    header[1] = PN532_STARTCODE1;
    header[2] = PN532_STARTCODE2;
    this->read_array(header + 3, 3);
  } else {
    // invalid packet
    this->disable();
    ESP_LOGV(TAG, "read data invalid preamble!");
    return {};
  }

  bool valid_header = (header[0] == PN532_PREAMBLE &&                                                      // preamble
                       header[1] == PN532_STARTCODE1 &&                                                      // start code
                       header[2] == PN532_STARTCODE2 && static_cast<uint8_t>(header[3] + header[4]) == 0 &&  // LCS, len + lcs = 0
                       header[5] == PN532_PN532TOHOST  // TFI - frame from PN532 to system controller
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

  uint8_t checksum = PN532_PN532TOHOST;
  for (uint8_t dat : ret)
    checksum += dat;
  checksum = ~checksum + 1;

  uint8_t dcs = this->read_byte();
  if (dcs != checksum) {
    this->disable();
    ESP_LOGV(TAG, "read data invalid checksum! %02X != %02X", dcs, checksum);
    return {};
  }

  if (this->read_byte() != PN532_POSTAMBLE) {
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
  this->write_byte(PN532_SPI_STATUSREAD);
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
  this->write_byte(PN532_SPI_DATAREAD);

  uint8_t ack[6];
  memset(ack, 0, sizeof(ack));

  this->read_array(ack, 6);
  this->disable();

  bool matches = (ack[0] == PN532_PREAMBLE &&                    // preamble
                  ack[1] == PN532_STARTCODE1 &&                    // start of packet
                  ack[2] == PN532_STARTCODE2 && 
                  ack[3] == 0x00 &&  // ACK packet code
                  ack[4] == 0xFF && 
                  ack[5] == PN532_POSTAMBLE     // postamble
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

bool PN532::Authenticate(byte u8_KeyNo, DESFireKey* pi_Key)
{
    ESP_LOGD(TAG, "Authenticate(KeyNo= %d, Key= %s)", u8_KeyNo, BufToHexMsg(pi_Key->Data(), pi_Key->GetKeySize(16)));

    byte u8_Command;
    switch (pi_Key->GetKeyType())
    { 
        case DF_KEY_AES:    u8_Command = DFEV1_INS_AUTHENTICATE_AES; break;
        case DF_KEY_2K3DES:
        case DF_KEY_3K3DES: u8_Command = DFEV1_INS_AUTHENTICATE_ISO; break;
        default:
            ESP_LOGE(TAG, "Invalid key");
            return false;
    }

    TX_BUFFER(i_Params, 1);
    if (!i_Params.AppendUint8(u8_KeyNo)) {
        ESP_LOGE(TAG, "Buffer Overflow");
    }

    // Request a random of 16 byte, but depending of the key the PICC may also return an 8 byte random
    DESFireStatus e_Status;
    byte u8_RndB_enc[16]; // encrypted random B
    int s32_Read = DataExchange(u8_Command, &i_Params, u8_RndB_enc, 16, &e_Status, MAC_None);
    if (e_Status != ST_MoreFrames || (s32_Read != 8 && s32_Read != 16))
    {
        ESP_LOGE(TAG, "Authentication failed (1)");
        return false;
    }

    int s32_RandomSize = s32_Read;

    byte u8_RndB[16];  // decrypted random B
    pi_Key->ClearIV(); // Fill IV with zeroes !ONLY ONCE HERE!
    if (!pi_Key->CryptDataCBC(CBC_RECEIVE, KEY_DECIPHER, u8_RndB, u8_RndB_enc, s32_RandomSize))
        return false;  // key not set

    byte u8_RndB_rot[16]; // rotated random B
    memcpy(u8_RndB_rot, u8_RndB + 1, s32_RandomSize - 1);
    u8_RndB_rot[s32_RandomSize - 1] = u8_RndB[0];

    byte u8_RndA[16];
    // GenerateRandom
    uint32_t u32_Now = millis();
    for (int i=0; i<s32_RandomSize; i++)
    {
        u8_RndA[i] = (byte)u32_Now;
        u32_Now *= 127773;
        u32_Now += 16807;
    }

    TX_BUFFER(i_RndAB, 32); // (randomA + rotated randomB)
    i_RndAB.AppendBuf(u8_RndA,     s32_RandomSize);
    i_RndAB.AppendBuf(u8_RndB_rot, s32_RandomSize);

    TX_BUFFER(i_RndAB_enc, 32); // encrypted (randomA + rotated randomB)
    i_RndAB_enc.SetCount(2*s32_RandomSize);
    if (!pi_Key->CryptDataCBC(CBC_SEND, KEY_ENCIPHER, i_RndAB_enc, i_RndAB, 2*s32_RandomSize))
        return false;

    ESP_LOGD(TAG, "RndB_enc: %s", BufToHexMsg(u8_RndB_enc, s32_RandomSize));
    ESP_LOGD(TAG, "RndB: %s", BufToHexMsg(u8_RndB, s32_RandomSize));
    ESP_LOGD(TAG, "RndB_rot: %s", BufToHexMsg(u8_RndB_rot, s32_RandomSize));
    ESP_LOGD(TAG, "RndA: %s", BufToHexMsg(u8_RndA, s32_RandomSize));
    ESP_LOGD(TAG, "RndAB: %s", BufToHexMsg(i_RndAB, 2 * s32_RandomSize));
    ESP_LOGD(TAG, "RndAB_enc: %s", BufToHexMsg(i_RndAB_enc, 2 * s32_RandomSize));

    byte u8_RndA_enc[16]; // encrypted random A
    s32_Read = DataExchange(DF_INS_ADDITIONAL_FRAME, &i_RndAB_enc, u8_RndA_enc, s32_RandomSize, &e_Status, MAC_None);
    if (e_Status != ST_Success || s32_Read != s32_RandomSize)
    {
        ESP_LOGE(TAG, "Authentication failed (2)");
        return false;
    }

    byte u8_RndA_dec[16]; // decrypted random A
    if (!pi_Key->CryptDataCBC(CBC_RECEIVE, KEY_DECIPHER, u8_RndA_dec, u8_RndA_enc, s32_RandomSize))
        return false;

    byte u8_RndA_rot[16]; // rotated random A
    memcpy(u8_RndA_rot, u8_RndA + 1, s32_RandomSize - 1);
    u8_RndA_rot[s32_RandomSize - 1] = u8_RndA[0];


    ESP_LOGD(TAG, "RndA_enc: %s", BufToHexMsg(u8_RndA_enc, s32_RandomSize));
    ESP_LOGD(TAG, "RndA_dec: %s", BufToHexMsg(u8_RndA_dec, s32_RandomSize));
    ESP_LOGD(TAG, "RndA_rot: %s", BufToHexMsg(u8_RndA_rot, s32_RandomSize));

    // Last step: Check if the received random A is equal to the sent random A.
    if (memcmp(u8_RndA_dec, u8_RndA_rot, s32_RandomSize) != 0)
    {
        ESP_LOGE(TAG, "Authentication failed (3)");
        return false;
    }

    // The session key is composed from RandA and RndB
    TX_BUFFER(i_SessKey, 24);
    i_SessKey.AppendBuf(u8_RndA, 4);
    i_SessKey.AppendBuf(u8_RndB, 4);

    if (pi_Key->GetKeySize() > 8) // the following block is not required for simple DES
    {
        switch (pi_Key->GetKeyType())
        {  
            case DF_KEY_2K3DES:
                i_SessKey.AppendBuf(u8_RndA + 4, 4);
                i_SessKey.AppendBuf(u8_RndB + 4, 4);
                break;
                
            case DF_KEY_3K3DES:
                i_SessKey.AppendBuf(u8_RndA +  6, 4);
                i_SessKey.AppendBuf(u8_RndB +  6, 4);
                i_SessKey.AppendBuf(u8_RndA + 12, 4);
                i_SessKey.AppendBuf(u8_RndB + 12, 4);
                break;
    
            case DF_KEY_AES:
                i_SessKey.AppendBuf(u8_RndA + 12, 4);
                i_SessKey.AppendBuf(u8_RndB + 12, 4);
                break;
    
            default: // avoid stupid gcc compiler warning
                break;
        }
    }
       
    if (pi_Key->GetKeyType() == DF_KEY_AES) mpi_SessionKey = &mi_AesSessionKey;
    else                                    mpi_SessionKey = &mi_DesSessionKey;
    
    if (!mpi_SessionKey->SetKeyData(i_SessKey, i_SessKey.GetCount(), 0) ||
        !mpi_SessionKey->GenerateCmacSubkeys())
        return false;

    ESP_LOGD(TAG, "SessKey: %s", BufToHexMsg(mpi_SessionKey->Data(), mpi_SessionKey->GetKeySize(16)));

    mu8_LastAuthKeyNo = u8_KeyNo;   
    return true;
}

bool PN532::GetRealCardID(byte u8_UID[7])
{
    ESP_LOGD(TAG, "GetRealCardID()");

    if (mu8_LastAuthKeyNo == NOT_AUTHENTICATED)
    {
        ESP_LOGE(TAG, "Not authenticated");
        return false;
    }

    RX_BUFFER(i_Data, 16);
    if (16 != DataExchange(DFEV1_INS_GET_CARD_UID, NULL, i_Data, 16, NULL, MAC_TmacRcrypt))
        return false;

    // The card returns UID[7] + CRC32[4] encrypted with the session key
    // Copy the 7 bytes of the UID to the output buffer
    if (!i_Data.ReadBuf(u8_UID, 7)) {
        ESP_LOGE("Buffer Overflow");
    }

    // Get the CRC sent by the card
    uint32_t u32_Crc1 = i_Data.ReadUint32();

    // The CRC must be calculated over the UID + the status byte appended
    byte u8_Status = ST_Success;
    uint32_t u32_Crc2 = CalcCrc32(u8_UID, 7, &u8_Status, 1);

    ESP_LOGV(TAG, "CRC: 0x%08X", u32_Crc2);

    if (u32_Crc1 != u32_Crc2)
    {
        ESP_LOGE(TAG, "Invalid CRC");
        return false;
    }

    ESP_LOGD(TAG, "Real UID: %s", BufToHexMsg(u8_UID, 7));
    return true;
}

bool PN532::SelectApplication(uint32_t u32_AppID)
{
    ESP_LOGD(TAG, "SelectApplication(0x%06X)", (unsigned int)u32_AppID);

    TX_BUFFER(i_Params, 3);
    if (!i_Params.AppendUint24(u32_AppID)) {
        ESP_LOGE(TAG, "Buffer Overflow");
    }

    // This command does not return a CMAC because after selecting another application the session key is no longer valid. (Authentication required)
    if (0 != DataExchange(DF_INS_SELECT_APPLICATION, &i_Params, NULL, 0, NULL, MAC_None))
        return false;

    mu8_LastAuthKeyNo    = NOT_AUTHENTICATED; // set to invalid value (the selected app requires authentication)
    mu32_LastApplication = u32_AppID;
    return true;
}

bool PN532::GetKeyVersion(byte u8_KeyNo, byte* pu8_Version)
{
    ESP_LOGD(TAG, "GetKeyVersion(KeyNo= %d)", u8_KeyNo);

    TX_BUFFER(i_Params, 1);
    if (!i_Params.AppendUint8(u8_KeyNo)) {
        ESP_LOGE(TAG, "Buffer Overflow");
    }

    if (1 != DataExchange(DF_INS_GET_KEY_VERSION, &i_Params, pu8_Version, 1, NULL, MAC_TmacRmac))
        return false;

    ESP_LOGD(TAG, "Version: 0x%02X", *pu8_Version);
    return true;
}

bool PN532::ReadFileData(byte u8_FileID, int s32_Offset, int s32_Length, byte* u8_DataBuffer)
{
    ESP_LOGD(TAG, "ReadFileData(ID= %d, Offset= %d, Length= %d)", u8_FileID, s32_Offset, s32_Length);

    // With intention this command does not use DF_INS_ADDITIONAL_FRAME because the CMAC must be calculated over all frames received.
    // When reading a lot of data this could lead to a buffer overflow in mi_CmacBuffer.
    while (s32_Length > 0)
    {
        int s32_Count = min(s32_Length, 48); // the maximum that can be transferred in one frame (must be a multiple of 16 if encryption is used)

        TX_BUFFER(i_Params, 7);
        if (!i_Params.AppendUint8 (u8_FileID)) {
            ESP_LOGE(TAG, "Buffer Overflow");
        }
        if (!i_Params.AppendUint24(s32_Offset)) { // only the low 3 bytes are used
            ESP_LOGE(TAG, "Buffer Overflow");
        }
        if (!i_Params.AppendUint24(s32_Count)) { // only the low 3 bytes are used
            ESP_LOGE(TAG, "Buffer Overflow");
        }
        
        DESFireStatus e_Status;
        int s32_Read = DataExchange(DF_INS_READ_DATA, &i_Params, u8_DataBuffer, s32_Count, &e_Status, MAC_TmacRmac);
        if (e_Status != ST_Success || s32_Read <= 0)
            return false; // ST_MoreFrames is not allowed here!

        s32_Length    -= s32_Read;
        s32_Offset    += s32_Read;
        u8_DataBuffer += s32_Read;
    }
    return true;
}

byte PN532::GetLastPN532Error()
{
    return mu8_LastPN532Error;
}

int PN532::DataExchange(byte u8_Command, TxBuffer* pi_Params, byte* u8_RecvBuf, int s32_RecvSize, DESFireStatus* pe_Status, DESFireCmac e_Mac)
{
    TX_BUFFER(i_Command, 1);
    if (!i_Command.AppendUint8(u8_Command)) {
        ESP_LOGE(TAG, "Buffer Overflow");
    }
  
    return DataExchange(&i_Command, pi_Params, u8_RecvBuf, s32_RecvSize, pe_Status, e_Mac);
}
int PN532::DataExchange(TxBuffer* pi_Command,               // in (command + params that are not encrypted)
                          TxBuffer* pi_Params,                // in (parameters that may be encrypted)
                          byte* u8_RecvBuf, int s32_RecvSize, // out
                          DESFireStatus* pe_Status,           // out
                          DESFireCmac    e_Mac)               // in
{
    if (pe_Status) *pe_Status = ST_Success;
    mu8_LastPN532Error = 0;

    TX_BUFFER(i_Empty, 1);
    if (pi_Params == NULL)
        pi_Params = &i_Empty;

    // The response for INDATAEXCHANGE is always: 
    // - 0xD5
    // - 0x41
    // - Status byte from PN532        (0 if no error)
    // - Status byte from Desfire card (0 if no error)
    // - data bytes ...
    int s32_Overhead = 11; // Overhead added to payload = 11 bytes = 7 bytes for PN532 frame + 3 bytes for INDATAEXCHANGE response + 1 card status byte
    if (e_Mac & MAC_Rmac) s32_Overhead += 8; // + 8 bytes for CMAC
  
    // mu8_PacketBuffer is used for input and output
    if (2 + pi_Command->GetCount() + pi_Params->GetCount() > PN532_PACKBUFFSIZE || s32_Overhead + s32_RecvSize > PN532_PACKBUFFSIZE)    
    {
        ESP_LOGE(TAG, "DataExchange(): Invalid parameters");
        return -1;
    }

    if (e_Mac & (MAC_Tcrypt | MAC_Rcrypt))
    {
        if (mu8_LastAuthKeyNo == NOT_AUTHENTICATED)
        {
            ESP_LOGE(TAG, "Not authenticated");
            return -1;
        }
    }

    if (e_Mac & MAC_Tcrypt) // CRC and encrypt pi_Params
    {
        ESP_LOGD(TAG, "Sess Key IV: %s", BufToHexMsg(mpi_SessionKey->GetIV(), mpi_SessionKey->GetBlockSize()));
    
        // The CRC is calculated over the command (which is not encrypted) and the parameters to be encrypted.
        uint32_t u32_Crc = CalcCrc32(pi_Command->GetData(), pi_Command->GetCount(), pi_Params->GetData(), pi_Params->GetCount());
        if (!pi_Params->AppendUint32(u32_Crc)) {
            ESP_LOGE(TAG, "Buffer Overflow");
            return -1; // buffer overflow
        }
    
        int s32_CryptCount = mpi_SessionKey->CalcPaddedBlockSize(pi_Params->GetCount());
        if (!pi_Params->SetCount(s32_CryptCount)) {
            ESP_LOGE(TAG, "Buffer Overflow");
            return -1; // buffer overflow
        }
    
        ESP_LOGD(TAG, "CRC Params: 0x%08X", u32_Crc);
        ESP_LOGD(TAG, "Params: %s", BufToHexMsg(pi_Params->GetData(), s32_CryptCount));
    
        if (!mpi_SessionKey->CryptDataCBC(CBC_SEND, KEY_ENCIPHER, pi_Params->GetData(), pi_Params->GetData(), s32_CryptCount))
            return -1;
    
        ESP_LOGD(TAG, "Params_enc: %s", BufToHexMsg(pi_Params->GetData(), s32_CryptCount));
    }

    byte u8_Command = pi_Command->GetData()[0];

    byte u8_CalcMac[16];
    if ((e_Mac & MAC_Tmac) &&                       // Calculate the TX CMAC only if the caller requests it 
        (u8_Command != DF_INS_ADDITIONAL_FRAME) &&  // In case of DF_INS_ADDITIONAL_FRAME there are never parameters passed -> nothing to do here
        (mu8_LastAuthKeyNo != NOT_AUTHENTICATED))   // No session key -> no CMAC calculation possible
    { 
        mi_CmacBuffer.Clear();
        if (!mi_CmacBuffer.AppendBuf(pi_Command->GetData(), pi_Command->GetCount()) ||
            !mi_CmacBuffer.AppendBuf(pi_Params ->GetData(), pi_Params ->GetCount()))
            return -1;
      
        // The CMAC must be calculated here although it is not transmitted, because it maintains the IV up to date.
        // The initialization vector must always be correct otherwise the card will give an integrity error the next time the session key is used.
        if (!mpi_SessionKey->CalculateCmac(mi_CmacBuffer, u8_CalcMac))
            return -1;

        ESP_LOGV(TAG, "TX CMAC: %s", BufToHexMsg(u8_CalcMac, mpi_SessionKey->GetBlockSize()));
    }

//    int P=0;
//    mu8_PacketBuffer[P++] = PN532_COMMAND_INDATAEXCHANGE;
//    mu8_PacketBuffer[P++] = 1; // Card number (Logical target number)

//    memcpy(mu8_PacketBuffer + P, pi_Command->GetData(), pi_Command->GetCount());
//    P += pi_Command->GetCount();

//    memcpy(mu8_PacketBuffer + P, pi_Params->GetData(),  pi_Params->GetCount());
//    P += pi_Params->GetCount();

    std::vector<uint8_t> buf = {
        PN532_COMMAND_INDATAEXCHANGE,
        1 // Card number (Logical target number)
    };
    for (int i = 0; i < pi_Command->GetCount(); i++)
        buf.push_back(pi_Command->GetData()[i]);
    for (int i = 0; i < pi_Params->GetCount(); i++)
        buf.push_back(pi_Params->GetData()[i]);

    if (!pn532_write_command_check_ack_(buf))
        return -1;

    byte s32_Len = ReadData(mu8_PacketBuffer, s32_RecvSize + s32_Overhead);

    // ReadData() returns 3 byte if status error from the PN532
    // ReadData() returns 4 byte if status error from the Desfire card
    if (s32_Len < 3 || mu8_PacketBuffer[1] != PN532_COMMAND_INDATAEXCHANGE + 1)
    {
        ESP_LOGE(TAG, "DataExchange() failed");
        return -1;
    }

    // Here we get two status bytes that must be checked
    byte u8_PN532Status = mu8_PacketBuffer[2]; // contains errors from the PN532
    byte u8_CardStatus  = mu8_PacketBuffer[3]; // contains errors from the Desfire card

    mu8_LastPN532Error = u8_PN532Status;

    if (!CheckPN532Status(u8_PN532Status) || s32_Len < 4)
        return -1;

    // After any error that the card has returned the authentication is invalidated.
    // The card does not send any CMAC anymore until authenticated anew.
    if (u8_CardStatus != ST_Success && u8_CardStatus != ST_MoreFrames)
    {
        mu8_LastAuthKeyNo = NOT_AUTHENTICATED; // A new authentication is required now
    }

    if (!CheckCardStatus((DESFireStatus)u8_CardStatus))
        return -1;

    if (pe_Status)
       *pe_Status = (DESFireStatus)u8_CardStatus;

    s32_Len -= 4; // 3 bytes for INDATAEXCHANGE response + 1 byte card status

    // A CMAC may be appended to the end of the frame.
    // The CMAC calculation is important because it maintains the IV of the session key up to date.
    // If the IV is out of sync with the IV in the card, the next encryption with the session key will result in an Integrity Error.
    if ((e_Mac & MAC_Rmac) &&                                              // Calculate RX CMAC only if the caller requests it
        (u8_CardStatus == ST_Success || u8_CardStatus == ST_MoreFrames) && // In case of an error there is no CMAC in the response
        (mu8_LastAuthKeyNo != NOT_AUTHENTICATED))                          // No session key -> no CMAC calculation possible
    {
        // For example GetCardVersion() calls DataExchange() 3 times:
        // 1. u8_Command = DF_INS_GET_VERSION      -> clear CMAC buffer + append received data
        // 2. u8_Command = DF_INS_ADDITIONAL_FRAME -> append received data
        // 3. u8_Command = DF_INS_ADDITIONAL_FRAME -> append received data
        if (u8_Command != DF_INS_ADDITIONAL_FRAME)
        {
            mi_CmacBuffer.Clear();
        }

        // This is an intermediate frame. More frames will follow. There is no CMAC in the response yet.
        if (u8_CardStatus == ST_MoreFrames)
        {
            if (!mi_CmacBuffer.AppendBuf(mu8_PacketBuffer + 4, s32_Len))
                return -1;
        }
        
        if ((s32_Len >= 8) &&             // If the response is shorter than 8 bytes it surely does not contain a CMAC
           (u8_CardStatus == ST_Success)) // Response contains CMAC only in case of success
        {
            s32_Len -= 8; // Do not return the received CMAC to the caller and do not include it into the CMAC calculation
          
            byte* u8_RxMac = mu8_PacketBuffer + 4 + s32_Len;
            
            // The CMAC is calculated over the RX data + the status byte appended to the END of the RX data!
            if (!mi_CmacBuffer.AppendBuf(mu8_PacketBuffer + 4, s32_Len) || !mi_CmacBuffer.AppendUint8(u8_CardStatus)) {
                ESP_LOGE(TAG, "Buffer Overflow");
                return -1;
            }

            if (!mpi_SessionKey->CalculateCmac(mi_CmacBuffer, u8_CalcMac))
                return -1;

            ESP_LOGV(TAG, "RX CMAC: %s", BufToHexMsg(u8_CalcMac, mpi_SessionKey->GetBlockSize()));
      
            // For AES the CMAC is 16 byte, but only 8 are transmitted
            if (memcmp(u8_RxMac, u8_CalcMac, 8) != 0)
            {
                ESP_LOGE(TAG, "CMAC Mismatch");
                return -1;
            }
        }
    }

    if (s32_Len > s32_RecvSize)
    {
        ESP_LOGE(TAG, "DataExchange() Buffer overflow");
        return -1;
    } 

    if (u8_RecvBuf && s32_Len)
    {
        memcpy(u8_RecvBuf, mu8_PacketBuffer + 4, s32_Len);

        if (e_Mac & MAC_Rcrypt) // decrypt received data with session key
        {
            if (!mpi_SessionKey->CryptDataCBC(CBC_RECEIVE, KEY_DECIPHER, u8_RecvBuf, u8_RecvBuf, s32_Len))
                return -1;

            ESP_LOGV(TAG, "Decrypt: %s", BufToHexMsg(u8_RecvBuf, s32_Len));
        }    
    }
    return s32_Len;
}

bool PN532::CheckCardStatus(DESFireStatus e_Status)
{
    switch (e_Status)
    {
        case ST_Success:    // Success
        case ST_NoChanges:  // No changes made
        case ST_MoreFrames: // Another frame will follow
            return true;

        default: break; // This is just to avoid stupid gcc compiler warnings
    }

    ESP_LOGE(TAG, "Desfire Error:");
    switch (e_Status)
    {
        case ST_OutOfMemory:
            ESP_LOGE(TAG, "Not enough EEPROM memory.");
            return false;
        case ST_IllegalCommand:
            ESP_LOGE(TAG, "Illegal command.");
            return false;
        case ST_IntegrityError:
            ESP_LOGE(TAG, "Integrity error.");
            return false;
        case ST_KeyDoesNotExist:
            ESP_LOGE(TAG, "Key does not exist.");
            return false;
        case ST_WrongCommandLen:
            ESP_LOGE(TAG, "Wrong command length.");
            return false;
        case ST_PermissionDenied:
            ESP_LOGE(TAG, "Permission denied.");
            return false;
        case ST_IncorrectParam:
            ESP_LOGE(TAG, "Incorrect parameter.");
            return false;
        case ST_AppNotFound:
            ESP_LOGE(TAG, "Application not found.");
            return false;
        case ST_AppIntegrityError:
            ESP_LOGE(TAG, "Application integrity error.");
            return false;
        case ST_AuthentError:
            ESP_LOGE(TAG, "Authentication error.");
            return false;
        case ST_LimitExceeded:
            ESP_LOGE(TAG, "Limit exceeded.");
            return false;
        case ST_CardIntegrityError:
            ESP_LOGE(TAG, "Card integrity error.");
            return false;
        case ST_CommandAborted:
            ESP_LOGE(TAG, "Command aborted.");
            return false;
        case ST_CardDisabled:
            ESP_LOGE(TAG, "Card disabled.");
            return false;
        case ST_InvalidApp:
            ESP_LOGE(TAG, "Invalid application.");
            return false;
        case ST_DuplicateAidFiles:
            ESP_LOGE(TAG, "Duplicate AIDs or files.");
            return false;
        case ST_EepromError:
            ESP_LOGE(TAG, "EEPROM error.");
            return false;
        case ST_FileNotFound:
            ESP_LOGE(TAG, "File not found.");
            return false;
        case ST_FileIntegrityError:
            ESP_LOGE(TAG, "File integrity error.");
            return false;
        default:
            ESP_LOGE(TAG, "0x%02X", (byte)e_Status);
            return false;
    }
}

bool PN532::CheckPN532Status(byte u8_Status)
{
    // Bits 0...5 contain the error code.
    u8_Status &= 0x3F;

    if (u8_Status == 0)
        return true;

    ESP_LOGE(TAG, "PN532 Error 0x%02X: ", u8_Status);

    switch (u8_Status)
    {
        case 0x01: 
            ESP_LOGE(TAG, "Timeout");
            return false;
        case 0x02: 
            ESP_LOGE(TAG, "CRC error");
            return false;
        case 0x03: 
            ESP_LOGE(TAG, "Parity error");
            return false;
        case 0x04: 
            ESP_LOGE(TAG, "Wrong bit count during anti-collision");
            return false;
        case 0x05: 
            ESP_LOGE(TAG, "Framing error");
            return false;
        case 0x06: 
            ESP_LOGE(TAG, "Abnormal bit collision");
            return false;
        case 0x07: 
            ESP_LOGE(TAG, "Insufficient communication buffer");
            return false;
        case 0x09: 
            ESP_LOGE(TAG, "RF buffer overflow");
            return false;
        case 0x0A: 
            ESP_LOGE(TAG, "RF field has not been switched on");
            return false;
        case 0x0B: 
            ESP_LOGE(TAG, "RF protocol error");
            return false;
        case 0x0D: 
            ESP_LOGE(TAG, "Overheating");
            return false;
        case 0x0E: 
            ESP_LOGE(TAG, "Internal buffer overflow");
            return false;
        case 0x10: 
            ESP_LOGE(TAG, "Invalid parameter");
            return false;
        case 0x12: 
            ESP_LOGE(TAG, "Command not supported");
            return false;
        case 0x13: 
            ESP_LOGE(TAG, "Wrong data format");
            return false;
        case 0x14:
            ESP_LOGE(TAG, "Authentication error");
            return false;
        case 0x23:
            ESP_LOGE(TAG, "Wrong UID check byte");
            return false;
        case 0x25:
            ESP_LOGE(TAG, "Invalid device state");
            return false;
        case 0x26:
            ESP_LOGE(TAG, "Operation not allowed");
            return false;
        case 0x27:
            ESP_LOGE(TAG, "Command not acceptable");
            return false;
        case 0x29:
            ESP_LOGE(TAG, "Target has been released");
            return false;
        case 0x2A:
            ESP_LOGE(TAG, "Card has been exchanged");
            return false;
        case 0x2B:
            ESP_LOGE(TAG, "Card has disappeared");
            return false;
        case 0x2C:
            ESP_LOGE(TAG, "NFCID3 initiator/target mismatch");
            return false;
        case 0x2D:
            ESP_LOGE(TAG, "Over-current");
            return false;
        case 0x2E:
            ESP_LOGE(TAG, "NAD msssing");
            return false;
        default:
            ESP_LOGE(TAG, "Undocumented error");
            return false;
    }
}

bool PN532::FormatCard()
{
    ESP_LOGD(TAG, "FormatCard()");

    return (0 == DataExchange(DF_INS_FORMAT_PICC, NULL, NULL, 0, NULL, MAC_TmacRmac));
}

bool PN532::EnableRandomIDForever()
{
    ESP_LOGD(TAG, "EnableRandomIDForever()");

    TX_BUFFER(i_Command, 2);
    if (!i_Command.AppendUint8(DFEV1_INS_SET_CONFIGURATION)) {
        ESP_LOGE(TAG, "Buffer Overflow");
    }
    if (!i_Command.AppendUint8(0x00)) { // subcommand 00
        ESP_LOGE(TAG, "Buffer Overflow");
    }
    TX_BUFFER(i_Params, 16);
    if (!i_Params.AppendUint8(0x02)) { // 0x02 = enable random ID, 0x01 = disable format
        ESP_LOGE(TAG, "Buffer Overflow");
    }
    // The TX CMAC must not be calculated here because a CBC encryption operation has already been executed
    return (0 == DataExchange(&i_Command, &i_Params, NULL, 0, NULL, MAC_TcryptRmac));
}

char* PN532::BufToHexMsg(const byte* u8_Data, const uint32_t u32_DataLen, int s32_Brace1, int s32_Brace2)
{
    const char* pszNibbleToHex = "0123456789ABCDEF";
    char msg[u32_DataLen * 3 + (s32_Brace1 >= 0 ? 1 : 0) + (s32_Brace2 >= 0 ? 1 : 0)];
    uint32_t pos = 0;
    for (uint32_t i = 0; i < u32_DataLen; i++)
    {
        if ((int)i == s32_Brace1) {
            msg[pos++] = ' ';
            msg[pos++] = '<';
        }
        else if ((int)i == s32_Brace2) {
            msg[pos++] = '>';
            msg[pos++] = ' ';
        }
        else if (i > 0)
            msg[pos++] = ' ';
        msg[pos++] = pszNibbleToHex[u8_Data[i] >> 4];
        msg[pos++] = pszNibbleToHex[u8_Data[i] & 0x0F];
    }
    msg[pos] = 0;
    return msg;
}

// This CRC is used for ISO and AES authentication.
// The new Desfire EV1 authentication calculates the CRC32 also over the command, but the command is not encrypted later.
// This function allows to include the command into the calculation without the need to add the command to the same buffer that is later encrypted.
uint32_t PN532::CalcCrc32(const byte* u8_Data1, int s32_Length1, // data to process
                          const byte* u8_Data2, int s32_Length2) // optional additional data to process (these parameters may be omitted)
{
    uint32_t u32_Crc = 0xFFFFFFFF;
    u32_Crc = CalcCrc32(u8_Data1, s32_Length1, u32_Crc);
    u32_Crc = CalcCrc32(u8_Data2, s32_Length2, u32_Crc);
    return u32_Crc;
}

// private
uint32_t PN532::CalcCrc32(const byte* u8_Data, int s32_Length, uint32_t u32_Crc)
{
    for (int i=0; i<s32_Length; i++)
    {
        u32_Crc ^= u8_Data[i];
        for (int b=0; b<8; b++)
        {
            bool b_Bit = (u32_Crc & 0x01) > 0;
            u32_Crc >>= 1;
            if (b_Bit) u32_Crc ^= 0xEDB88320;
        }
    }
    return u32_Crc;
}

}  // namespace pn532
}  // namespace esphome
