#pragma once

#include "esphome/core/component.h"
#include "esphome/core/automation.h"
#include "esphome/components/binary_sensor/binary_sensor.h"
#include "esphome/components/spi/spi.h"
#include "Desfire.h"
#include "Secrets.h"
#include "Buffer.h"

namespace esphome {
namespace pn532 {

class PN532BinarySensor;
class PN532Trigger;

class PN532 : public PollingComponent, public spi::SPIDevice {
 public:
  void setup() override;

  void dump_config() override;

  void update() override;
  float get_setup_priority() const override;

  void loop() override;

  void register_tag(PN532BinarySensor *tag) { this->binary_sensors_.push_back(tag); }
  void register_trigger(PN532Trigger *trig) { this->triggers_.push_back(trig); }

 protected:
  bool is_device_msb_first() override;

  std::string card_type_;
  void set_card_type(const std::string &card_type);
  std::string get_card_type();

  /// Write the full command given in data to the PN532
  void pn532_write_command_(const std::vector<uint8_t> &data);
  bool pn532_write_command_check_ack_(const std::vector<uint8_t> &data);

  /** Read a data frame from the PN532 and return the result as a vector.
   *
   * Note that is_ready needs to be checked first before requesting this method.
   *
   * On failure, an empty vector is returned.
   */
  std::vector<uint8_t> pn532_read_data_();

  /** Checks if the PN532 has set its ready status flag.
   *
   * Procedure goes as follows:
   * - Host sends command to PN532 "write data"
   * - Wait for readiness (until PN532 has processed command) by polling "read status"/is_ready_
   * - Parse ACK/NACK frame with "read data" byte
   *
   * - If data required, wait until device reports readiness again
   * - Then call "read data" and read certain number of bytes (length is given at offset 4 of frame)
   */
  bool is_ready_();
  bool wait_ready_();

  bool read_ack_();

  bool requested_read_{false};
  std::vector<PN532BinarySensor *> binary_sensors_;
  std::vector<PN532Trigger *> triggers_;
  enum PN532Error {
    NONE = 0,
    WAKEUP_FAILED,
    SAM_COMMAND_FAILED,
    RETRY_COMMAND_FAILED,
  } error_code_{NONE};

  Desfire gi_PN532;
  //DESFireKey gi_PiccMasterKey;
  DES gi_PiccMasterKey_DES;
  AES gi_PiccMasterKey_AES;
  union 
  {
      uint64_t  u64;      
      byte      u8[8];
  } last_uid;
  uint8_t last_uid_len;
  bool ReadCard(byte u8_UID[8], kCard* pk_Card);
  bool AuthenticatePICC(byte* pu8_KeyVersion);
  bool PN532::CheckDesfireSecret(uint8_t* user_id);
  bool PN532::GenerateDesfireSecrets(uint8_t* user_id, DESFireKey* pi_AppMasterKey, byte u8_StoreValue[16]);
};

class PN532BinarySensor : public binary_sensor::BinarySensor {
 public:
  void set_uid(const std::vector<uint8_t> &uid) { uid_ = uid; }

  bool process(const uint8_t *data, uint8_t len);

  void on_scan_end() {
    if (!this->found_) {
      this->publish_state(false);
    }
    this->found_ = false;
  }

 protected:
  std::vector<uint8_t> uid_;
  bool found_{false};
};

class PN532Trigger : public Trigger<std::string> {
 public:
  void process(const uint8_t *uid, uint8_t uid_length);
};

}  // namespace pn532
}  // namespace esphome
