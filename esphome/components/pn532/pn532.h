#pragma once

#include "esphome/core/component.h"
#include "esphome/core/automation.h"
#include "esphome/components/binary_sensor/binary_sensor.h"
#include "esphome/components/spi/spi.h"
#include "DES.h"
#include "AES128.h"
#include "Buffer.h"

namespace esphome {
namespace pn532 {

class PN532BinarySensor;
class PN532Trigger;

// // Just an invalid key number
#define NOT_AUTHENTICATED      255

#define MAX_FRAME_SIZE         60 // The maximum total length of a packet that is transfered to / from the card

// // ------- Desfire legacy instructions --------

// #define DF_INS_AUTHENTICATE_LEGACY        0x0A
#define DF_INS_CHANGE_KEY_SETTINGS        0x54
// #define DF_INS_GET_KEY_SETTINGS           0x45
#define DF_INS_CHANGE_KEY                 0xC4
#define DF_INS_GET_KEY_VERSION            0x64

#define DF_INS_CREATE_APPLICATION         0xCA
#define DF_INS_DELETE_APPLICATION         0xDA
#define DF_INS_GET_APPLICATION_IDS        0x6A
#define DF_INS_SELECT_APPLICATION         0x5A

#define DF_INS_FORMAT_PICC                0xFC
#define DF_INS_GET_VERSION                0x60

// #define DF_INS_GET_FILE_IDS               0x6F
// #define DF_INS_GET_FILE_SETTINGS          0xF5
// #define DF_INS_CHANGE_FILE_SETTINGS       0x5F
#define DF_INS_CREATE_STD_DATA_FILE       0xCD
// #define DF_INS_CREATE_BACKUP_DATA_FILE    0xCB
// #define DF_INS_CREATE_VALUE_FILE          0xCC
// #define DF_INS_CREATE_LINEAR_RECORD_FILE  0xC1
// #define DF_INS_CREATE_CYCLIC_RECORD_FILE  0xC0
// #define DF_INS_DELETE_FILE                0xDF

#define DF_INS_READ_DATA                  0xBD
#define DF_INS_WRITE_DATA                 0x3D
// #define DF_INS_GET_VALUE                  0x6C
// #define DF_INS_CREDIT                     0x0C
// #define DF_INS_DEBIT                      0xDC
// #define DF_INS_LIMITED_CREDIT             0x1C
// #define DF_INS_WRITE_RECORD               0x3B
// #define DF_INS_READ_RECORDS               0xBB
// #define DF_INS_CLEAR_RECORD_FILE          0xEB
// #define DF_COMMIT_TRANSACTION             0xC7
// #define DF_INS_ABORT_TRANSACTION          0xA7

#define DF_INS_ADDITIONAL_FRAME           0xAF // data did not fit into a frame, another frame will follow

// // -------- Desfire EV1 instructions ----------

#define DFEV1_INS_AUTHENTICATE_ISO        0x1A
#define DFEV1_INS_AUTHENTICATE_AES        0xAA
// #define DFEV1_INS_FREE_MEM                0x6E
// #define DFEV1_INS_GET_DF_NAMES            0x6D
#define DFEV1_INS_GET_CARD_UID            0x51
// #define DFEV1_INS_GET_ISO_FILE_IDS        0x61
#define DFEV1_INS_SET_CONFIGURATION       0x5C

// // ---------- ISO7816 instructions ------------

// #define ISO7816_INS_EXTERNAL_AUTHENTICATE 0x82
// #define ISO7816_INS_INTERNAL_AUTHENTICATE 0x88
// #define ISO7816_INS_APPEND_RECORD         0xE2
// #define ISO7816_INS_GET_CHALLENGE         0x84
// #define ISO7816_INS_READ_RECORDS          0xB2
// #define ISO7816_INS_SELECT_FILE           0xA4
// #define ISO7816_INS_READ_BINARY           0xB0
// #define ISO7816_INS_UPDATE_BINARY         0xD6

// #define PN532_TIMEOUT  1000
#define PN532_PACKBUFFSIZE   80

#define PN532_PREAMBLE                      (0x00)
#define PN532_STARTCODE1                    (0x00)
#define PN532_STARTCODE2                    (0xFF)
#define PN532_POSTAMBLE                     (0x00)

#define PN532_HOSTTOPN532                   (0xD4)
#define PN532_PN532TOHOST                   (0xD5)

// // PN532 Commands
// #define PN532_COMMAND_DIAGNOSE              (0x00)
#define PN532_COMMAND_GETFIRMWAREVERSION    (0x02)
// #define PN532_COMMAND_GETGENERALSTATUS      (0x04)
// #define PN532_COMMAND_READREGISTER          (0x06)
// #define PN532_COMMAND_WRITEREGISTER         (0x08)
// #define PN532_COMMAND_READGPIO              (0x0C)
// #define PN532_COMMAND_WRITEGPIO             (0x0E)
// #define PN532_COMMAND_SETSERIALBAUDRATE     (0x10)
// #define PN532_COMMAND_SETPARAMETERS         (0x12)
#define PN532_COMMAND_SAMCONFIGURATION      (0x14)
// #define PN532_COMMAND_POWERDOWN             (0x16)
#define PN532_COMMAND_RFCONFIGURATION       (0x32)
// #define PN532_COMMAND_RFREGULATIONTEST      (0x58)
// #define PN532_COMMAND_INJUMPFORDEP          (0x56)
// #define PN532_COMMAND_INJUMPFORPSL          (0x46)
#define PN532_COMMAND_INLISTPASSIVETARGET   (0x4A)
// #define PN532_COMMAND_INATR                 (0x50)
// #define PN532_COMMAND_INPSL                 (0x4E)
#define PN532_COMMAND_INDATAEXCHANGE        (0x40)
// #define PN532_COMMAND_INCOMMUNICATETHRU     (0x42)
// #define PN532_COMMAND_INDESELECT            (0x44)
// #define PN532_COMMAND_INRELEASE             (0x52)
// #define PN532_COMMAND_INSELECT              (0x54)
// #define PN532_COMMAND_INAUTOPOLL            (0x60)
// #define PN532_COMMAND_TGINITASTARGET        (0x8C)
// #define PN532_COMMAND_TGSETGENERALBYTES     (0x92)
// #define PN532_COMMAND_TGGETDATA             (0x86)
// #define PN532_COMMAND_TGSETDATA             (0x8E)
// #define PN532_COMMAND_TGSETMETADATA         (0x94)
// #define PN532_COMMAND_TGGETINITIATORCOMMAND (0x88)
// #define PN532_COMMAND_TGRESPONSETOINITIATOR (0x90)
// #define PN532_COMMAND_TGGETTARGETSTATUS     (0x8A)

// #define PN532_WAKEUP                        (0x55)

#define PN532_SPI_STATUSREAD                (0x02)
#define PN532_SPI_DATAWRITE                 (0x01)
#define PN532_SPI_DATAREAD                  (0x03)
// #define PN532_SPI_READY                     (0x01)

// #define PN532_I2C_ADDRESS                   (0x48 >> 1)
// #define PN532_I2C_READY                     (0x01)

// #define PN532_GPIO_P30                      (0x01)
// #define PN532_GPIO_P31                      (0x02)
// #define PN532_GPIO_P32                      (0x04)
// #define PN532_GPIO_P33                      (0x08)
// #define PN532_GPIO_P34                      (0x10)
// #define PN532_GPIO_P35                      (0x20)
// #define PN532_GPIO_VALIDATIONBIT            (0x80)

#define CARD_TYPE_106KB_ISO14443A           (0x00) // card baudrate 106 kB
#define CARD_TYPE_212KB_FELICA              (0x01) // card baudrate 212 kB
#define CARD_TYPE_424KB_FELICA              (0x02) // card baudrate 424 kB
#define CARD_TYPE_106KB_ISO14443B           (0x03) // card baudrate 106 kB
#define CARD_TYPE_106KB_JEWEL               (0x04) // card baudrate 106 kB

// // Prefixes for NDEF Records (to identify record type), not used
// #define NDEF_URIPREFIX_NONE                 (0x00)
// #define NDEF_URIPREFIX_HTTP_WWWDOT          (0x01)
// #define NDEF_URIPREFIX_HTTPS_WWWDOT         (0x02)
// #define NDEF_URIPREFIX_HTTP                 (0x03)
// #define NDEF_URIPREFIX_HTTPS                (0x04)
// #define NDEF_URIPREFIX_TEL                  (0x05)
// #define NDEF_URIPREFIX_MAILTO               (0x06)
// #define NDEF_URIPREFIX_FTP_ANONAT           (0x07)
// #define NDEF_URIPREFIX_FTP_FTPDOT           (0x08)
// #define NDEF_URIPREFIX_FTPS                 (0x09)
// #define NDEF_URIPREFIX_SFTP                 (0x0A)
// #define NDEF_URIPREFIX_SMB                  (0x0B)
// #define NDEF_URIPREFIX_NFS                  (0x0C)
// #define NDEF_URIPREFIX_FTP                  (0x0D)
// #define NDEF_URIPREFIX_DAV                  (0x0E)
// #define NDEF_URIPREFIX_NEWS                 (0x0F)
// #define NDEF_URIPREFIX_TELNET               (0x10)
// #define NDEF_URIPREFIX_IMAP                 (0x11)
// #define NDEF_URIPREFIX_RTSP                 (0x12)
// #define NDEF_URIPREFIX_URN                  (0x13)
// #define NDEF_URIPREFIX_POP                  (0x14)
// #define NDEF_URIPREFIX_SIP                  (0x15)
// #define NDEF_URIPREFIX_SIPS                 (0x16)
// #define NDEF_URIPREFIX_TFTP                 (0x17)
// #define NDEF_URIPREFIX_BTSPP                (0x18)
// #define NDEF_URIPREFIX_BTL2CAP              (0x19)
// #define NDEF_URIPREFIX_BTGOEP               (0x1A)
// #define NDEF_URIPREFIX_TCPOBEX              (0x1B)
// #define NDEF_URIPREFIX_IRDAOBEX             (0x1C)
// #define NDEF_URIPREFIX_FILE                 (0x1D)
// #define NDEF_URIPREFIX_URN_EPC_ID           (0x1E)
// #define NDEF_URIPREFIX_URN_EPC_TAG          (0x1F)
// #define NDEF_URIPREFIX_URN_EPC_PAT          (0x20)
// #define NDEF_URIPREFIX_URN_EPC_RAW          (0x21)
// #define NDEF_URIPREFIX_URN_EPC              (0x22)
// #define NDEF_URIPREFIX_URN_NFC              (0x23)

// Status codes (errors) returned from Desfire card
enum DESFireStatus
{
    ST_Success               = 0x00,
    ST_NoChanges             = 0x0C,
    ST_OutOfMemory           = 0x0E,
    ST_IllegalCommand        = 0x1C,
    ST_IntegrityError        = 0x1E,
    ST_KeyDoesNotExist       = 0x40,
    ST_WrongCommandLen       = 0x7E,
    ST_PermissionDenied      = 0x9D,
    ST_IncorrectParam        = 0x9E,
    ST_AppNotFound           = 0xA0,
    ST_AppIntegrityError     = 0xA1,
    ST_AuthentError          = 0xAE,
    ST_MoreFrames            = 0xAF, // data did not fit into a frame, another frame will follow
    ST_LimitExceeded         = 0xBE,
    ST_CardIntegrityError    = 0xC1,
    ST_CommandAborted        = 0xCA,
    ST_CardDisabled          = 0xCD,
    ST_InvalidApp            = 0xCE,
    ST_DuplicateAidFiles     = 0xDE,
    ST_EepromError           = 0xEE,
    ST_FileNotFound          = 0xF0,
    ST_FileIntegrityError    = 0xF1,
};

/*
// Card information about software and hardware version.
struct DESFireCardVersion
{
    byte hardwareVendorId;    // The hardware vendor
    byte hardwareType;        // The hardware type
    byte hardwareSubType;     // The hardware subtype
    byte hardwareMajVersion;  // The hardware major version
    byte hardwareMinVersion;  // The hardware minor version
    byte hardwareStorageSize; // The hardware storage size
    byte hardwareProtocol;    // The hardware protocol

    byte softwareVendorId;    // The software vendor
    byte softwareType;        // The software type
    byte softwareSubType;     // The software subtype
    byte softwareMajVersion;  // The software major version
    byte softwareMinVersion;  // The software minor version
    byte softwareStorageSize; // The software storage size
    byte softwareProtocol;    // The software protocol

    byte uid[7];              // The serial card number
    byte batchNo[5];          // The batch number
    byte cwProd;              // The production week (BCD)
    byte yearProd;            // The production year (BCD)
};
*/

// MK = Application Master Key or PICC Master Key
enum DESFireKeySettings
{
    // ------------ BITS 0-3 ---------------
    KS_ALLOW_CHANGE_MK                = 0x01, // If this bit is set, the MK can be changed, otherwise it is frozen.
    KS_LISTING_WITHOUT_MK             = 0x02, // Picc key: If this bit is set, GetApplicationIDs, GetKeySettings do not require MK authentication.
                                              // App  key: If this bit is set, GetFileIDs, GetFileSettings, GetKeySettings do not require MK authentication.
    KS_CREATE_DELETE_WITHOUT_MK       = 0x04, // Picc key: If this bit is set, CreateApplication does not require MK authentication.
                                              // App  key: If this bit is set, CreateFile, DeleteFile do not require MK authentication.
    KS_CONFIGURATION_CHANGEABLE       = 0x08, // If this bit is set, the configuration settings of the MK can be changed, otherwise they are frozen.
    
    // ------------ BITS 4-7 (not used for the PICC master key) -------------
    KS_CHANGE_KEY_WITH_MK             = 0x00, // A key change requires MK authentication
    KS_CHANGE_KEY_WITH_KEY_1          = 0x10, // A key change requires authentication with key 1
    KS_CHANGE_KEY_WITH_KEY_2          = 0x20, // A key change requires authentication with key 2
    KS_CHANGE_KEY_WITH_KEY_3          = 0x30, // A key change requires authentication with key 3
    KS_CHANGE_KEY_WITH_KEY_4          = 0x40, // A key change requires authentication with key 4 
    KS_CHANGE_KEY_WITH_KEY_5          = 0x50, // A key change requires authentication with key 5
    KS_CHANGE_KEY_WITH_KEY_6          = 0x60, // A key change requires authentication with key 6
    KS_CHANGE_KEY_WITH_KEY_7          = 0x70, // A key change requires authentication with key 7
    KS_CHANGE_KEY_WITH_KEY_8          = 0x80, // A key change requires authentication with key 8
    KS_CHANGE_KEY_WITH_KEY_9          = 0x90, // A key change requires authentication with key 9
    KS_CHANGE_KEY_WITH_KEY_A          = 0xA0, // A key change requires authentication with key 10
    KS_CHANGE_KEY_WITH_KEY_B          = 0xB0, // A key change requires authentication with key 11
    KS_CHANGE_KEY_WITH_KEY_C          = 0xC0, // A key change requires authentication with key 12
    KS_CHANGE_KEY_WITH_KEY_D          = 0xD0, // A key change requires authentication with key 13
    KS_CHANGE_KEY_WITH_TARGETED_KEY   = 0xE0, // A key change requires authentication with the same key that is to be changed
    KS_CHANGE_KEY_FROZEN              = 0xF0, // All keys are frozen
    
    // -------------------------------------
    KS_FACTORY_DEFAULT                = 0x0F,
};

enum DESFireAccessRights
{
    AR_KEY0  = 0x00, // Authentication with application key 0 required (master key)
    AR_KEY1  = 0x01, // Authentication with application key 1 required
    AR_KEY2  = 0x02, // ...
    AR_KEY3  = 0x03,
    AR_KEY4  = 0x04,
    AR_KEY5  = 0x05,
    AR_KEY6  = 0x06,
    AR_KEY7  = 0x07,
    AR_KEY8  = 0x08,
    AR_KEY9  = 0x09,
    AR_KEY10 = 0x0A,
    AR_KEY11 = 0x0B,
    AR_KEY12 = 0x0C,
    AR_KEY13 = 0x0D,
    AR_FREE  = 0x0E, // Always allowed even without authentication
    AR_NEVER = 0x0F  // Always forbidden even with authentication
};

struct DESFireFilePermissions
{
    DESFireAccessRights  e_ReadAccess;         
    DESFireAccessRights  e_WriteAccess;        
    DESFireAccessRights  e_ReadAndWriteAccess; 
    DESFireAccessRights  e_ChangeAccess;       

    uint16_t Pack()
    {
        return (e_ReadAccess << 12) | (e_WriteAccess <<  8) | (e_ReadAndWriteAccess <<  4) | e_ChangeAccess;
    }
    void Unpack(uint16_t u16_Data)
    {
        e_ReadAccess         = (DESFireAccessRights)((u16_Data >> 12) & 0x0F);
        e_WriteAccess        = (DESFireAccessRights)((u16_Data >>  8) & 0x0F);
        e_ReadAndWriteAccess = (DESFireAccessRights)((u16_Data >>  4) & 0x0F);
        e_ChangeAccess       = (DESFireAccessRights)((u16_Data      ) & 0x0F);
    }
};

// Defines if data transmitted to files is encrypted (with the session key) or secured with a MAC
enum DESFireFileEncryption
{
    CM_PLAIN   = 0x00,
    CM_MAC     = 0x01,   // not implemented (Plain data transfer with additional MAC)
    CM_ENCRYPT = 0x03,   // not implemented (Does not make data stored on the card more secure. Only encrypts the transfer between Teensy and the card)
};

enum DESFireFileType
{
    MDFT_STANDARD_DATA_FILE             = 0x00,
    MDFT_BACKUP_DATA_FILE               = 0x01, // not implemented
    MDFT_VALUE_FILE_WITH_BACKUP         = 0x02, // not implemented
    MDFT_LINEAR_RECORD_FILE_WITH_BACKUP = 0x03, // not implemented
    MDFT_CYCLIC_RECORD_FILE_WITH_BACKUP = 0x04, // not implemented
};

struct DESFireFileSettings
{
    DESFireFileType        e_FileType;
    DESFireFileEncryption  e_Encrypt;
    DESFireFilePermissions k_Permis;
    // -----------------------------
    // used only for MDFT_STANDARD_DATA_FILE and MDFT_BACKUP_DATA_FILE
    uint32_t u32_FileSize;
    // -----------------------------
    // used only for MDFT_VALUE_FILE_WITH_BACKUP
    uint32_t  u32_LowerLimit;
    uint32_t  u32_UpperLimit;
    uint32_t  u32_LimitedCreditValue;
    bool      b_LimitedCreditEnabled;
    // -----------------------------
    // used only for MDFT_LINEAR_RECORD_FILE_WITH_BACKUP and MDFT_CYCLIC_RECORD_FILE_WITH_BACKUP
    uint32_t  u32_RecordSize;
    uint32_t  u32_MaxNumberRecords;
    uint32_t  u32_CurrentNumberRecords;
};

enum DESFireCmac
{
    MAC_None   = 0,
    // Transmit data:
    MAC_Tmac   = 1, // The CMAC must be calculated for the TX data sent to the card although this Tx CMAC is not transmitted
    MAC_Tcrypt = 2, // To the parameters sent to the card a CRC32 must be appended and then they must be encrypted with the session key    
    // Receive data:
    MAC_Rmac   = 4, // The CMAC must be calculated for the RX data received from the card. If status == ST_Success -> verify the CMAC in the response
    MAC_Rcrypt = 8, // The data received from the card must be decrypted with the session key
    // Combined:
    MAC_TmacRmac   = MAC_Tmac   | MAC_Rmac,
    MAC_TmacRcrypt = MAC_Tmac   | MAC_Rcrypt,
    MAC_TcryptRmac = MAC_Tcrypt | MAC_Rmac,
};

enum eCardType
{
    CARD_Unknown   = 0, // Mifare Classic or other card
    CARD_Desfire   = 1, // A Desfire card with normal 7 byte UID  (bit 0)
    CARD_DesRandom = 3, // A Desfire card with 4 byte random UID  (bit 0 + 1)
};

struct kCard
{
    union {
      uint64_t  u64;      
      byte      u8[8];
    } Uid;
    byte     u8_UidLength;   // UID = 4 or 7 bytes
    byte     u8_KeyVersion;  // for Desfire random ID cards
    bool      b_PN532_Error; // true -> the error comes from the PN532, false -> crypto error
    eCardType e_CardType;    
};

class PN532 : public PollingComponent, public spi::SPIDevice {
 public:
  void setup() override;

  void dump_config() override;

  void update() override;
  float get_setup_priority() const override;

  void loop() override;

  void register_tag(PN532BinarySensor *tag) { this->binary_sensors_.push_back(tag); }
  void register_trigger(PN532Trigger *trig) { this->triggers_.push_back(trig); }

  void set_card_type(const std::string &card_type);
  std::string get_card_type();
  void set_master_key(const std::string &master_key);
  void set_application_key(const std::string &application_key);
  void set_value_key(const std::string &value_key);
  void set_application_id(const std::string &application_id);
  void set_file_id(const byte file_id);
  void set_key_version(const byte key_version);

    PN532();
//    bool GetCardVersion(DESFireCardVersion* pk_Version);
    bool FormatCard();
    bool EnableRandomIDForever();
    bool GetRealCardID(byte u8_UID[7]);
//    bool GetFreeMemory(uint32_t* pu32_Memory);
    // ---------------------    
    bool Authenticate (byte u8_KeyNo, DESFireKey* pi_Key);
    bool ChangeKey    (byte u8_KeyNo, DESFireKey* pi_NewKey, DESFireKey* pi_CurKey);
    bool GetKeyVersion(byte u8_KeyNo, byte* pu8_Version);
//    bool GetKeySettings   (DESFireKeySettings* pe_Settg, byte* pu8_KeyCount, DESFireKeyType* pe_KeyType);
    bool ChangeKeySettings(DESFireKeySettings e_NewSettg);  
    // ---------------------
    bool GetApplicationIDs(uint32_t u32_IDlist[28], byte* pu8_AppCount);
    bool CreateApplication(uint32_t u32_AppID, DESFireKeySettings e_Settg, byte u8_KeyCount, DESFireKeyType e_KeyType);
    bool SelectApplication(uint32_t u32_AppID);    
    bool DeleteApplication(uint32_t u32_AppID);    
    bool DeleteApplicationIfExists(uint32_t u32_AppID);
    // ---------------------
//    bool GetFileIDs       (byte* u8_FileIDs, byte* pu8_FileCount);
//    bool GetFileSettings  (byte u8_FileID, DESFireFileSettings* pk_Settings);
//    bool DeleteFile       (byte u8_FileID);
    bool CreateStdDataFile(byte u8_FileID, DESFireFilePermissions* pk_Permis, int s32_FileSize);
    bool ReadFileData     (byte u8_FileID, int s32_Offset, int s32_Length, byte* u8_DataBuffer);
    bool WriteFileData    (byte u8_FileID, int s32_Offset, int s32_Length, const byte* u8_DataBuffer);
//  	bool ReadFileValue    (byte u8_FileID, uint32_t* pu32_Value);
    // ---------------------
//    bool SwitchOffRfField();  // overrides PN532::SwitchOffRfField()
//    bool Selftest();
    byte GetLastPN532Error(); // See comment for this function in CPP file

    DES  DES2_DEFAULT_KEY; // 2K3DES key with  8 zeroes {00,00,00,00,00,00,00,00}
    DES  DES3_DEFAULT_KEY; // 3K3DES key with 24 zeroes 
    AES  AES_DEFAULT_KEY; // AES    key with 16 zeroes

    byte mu8_DebugLevel;   // 0, 1, or 2
    byte mu8_PacketBuffer[PN532_PACKBUFFSIZE];

    bool ReadPacket(byte* buff, byte len);
    byte ReadData(byte* buff, byte len);
    bool ReadPassiveTargetID(byte* u8_UidBuffer, byte* pu8_UidLength, eCardType* pe_CardType);

 protected:
  bool is_device_msb_first() override;

  std::string card_type_;

  /// Write the full command given in data to the PN532
  void pn532_write_command_(const std::vector<uint8_t> &data);
  bool pn532_write_command_check_ack_(const std::vector<uint8_t> &data);

  std::vector<uint8_t> pn532_read_data_();

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

  DES gi_PiccMasterKey_DES;
  AES gi_PiccMasterKey_AES;
  kCard last_card;
  bool ReadCard(kCard* pk_Card);
  bool AuthenticatePICC(byte* pu8_KeyVersion);
  bool CheckDesfireSecret(uint8_t* user_id);
  bool GenerateDesfireSecrets(uint8_t* user_id, DESFireKey* pi_AppMasterKey, byte u8_StoreValue[16]);
  bool StoreDesfireSecret(uint8_t* user_id);
  bool CheckPN532Status(byte u8_Status);

private:
    byte SECRET_PICC_MASTER_KEY[24];
    byte SECRET_APPLICATION_KEY[24];
    byte SECRET_STORE_VALUE_KEY[24];
    uint32_t CARD_APPLICATION_ID;
    byte CARD_FILE_ID;
    byte CARD_KEY_VERSION;

    int  DataExchange(byte      u8_Command, TxBuffer* pi_Params, byte* u8_RecvBuf, int s32_RecvSize, DESFireStatus* pe_Status, DESFireCmac e_Mac);
    int  DataExchange(TxBuffer* pi_Command, TxBuffer* pi_Params, byte* u8_RecvBuf, int s32_RecvSize, DESFireStatus* pe_Status, DESFireCmac e_Mac);    
    bool CheckCardStatus(DESFireStatus e_Status);
//    bool SelftestKeyChange(uint32_t u32_Application, DESFireKey* pi_DefaultKey, DESFireKey* pi_NewKeyA, DESFireKey* pi_NewKeyB);

    byte          mu8_LastAuthKeyNo; // The last key which did a successful authetication (0xFF if not yet authenticated)
    uint32_t      mu32_LastApplication;
    DESFireKey*   mpi_SessionKey;
    AES           mi_AesSessionKey;
    DES           mi_DesSessionKey;
    byte          mu8_LastPN532Error;

    // Must have enough space to hold the entire response from DF_INS_GET_APPLICATION_IDS (84 byte) + CMAC padding
    byte          mu8_CmacBuffer_Data[120]; 
    TxBuffer      mi_CmacBuffer;

    void LogHex(byte loglevel, const char* msg, const byte* u8_Data, const uint32_t u32_DataLen, int s32_Brace1=-1, int s32_Brace2=-1);
    void LogDebugHex(const char* msg, const byte* u8_Data, const uint32_t u32_DataLen, int s32_Brace1=-1, int s32_Brace2=-1);
    void LogVerboseHex(const char* msg, const byte* u8_Data, const uint32_t u32_DataLen, int s32_Brace1=-1, int s32_Brace2=-1);

    uint32_t CalcCrc32(const byte* u8_Data1, int s32_Length1, const byte* u8_Data2=NULL, int s32_Length2=0);
    uint32_t CalcCrc32(const byte* u8_Data, int s32_Length, uint32_t u32_Crc);
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
