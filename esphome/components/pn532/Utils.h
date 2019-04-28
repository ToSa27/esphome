
#ifndef UTILS_H
#define UTILS_H

#include <Arduino.h>

#define TRUE   true
#define FALSE  false

#define LF  "\r\n" // LineFeed 

// Teensy definitions for digital pins:
#ifndef INPUT
    #define OUTPUT   0x1
    #define INPUT    0x0
    #define HIGH     0x1
    #define LOW      0x0
#endif

class Utils
{
public:
    static void     Print(const char*   s8_Text,  const char* s8_LF=NULL);
    static void     PrintDec  (int      s32_Data, const char* s8_LF=NULL);
    static void     PrintHex8 (byte     u8_Data,  const char* s8_LF=NULL);
    static void     PrintHex32(uint32_t u32_Data, const char* s8_LF=NULL);
    static void     PrintHexBuf(const byte* u8_Data, const uint32_t u32_DataLen, const char* s8_LF=NULL, int s32_Brace1=-1, int S32_Brace2=-1);
    static void     GenerateRandom(byte* u8_Random, int s32_Length);
    static void     RotateBlockLeft(byte* u8_Out, const byte* u8_In, int s32_Length);
    static void     BitShiftLeft(uint8_t* u8_Data, int s32_Length);
    static void     XorDataBlock(byte* u8_Out,  const byte* u8_In, const byte* u8_Xor, int s32_Length);    
    static void     XorDataBlock(byte* u8_Data, const byte* u8_Xor, int s32_Length);
    static uint32_t CalcCrc32(const byte* u8_Data1, int s32_Length1, const byte* u8_Data2=NULL, int s32_Length2=0);

private:
    static uint32_t CalcCrc32(const byte* u8_Data, int s32_Length, uint32_t u32_Crc);
};

#endif // UTILS_H
