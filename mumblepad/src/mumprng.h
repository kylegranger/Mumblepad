//////////////////////////////////////////////////////////////////////////
//                                                                      //
//   Mumblepad Block Cipher                                             //
//   Version 1, completed March 14, 2017                                //
//                                                                      //
//   Key size 4096 bytes, 32768 bits                                    //
//   Six different block sizes: 128, 256, 512, 1024, 2048, 4096 bytes   //
//   Encryption and decryption, runs on either CPU and GPU              //
//   May run multi-threaded on CPU.                                     //
//   Runs on GPU with OpenGL or OpenGL ES 2.0                           //
//                                                                      //
//   Encrypted blocks containing same plaintext are different, due to   //
//   small amount of per-block random number padding.                   //
//   Encrypted block contains length, 16-bit sequence number, 32-bit    //
//   checksum.                                                          //
//   No block cipher mode required                                      //
//   Can use parallel processing, multi-threaded encrypt/decrypt        //
//                                                                      //
//   8 rounds, 2 passes per round                                       //
//   Encrypt: diffusion pass followed by confusion pass.                //
//   Decrypt: inverse confusion followed by inverse diffusion.          //
//                                                                      //
//   Free for non-commercial use, analysis/evaluation.                  //
//                                                                      //
//   Copyright 2017, Kyle Granger                                       //
//   Email contact:  kyle.granger@chello.at                             //
//                                                                      //
//////////////////////////////////////////////////////////////////////////


#ifndef MUMPRNG_H
#define MUMPRNG_H

#include "mumdefines.h"

#define MUM_PRNG_SUBKEY_SIZE   (MUM_KEY_SIZE*16)
#define MUM_PRNG_SEED1 0xb11924e1
#define MUM_PRNG_SEED2 0x6d73e55f


class CMumPrng
{
public:
    CMumPrng(uint8_t *subkeyData);
    ~CMumPrng();
    void Fetch(uint8_t *dst, uint32_t size);

private:
    void Init();
    void Regenerate();
    void Generate(uint8_t *dst, uint32_t size);
    void XorWithSubkey();
    uint8_t mState[256];
    uint32_t mA;
    uint32_t mB;
    uint32_t mReadIndex;
    uint8_t mSubkeyData[MUM_PRNG_SUBKEY_SIZE];
    uint8_t mReadyData[MUM_PRNG_SUBKEY_SIZE];


} ;

#endif

