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


#include <assert.h>
#include <string.h>
#include "stdio.h"
#include "stdlib.h"
#include "mumprng.h"



CMumPrng::CMumPrng(uint8_t *subkeyData)
{
    memcpy(mSubkeyData, subkeyData, MUM_PRNG_SUBKEY_SIZE);
    memset(mReadyData, 0, MUM_PRNG_SUBKEY_SIZE);
    mReadIndex = 0;
    Init();
    Regenerate();
}

CMumPrng::~CMumPrng()
{
}


static __inline void swap(uint8_t *a, uint8_t *b)
{
    uint8_t temp = *a;
    *a = *b;
    *b = temp;
}

void CMumPrng::Init()
{
    mA = 0;
    mB = 0;

    // RC4 initialization
    for (int i = 0; i < 256; i++)
        mState[i] = i;

    // our subkey area is 64KB -- for the state initialization we will
    // use a 256-byte from there, 89 bytes before the end.
    uint8_t *prngKey = &mSubkeyData[MUM_PRNG_SUBKEY_SIZE - 256 - 89];
    uint32_t j = 0;
    for (int i = 0; i < 256; i++)
    {
        j = (j + mState[i] + prngKey[i]) & 255;
        swap(&mState[i], &mState[j]);
    }
}

void CMumPrng::Fetch(uint8_t *dst, uint32_t size)
{
    if (size > (MUM_PRNG_SUBKEY_SIZE - mReadIndex))
        Regenerate();
    memcpy(dst, mReadyData+mReadIndex,size);
    mReadIndex += size;
}


void CMumPrng::XorWithSubkey()
{
    uint32_t *src = (uint32_t*) mReadyData;
    uint32_t *xor = (uint32_t*) mSubkeyData;
    for (uint32_t i = 0; i < MUM_PRNG_SUBKEY_SIZE / 4; i++)
        *src++ ^= *xor++;
}

void CMumPrng::Regenerate()
{
    Generate(mReadyData, MUM_PRNG_SUBKEY_SIZE);
    // every 64KB of stream generated gets XOR's with the subkey.
    XorWithSubkey();
    mReadIndex = 0;
}

void CMumPrng::Generate(uint8_t *dst, uint32_t size)
{
    for (uint32_t i = 0; i < size; i++)
    {
        // RC4 stream generation
        mA = (mA + 1) & 255;
        mB = (mB + mState[mA]) & 255;
        swap(&mState[mA], &mState[mB]);
        uint32_t c = (mState[mA] + mState[mA]) & 255;
        dst[i] = mState[c];
    }
}



