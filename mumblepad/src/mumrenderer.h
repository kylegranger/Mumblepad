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


#ifndef MUMRENDERER_H
#define MUMRENDERER_H

#include "mumdefines.h"
#include "mumprng.h"

class CMumRenderer {

public:

    CMumRenderer(TMumInfo *mumInfo);
    virtual ~CMumRenderer();

    virtual EMumError EncryptBlock(uint8_t *src, uint8_t *dst, uint32_t length, uint32_t seqnum);
    virtual EMumError DecryptBlock(uint8_t *src, uint8_t *dst, uint32_t *length, uint32_t *seqnum);
    virtual EMumError Encrypt(uint8_t *src, uint8_t *dst, uint32_t length, uint32_t *outlength, uint16_t seqNum);
    virtual EMumError Decrypt(uint8_t *src, uint8_t *dst, uint32_t length, uint32_t *outlength);


    virtual void EncryptDiffuse(uint32_t round) = 0;
    virtual void EncryptConfuse(uint32_t round) = 0;
    virtual void DecryptConfuse(uint32_t round) = 0;
    virtual void DecryptDiffuse(uint32_t round) = 0;
    virtual void EncryptUpload(uint8_t *data) = 0;
    virtual void EncryptDownload(uint8_t *data) = 0;
    virtual void DecryptUpload(uint8_t *data) = 0;
    virtual void DecryptDownload(uint8_t *data) = 0;
    virtual void InitKey() = 0;

    void ResetEncryption() { numEncryptedBlocks = 0; }
    void ResetDecryption() { numDecryptedBlocks = 0; }
protected:
    TMumInfo *mMumInfo;
    CMumPrng *mPrng;
    __int64 numEncryptedBlocks;
    __int64 numDecryptedBlocks;
    __int64 blockLatency;
    uint8_t  mPackedData[MUM_MAX_BLOCK_SIZE];
    uint8_t mPingPongBlock[2][MUM_MAX_BLOCK_SIZE];
    uint8_t mPadding[MUM_PADDING_SIZE_R32];


    uint32_t ComputeChecksum(uint8_t *data, uint32_t size);
    void SetPadding(uint8_t *src, uint32_t length);

    EMumError(CMumRenderer::*packData)(uint8_t *unpackedData, uint32_t length, uint32_t seqnum);
    EMumError(CMumRenderer::*unpackData)(uint8_t *unpackedData, uint32_t *length, uint32_t *seqnum);
    EMumError PackDataR32(uint8_t *unpackedData, uint32_t length, uint32_t seqnum);
    EMumError PackDataR16(uint8_t *unpackedData, uint32_t length, uint32_t seqnum);
    EMumError PackDataR8(uint8_t *unpackedData, uint32_t length, uint32_t seqnum);
    EMumError PackDataR4(uint8_t *unpackedData, uint32_t length, uint32_t seqnum);
    EMumError PackDataR2(uint8_t *unpackedData, uint32_t length, uint32_t seqnum);
    EMumError PackDataR1(uint8_t *unpackedData, uint32_t length, uint32_t seqnum);
    EMumError UnpackDataR32(uint8_t *unpackedData, uint32_t *length, uint32_t *seqnum);
    EMumError UnpackDataR16(uint8_t *unpackedData, uint32_t *length, uint32_t *seqnum);
    EMumError UnpackDataR8(uint8_t *unpackedData, uint32_t *length, uint32_t *seqnum);
    EMumError UnpackDataR4(uint8_t *unpackedData, uint32_t *length, uint32_t *seqnum);
    EMumError UnpackDataR2(uint8_t *unpackedData, uint32_t *length, uint32_t *seqnum);
    EMumError UnpackDataR1(uint8_t *unpackedData, uint32_t *length, uint32_t *seqnum);

};


#endif

