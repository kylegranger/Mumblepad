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


#ifndef __MUMBLEPADMT_H
#define __MUMBLEPADMT_H

#include "mumblepadthread.h"

#define MUM_MAX_THREADS 16
#define MUM_MAX_BYTES_PER_JOB (16*MUM_MAX_BLOCK_SIZE)


class CMumblepadMt : public CMumRenderer {
public:
    CMumblepadMt(TMumInfo *mumInfo, uint32_t numThreads);
    ~CMumblepadMt();

    void Start();
    void Stop();

    virtual EMumError EncryptBlock(uint8_t *src, uint8_t *dst, uint32_t length, uint32_t seqnum);
    virtual EMumError DecryptBlock(uint8_t *src, uint8_t *dst, uint32_t *length, uint32_t *seqnum);
    virtual EMumError Encrypt(uint8_t *src, uint8_t *dst, uint32_t length, uint32_t *outlength, uint16_t seqNum);
    virtual EMumError Decrypt(uint8_t *src, uint8_t *dst, uint32_t length, uint32_t *outlength);

    virtual void EncryptDiffuse(uint32_t round);
    virtual void EncryptConfuse(uint32_t round);
    virtual void DecryptConfuse(uint32_t round);
    virtual void DecryptDiffuse(uint32_t round);
    virtual void EncryptUpload(uint8_t *data);
    virtual void EncryptDownload(uint8_t *data);
    virtual void DecryptUpload(uint8_t *data);
    virtual void DecryptDownload(uint8_t *data);
    virtual void InitKey() { return;  }
private:
    uint32_t mNumThreads;
    CMumblepadThread *mThreads[MUM_MAX_THREADS];
    HANDLE mServerSignal;
    bool mStarted;

};


#endif