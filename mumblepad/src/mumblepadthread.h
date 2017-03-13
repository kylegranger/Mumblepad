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


#ifndef __MUMBLEPADTHREAD_H
#define __MUMBLEPADTHREAD_H

#include "mumrenderer.h"


typedef enum EMumJobState {
    MUM_JOB_STATE_NONE = -1,
    MUM_JOB_STATE_DONE = 0,
    MUM_JOB_STATE_ASSIGNED = 1,
    MUM_JOB_STATE_WORKING = 2,
} EMumJobState;

typedef enum EMumJobType {
    MUM_JOB_TYPE_ENCRYPT = 0,
    MUM_JOB_TYPE_DECRYPT = 1,
} EMumJobType;

typedef struct TMumJob
{
    EMumJobState state;
    EMumJobType type;
    uint8_t *src;
    uint8_t *dst;
    uint32_t length;
    uint32_t outlength;
    uint16_t seqNum;
} TMumRenderJob;


class CMumblepadThread : public CMumRenderer {
public:
    CMumblepadThread(TMumInfo *mumInfo, uint32_t id, HANDLE serverSignal);
    ~CMumblepadThread();
    virtual void EncryptDiffuse(uint32_t round);
    virtual void EncryptConfuse(uint32_t round);
    virtual void DecryptConfuse(uint32_t round);
    virtual void DecryptDiffuse(uint32_t round);
    virtual void EncryptUpload(uint8_t *data);
    virtual void EncryptDownload(uint8_t *data);
    virtual void DecryptUpload(uint8_t *data);
    virtual void DecryptDownload(uint8_t *data);
    virtual void InitKey();
    uint8_t mPingPongBlock[2][MUM_MAX_BLOCK_SIZE];
    uint32_t mId;
    TMumJob mJob;
    HANDLE mThreadHandle;
    HANDLE mWorkerSignal;
    HANDLE mServerSignal;
    uint32_t mThreadID;
    bool mRunning;
    uint32_t mEncryptLength;
    uint32_t mDecryptLength;
    void Run();
    void Start();
    void Stop();
};




#endif