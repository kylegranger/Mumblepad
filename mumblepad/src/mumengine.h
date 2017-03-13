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


#ifndef MUMENGINE_H
#define MUMENGINE_H

#include "mumdefines.h"
#include "mumprng.h"
#include "mumrenderer.h"
#ifdef USE_MUM_OPENGL
#include "mumglwrapper.h"
#endif

class CMumEngine
{
public:
    CMumEngine(EMumEngineType engineType, EMumBlockType blockType, EMumPaddingType paddingType, uint32_t numThreads);
    ~CMumEngine();
    EMumError InitKey(uint8_t *key);
    EMumError LoadKey(char *keyfile);
    EMumError GetSubkey(uint32_t index, uint8_t *subkey);
    uint32_t PlaintextBlockSize();
    uint32_t EncryptedBlockSize();
    uint32_t EncryptedSize(uint32_t plaintextSize);
    EMumError EncryptBlock(uint8_t *src, uint8_t *dst, uint32_t length, uint32_t seqnum);
    EMumError DecryptBlock(uint8_t *src, uint8_t *dst, uint32_t *length, uint32_t *seqnum);

    EMumError EncryptFile(char *srcfile, char *dstfile);
    EMumError DecryptFile(char *srcfile, char *dstfile);
    EMumError Encrypt(uint8_t *src, uint8_t *dst, uint32_t length, uint32_t *outlength, uint16_t seqNum);
    EMumError Decrypt(uint8_t *src, uint8_t *dst, uint32_t length, uint32_t *outlength);

private:
    TMumInfo mMumInfo;
    CMumRenderer *mMumRenderer;
    uint32_t GetSubkeyInteger(uint8_t *subkey, uint32_t offset);
    void InitXorTextureData();
    void CreatePermuteTable(uint8_t *subkey, uint32_t numEntries, uint32_t *outTable);
    void CreatePrimeCycleWithOffset(uint32_t primeIndex, uint32_t offset, uint8_t *outCycle);

#ifdef USE_MUM_OPENGL
    static CMumGlWrapper *mMumGlWrapper;
#endif

    void InitSubkeys();
    void InitPermuteTables();
    void InitPositionTables();
    void InitBitmasks();
};


#endif

