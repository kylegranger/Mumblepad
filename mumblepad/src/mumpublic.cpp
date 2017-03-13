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


#include "mumpublic.h"
#include "mumengine.h"
#include "stdio.h"
#include "assert.h"


EMumError MumEncryptedSize(void *mev, uint32_t plaintextSize, uint32_t *encryptedSize)
{
    CMumEngine *me = NULL;

    *encryptedSize = 0;
    me = (CMumEngine *)mev;
    *encryptedSize = me->EncryptedSize(plaintextSize);

    return MUM_ERROR_OK;
}



void MumDestroyEngine(void *mev)
{
    CMumEngine *me = (CMumEngine *)mev;
    delete me;
}

EMumError MumPlaintextBlockSize(void *mev, uint32_t *plaintextBlockSize)
{
    CMumEngine *me = (CMumEngine *)mev;
    *plaintextBlockSize =  me->PlaintextBlockSize();
    return MUM_ERROR_OK;
}


EMumError MumEncryptedBlockSize(void *mev, uint32_t *encryptedBlockSize)
{
    CMumEngine *me = (CMumEngine *)mev;
    *encryptedBlockSize =  me->EncryptedBlockSize();
    return MUM_ERROR_OK;
}


EMumError MumInitKey(void *mev, uint8_t *key)
{
    CMumEngine *me = (CMumEngine *)mev;
    return me->InitKey(key);
}


EMumError MumLoadKey(void *mev, char *keyfile)
{
    CMumEngine *me = (CMumEngine *)mev;
    return me->LoadKey(keyfile);
}

EMumError MumEncryptFile(void *mev, char *srcfile, char *dstfile)
{
    CMumEngine *me = (CMumEngine *)mev;
    return me->EncryptFile(srcfile, dstfile);
}


EMumError MumDecryptFile(void *mev, char *srcfile, char *dstfile)
{
    CMumEngine *me = (CMumEngine *)mev;
    return me->DecryptFile(srcfile, dstfile);
}


EMumError MumEncrypt(void *mev, uint8_t *src, uint8_t *dst, uint32_t length, uint32_t *outlength, uint16_t seqNum)
{
    CMumEngine *me = (CMumEngine *)mev;
    return me->Encrypt(src, dst, length, outlength, seqNum);
}

EMumError MumDecrypt(void *mev, uint8_t *src, uint8_t *dst, uint32_t length, uint32_t *outlength)
{
    CMumEngine *me = (CMumEngine *)mev;
    return me->Decrypt(src, dst, length, outlength);
}


EMumError MumEncryptBlock(void *mev, uint8_t *src, uint8_t *dst, uint32_t length, uint32_t seqnum)
{
    CMumEngine *me = (CMumEngine *)mev;
    return me->EncryptBlock(src, dst, length, seqnum);
}

EMumError MumDecryptBlock(void *mev, uint8_t *src, uint8_t *dst, uint32_t *length, uint32_t *seqnum)
{
    CMumEngine *me = (CMumEngine *)mev;
    return me->DecryptBlock(src, dst, length, seqnum);
}

EMumError MumGetSubkey(void *mev, uint32_t index, uint8_t *subkey)
{
    CMumEngine *me = (CMumEngine *)mev;
    return me->GetSubkey(index, subkey);
}


void *MumCreateEngine(EMumEngineType engineType, EMumBlockType blockType, EMumPaddingType paddingType, uint32_t numThreads)
{
    if ( engineType < MUM_ENGINE_TYPE_CPU)
        return NULL;
#ifdef USE_MUM_OPENGL
    if ( engineType > MUM_ENGINE_TYPE_GPU_B)
        return NULL;
#else
    if ( engineType > MUM_ENGINE_TYPE_CPU)
        return NULL;
#endif
    CMumEngine *me = new CMumEngine(engineType, blockType, paddingType, numThreads);
    return me;
}


EMumError MumCreateEncryptedFileName(EMumBlockType blockType, char *infilename, char *outfilename, size_t outlength)
{
    sprintf_s(outfilename, outlength, "%s.mu%d",infilename, blockType);
    return MUM_ERROR_OK;
}

EMumError MumGetInfoFromEncryptedFileName(char *infilename, EMumBlockType *blockType, char *outfilename, size_t outlength)
{
    size_t len = strlen(infilename);
    if (len < 4)
        return MUM_ERROR_INVALID_FILE_EXTENSION;

    char ext[8];
    memcpy(ext, &infilename[len-4], 4);
    ext[4] = 0;

    if (!strcmp(ext, ".mu1"))
        *blockType = MUM_BLOCKTYPE_128;
    else if (!strcmp(ext, ".mu2"))
        *blockType = MUM_BLOCKTYPE_256;
    else if (!strcmp(ext, ".mu3"))
        *blockType = MUM_BLOCKTYPE_512;
    else if (!strcmp(ext, ".mu4"))
        *blockType = MUM_BLOCKTYPE_1024;
    else if (!strcmp(ext, ".mu5"))
        *blockType = MUM_BLOCKTYPE_2048;
    else if (!strcmp(ext, ".mu6"))
        *blockType = MUM_BLOCKTYPE_4096;
    else
        return MUM_ERROR_INVALID_FILE_EXTENSION;

    if (outlength < len - 3)
        return MUM_ERROR_LENGTH_TOO_SMALL;

    memcpy(outfilename, infilename, len-4);
    outfilename[len - 4] = 0;
    return MUM_ERROR_OK;
}



