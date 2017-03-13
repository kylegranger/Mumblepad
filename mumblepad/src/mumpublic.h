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


#ifndef MUMPUBLIC_H
#define MUMPUBLIC_H

#include "mumtypes.h"

#define USE_MUM_OPENGL

#define MUM_KEY_SIZE          4096
#define MUM_NUM_SUBKEYS        560
#define MUM_PRNG_SUBKEY_INDEX  304


typedef enum EMumEngineType {
    MUM_ENGINE_TYPE_NONE   = -1,
    MUM_ENGINE_TYPE_CPU       = 100,
    MUM_ENGINE_TYPE_CPU_MT = 101,
    MUM_ENGINE_TYPE_GPU_A  = 102,
    MUM_ENGINE_TYPE_GPU_B  = 103,
} EMumEngineType;

typedef enum EMumError {
    MUM_ERROR_OK = 0,
    MUM_ERROR_FILEIO_INPUT = -1001,
    MUM_ERROR_FILEIO_OUTPUT = -1002,
    MUM_ERROR_INVALID_ENCRYPT_SIZE = -1003,
    MUM_ERROR_INVALID_DECRYPT_SIZE = -1004,
    MUM_ERROR_INVALID_ENCRYPTED_BLOCK = -1005,
    MUM_ERROR_INVALID_BLOCK_SIZE = -1006,
    MUM_ERROR_INVALID_MAX_ENCRYPT_SIZE = -1007,
    MUM_ERROR_BUFFER_WAIT_ENCRYPT = -1008,
    MUM_ERROR_BUFFER_WAIT_DECRYPT = -1009,
    MUM_ERROR_RENDERER_NOT_MULTITHREADED = -1010,
    MUM_ERROR_MTRENDERER_NO_THREADS = -1011,
    MUM_ERROR_KEYFILE_READ = -1012,
    MUM_ERROR_KEYFILE_WRITE = -1013,
    MUM_ERROR_INVALID_FILE_EXTENSION = -1014,
    MUM_ERROR_SUBKEY_INDEX_OUTOFRANGE = -1015,
    MUM_ERROR_KEY_NOT_INITIALIZED = -1016,
    MUM_ERROR_LENGTH_TOO_SMALL = -1017,
} EMumError;

typedef enum EMumBlockType {
    // maximum encrypt size is 112 bytes
    MUM_BLOCKTYPE_128 = 1,
    // maximum encrypt size is 240 bytes
    MUM_BLOCKTYPE_256 = 2,
    // maximum encrypt size is 496 bytes
    MUM_BLOCKTYPE_512 = 3,
    // maximum encrypt size is 1000 bytes
    MUM_BLOCKTYPE_1024 = 4,
    // maximum encrypt size is 2000 bytes
    MUM_BLOCKTYPE_2048 = 5,
    // maximum encrypt size is 4000 bytes
    MUM_BLOCKTYPE_4096 = 6
} EMumBlockType;

typedef enum EMumPaddingType {
    // maximum encrypt size is 112 bytes
    MUM_PADDING_TYPE_OFF = 0,
    // maximum encrypt size is 240 bytes
    MUM_PADDING_TYPE_ON = 1,
} EMumPaddingType;


extern void * MumCreateEngine(EMumEngineType engineType, EMumBlockType blockType, EMumPaddingType paddingType, uint32_t numThreads);
extern void MumDestroyEngine(void *me);
extern EMumError MumInitKey(void *me, uint8_t *key);
extern EMumError MumGetSubkey(void *me, uint32_t index, uint8_t *subkey);
extern EMumError MumLoadKey(void *me, char *keyfile);
extern EMumError MumEncryptBlock(void *me, uint8_t *src, uint8_t *dst, uint32_t length, uint32_t seqnum);
extern EMumError MumDecryptBlock(void *me, uint8_t *src, uint8_t *dst, uint32_t *length, uint32_t *seqnum);
extern EMumError MumEncrypt(void *me, uint8_t *src, uint8_t *dst, uint32_t length, uint32_t *outlength, uint16_t seqNum);
extern EMumError MumDecrypt(void *me, uint8_t *src, uint8_t *dst, uint32_t length, uint32_t *outlength);
extern EMumError MumEncryptFile(void *me, char *srcfile, char *dstfile);
extern EMumError MumDecryptFile(void *me, char *srcfile, char *dstfile);
extern EMumError MumPlaintextBlockSize(void *me, uint32_t *plaintextBlockSize);
extern EMumError MumEncryptedBlockSize(void *me, uint32_t *encryptedBlockSize);
extern EMumError MumEncryptedSize(void *me, uint32_t plaintextSize, uint32_t *encryptedSize);
// adds a file extension to a file based, based on the block size/type:
// .mu1 = 128-byte block
// .mu2 = 256-byte block
// .mu3 = 512-byte block
// .mu4 = 1024-byte block
// .mu5 = 2048-byte block
// .mu6 = 4096-byte block
extern EMumError MumCreateEncryptedFileName(EMumBlockType blockType, char *infilename, char *outfilename, size_t outlength);
// returns original filename (stripped of Mumblepad extension), plus block type used.
extern EMumError MumGetInfoFromEncryptedFileName(char *infilename, EMumBlockType *blockType, char *outfilename, size_t outlength);

#endif

