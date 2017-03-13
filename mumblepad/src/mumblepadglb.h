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


#ifndef __MUMBLEPADGLB_H
#define __MUMBLEPADGLB_H

#include "mumrenderer.h"

#ifdef USE_MUM_OPENGL

#include "mumglwrapper.h"


class CMumblepadGlb : public CMumRenderer 
{
public:
    CMumblepadGlb(TMumInfo *mumInfo, CMumGlWrapper *mumGlWrapper);
    ~CMumblepadGlb();
    virtual void EncryptDiffuse(uint32_t round);
    virtual void EncryptConfuse(uint32_t round);
    virtual void DecryptConfuse(uint32_t round);
    virtual void DecryptDiffuse(uint32_t round);
    virtual void EncryptUpload(uint8_t *data);
    virtual void EncryptDownload(uint8_t *data);
    virtual void DecryptUpload(uint8_t *data);
    virtual void DecryptDownload(uint8_t *data);
    virtual void InitKey();
private:
    TMumInfo *mMumInfo;
    CMumGlWrapper *mGlw;
    bool InitTextures();
    bool CreateLutTextures();
    bool CreateFrameBuffers();
    bool CreateShaders();
    void DeleteFrameBuffers();
    void DeleteLutTextures();
    void WriteTextures();
    GLuint CreateShader(const char *vertShaderSrc, const char *fragShaderSrc);

    uint32_t mEncryptDiffuseProgram;
    uint32_t mEncryptConfuseProgram;
    uint32_t mDecryptDiffuseProgram;
    uint32_t mDecryptConfuseProgram;

    // textures
    GLuint mLutTextureKey;
    GLuint mLutTextureKeyI;
    GLuint mLutTexturePermute;
    GLuint mLutTexturePermuteI;
    GLuint mLutTextureXor;
    GLuint mLutTextureBitmask;
    GLuint mLutTextureBitmaskI;
    GLuint mPingPongTexture[2];
    GLuint mPingPongFBuffer[2];
    GLuint mPositionTexturesX;
    GLuint mPositionTexturesY;
    GLuint mPositionTexturesXI;
    GLuint mPositionTexturesYI;

};

#endif

#endif
