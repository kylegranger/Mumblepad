//////////////////////////////////////////////////////////////////////////
//                                                                      //
//   GELB Cipher Engine                                                 //
//   Copyright 2013, Kyle Granger                                       //
//   Version 1, completed December 22, 2013                             //
//                                                                      //
//   GPU Encrypted Large Blocks                                         //
//   Encryption and decryption, runs on both CPU and GPU                //
//   Runs on GPU with OpenGL or OpenGL ES 2.0...........................//
//   8 rounds, 2 passes per round                                       //
//     Diffusion pass followed by confusion pass on encrypt.............//
//     Inverse confusion pass followed by inverse diffusion pass on ....//
//       decrypt.............                                           //
//   Block/key size 4096 bytes, 32768 bits                              //
//   Uses 4000 bytes plaintext per block                                //
//      Encrypted data 2.4% larger then plaintext                       //
//      No block cipher mode                                            //
//      Can use parallel processing, multi-threaded encrypt/decrypt     //
//      Data loss is allowed for audio/video communications             //
//                                                                      //
//   Free for individual use, as well as analysis/evaluation for        //
//     commercial use.                                                  //
//   For commerical license enquiries, please contact the author:       //
//         kyle.granger@chello.at                                       //
//                                                                      //
//////////////////////////////////////////////////////////////////////////

#ifndef __MUMBLEPADGLC_H
#define __MUMBLEPADGLC_H

#include "mumrenderer.h"

#ifdef USE_MUM_OPENGL

#include "mumglwrapper.h"


class CMumblepadGlc : public CMumRenderer 
{
public:
    CMumblepadGlc(TMumInfo *mumInfo, CMumGlWrapper *mumGlWrapper);
    ~CMumblepadGlc();
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
    uint8_t *mUploadBuffer;
    uint8_t *mDownloadBuffer;
    uint32_t mPrepOffset;
    uint32_t mUploadIter;
    uint32_t mDownloadIter;
    bool InitTextures();
    bool CreateLutTextures();
    bool CreateFrameBuffers();
    bool CreateShaders();
    void DeleteFrameBuffers();
    void DeleteLutTextures();
    void WriteTextures();
    void UploadPrep(uint8_t *data);
    void DownloadPrep(uint8_t *data);
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
