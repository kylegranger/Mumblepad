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

#include "stdio.h"
#include "malloc.h"
#include "assert.h"
#include "mumblepadglc.h"

#ifdef USE_MUM_OPENGL

static float wholeSquareVertices[] = {
    -1.0f,  1.0f, 0.0f,
    -1.0f, -1.0f, 0.0f,
     1.0f, -1.0f, 0.0f,
     1.0f,  1.0f, 0.0f,
};

static float wholeSquareUv[] = {
     0.0f,  1.0f,
     0.0f,  0.0f,
     1.0f,  0.0f,
     1.0f,  1.0f
};

static float wholeSquareUvOffset[] = {
     0.0f,   0.875f,
     0.0f,  -0.125f,
     1.0f,  -0.125f,
     1.0f,   0.875f
};


static unsigned short wholeSquareIndices[] = { 0, 1, 2, 0, 2, 3 };



static char *vertexShaderText = 
"attribute vec4 a_position;   \n"
"attribute vec2 a_texCoord;   \n"
"varying vec2 v_texCoord;     \n"
"void main()                  \n"
"{                            \n"
"   gl_Position = a_position; \n"
"   v_texCoord = a_texCoord;  \n"
"}                            \n";


static char *nullShaderText = 
"precision mediump float;\n\
varying vec2 v_texCoord;\n\
uniform sampler2D source;\n\
void main(void)\n\
{\n\
    gl_FragColor  = texture2D(source, v_texCoord);\n\
}";


static char *encryptDiffuseText = 
"precision mediump float;\n\
varying vec2 v_texCoord;\n\
uniform sampler2D source;\n\
uniform sampler2D bitmasks;\n\
uniform sampler2D positionX;\n\
uniform sampler2D positionY;\n\
void main(void)\n\
{\n\
    float column = floor((v_texCoord[0] + 0.001) * 16.0);\n\
    vec4 posX  = texture2D(positionX, v_texCoord)/16.0+column/16.0 + 0.001;\n\
    vec4 posY  = texture2D(positionY, v_texCoord);\n\
    vec4 src1  = texture2D(source, vec2(posX[0],posY[0]));\n\
    vec4 src2  = texture2D(source, vec2(posX[1],posY[1]));\n\
    vec4 src3  = texture2D(source, vec2(posX[2],posY[2]));\n\
    vec4 src4  = texture2D(source, vec2(posX[3],posY[3]));\n\
    float round = floor((v_texCoord[1]) * 8.0);\n\
    float offset = round/8.0 + 0.015625;\n\
    gl_FragColor[0] = texture2D(bitmasks,vec2(src1[0],offset))[0] + \
        texture2D(bitmasks,vec2(src2[2],offset+0.03125))[0] + \
        texture2D(bitmasks,vec2(src3[3],offset+0.0625))[0] + \
        texture2D(bitmasks,vec2(src4[1],offset+0.09375))[0];\n\
    gl_FragColor[1] = texture2D(bitmasks,vec2(src1[2],offset))[0] + \
        texture2D(bitmasks,vec2(src2[3],offset+0.03125))[0] + \
        texture2D(bitmasks,vec2(src3[1],offset+0.0625))[0] + \
        texture2D(bitmasks,vec2(src4[0],offset+0.09375))[0];\n\
    gl_FragColor[2] = texture2D(bitmasks,vec2(src1[3],offset))[0] + \
        texture2D(bitmasks,vec2(src2[1],offset+0.03125))[0] + \
        texture2D(bitmasks,vec2(src3[0],offset+0.0625))[0] + \
        texture2D(bitmasks,vec2(src4[2],offset+0.09375))[0];\n\
    gl_FragColor[3] = texture2D(bitmasks,vec2(src1[1],offset))[0] + \
        texture2D(bitmasks,vec2(src2[0],offset+0.03125))[0] + \
        texture2D(bitmasks,vec2(src3[2],offset+0.0625))[0] + \
        texture2D(bitmasks,vec2(src4[3],offset+0.09375))[0];\n\
}";



static char *encryptConfuseText = 
"precision mediump float;\n\
varying vec2 v_texCoord;\n\
uniform sampler2D source;\n\
uniform sampler2D lutKey;\n\
uniform sampler2D lutXor;\n\
uniform sampler2D lutPermute;\n\
void main(void)\n\
{\n\
    vec4 clav = texture2D(lutKey, v_texCoord);\n\
    vec4 src  = texture2D(source, v_texCoord);\n\
    vec4 xorKey;\n\
    xorKey[0] = texture2D(lutXor,vec2(src.r,clav.r))[0];\n\
    xorKey[1] = texture2D(lutXor,vec2(src.g,clav.g))[0];\n\
    xorKey[2] = texture2D(lutXor,vec2(src.b,clav.b))[0];\n\
    xorKey[3] = texture2D(lutXor,vec2(src.a,clav.a))[0];\n\
    gl_FragColor[0] = texture2D(lutPermute,vec2(xorKey[0],v_texCoord[1]))[0];\n\
    gl_FragColor[1] = texture2D(lutPermute,vec2(xorKey[1],v_texCoord[1]))[0];\n\
    gl_FragColor[2] = texture2D(lutPermute,vec2(xorKey[2],v_texCoord[1]))[0];\n\
    gl_FragColor[3] = texture2D(lutPermute,vec2(xorKey[3],v_texCoord[1]))[0];\n\
}";




static char *decryptDiffuseText = 
"precision mediump float;\n\
varying vec2 v_texCoord;\n\
uniform sampler2D source;\n\
uniform sampler2D bitmasks;\n\
uniform sampler2D positionX;\n\
uniform sampler2D positionY;\n\
void main(void)\n\
{\n\
    vec4 posX  = texture2D(positionX, v_texCoord);\n\
    vec4 posY  = texture2D(positionY, v_texCoord);\n\
    vec4 src1  = texture2D(source, vec2(posX[0],posY[0]));\n\
    vec4 src2  = texture2D(source, vec2(posX[1],posY[1]));\n\
    vec4 src3  = texture2D(source, vec2(posX[2],posY[2]));\n\
    vec4 src4  = texture2D(source, vec2(posX[3],posY[3]));\n\
    float round = floor((v_texCoord[1]) * 8.0);\n\
    float offset = round/8.0 + 0.015625;\n\
    gl_FragColor[0] = texture2D(bitmasks,vec2(src1[0],offset))[0] + \
        texture2D(bitmasks,vec2(src2[3],offset+0.03125))[0] + \
        texture2D(bitmasks,vec2(src3[2],offset+0.0625))[0] + \
        texture2D(bitmasks,vec2(src4[1],offset+0.09375))[0];\n\
    gl_FragColor[1] = texture2D(bitmasks,vec2(src1[3],offset))[0] + \
        texture2D(bitmasks,vec2(src2[2],offset+0.03125))[0] + \
        texture2D(bitmasks,vec2(src3[1],offset+0.0625))[0] + \
        texture2D(bitmasks,vec2(src4[0],offset+0.09375))[0];\n\
    gl_FragColor[2] = texture2D(bitmasks,vec2(src1[1],offset))[0] + \
        texture2D(bitmasks,vec2(src2[0],offset+0.031255))[0] + \
        texture2D(bitmasks,vec2(src3[3],offset+0.0625))[0] + \
        texture2D(bitmasks,vec2(src4[2],offset+0.09375))[0];\n\
    gl_FragColor[3] = texture2D(bitmasks,vec2(src1[2],offset))[0] + \
        texture2D(bitmasks,vec2(src2[1],offset+0.03125))[0] + \
        texture2D(bitmasks,vec2(src3[0],offset+0.0625))[0] + \
        texture2D(bitmasks,vec2(src4[3],offset+0.09375))[0];\n\
}";



static char *decryptConfuseText = 
"precision mediump float;\n\
varying vec2 v_texCoord;\n\
uniform sampler2D source;\n\
uniform sampler2D lutKey;\n\
uniform sampler2D lutXor;\n\
uniform sampler2D lutPermute;\n\
void main(void)\n\
{\n\
    vec4 clav = texture2D(lutKey, v_texCoord);\n\
    vec4 src  = texture2D(source, v_texCoord);\n\
    vec4 prm;\n\
    prm[0] = texture2D(lutPermute,vec2(src[0],v_texCoord[1]))[0];\n\
    prm[1] = texture2D(lutPermute,vec2(src[1],v_texCoord[1]))[0];\n\
    prm[2] = texture2D(lutPermute,vec2(src[2],v_texCoord[1]))[0];\n\
    prm[3] = texture2D(lutPermute,vec2(src[3],v_texCoord[1]))[0];\n\
    gl_FragColor[0] = texture2D(lutXor,vec2(prm.r,clav.r))[0];\n\
    gl_FragColor[1] = texture2D(lutXor,vec2(prm.g,clav.g))[0];\n\
    gl_FragColor[2] = texture2D(lutXor,vec2(prm.b,clav.b))[0];\n\
    gl_FragColor[3] = texture2D(lutXor,vec2(prm.a,clav.a))[0];\n\
}";



CMumblepadGlc::CMumblepadGlc(TMumInfo *mumInfo, CMumGlWrapper *gelbGlWrapper) : CMumRenderer(mumInfo)
{
    mMumInfo = mumInfo;
    mGlw = gelbGlWrapper;
    mEncryptDiffuseProgram = -1;
    mEncryptConfuseProgram = -1;
    mDecryptDiffuseProgram = -1;
    mDecryptConfuseProgram = -1;

    mPingPongTexture[0] = -1;
    mPingPongFBuffer[0] = -1;
    mPingPongTexture[1] = -1;
    mPingPongFBuffer[1] = -1;

    mLutTextureKey = -1;
    mLutTextureKeyI = -1;
    mLutTextureXor = -1;
    if ( !InitTextures() )
        assert(0);

    uint32_t size = MUM_CELLS_X * MUM_GPUC_SCALE * MUM_CELLS_MAX_Y * 4;
    mUploadBuffer = new uint8_t[size];
    mDownloadBuffer = new uint8_t[size];
    mPrepOffset = MUM_CELLS_X * 4 * (mMumInfo->horizontalScaling - 1);
    mUploadIter = 0;
    mDownloadIter = 0;

}



void CMumblepadGlc::DeleteFrameBuffers()
{
    glDeleteTextures(2, mPingPongTexture);
    mGlw->glDeleteFramebuffers(2, mPingPongFBuffer);
}

void CMumblepadGlc::DeleteLutTextures()
{
    glDeleteTextures(1,&mLutTextureKey);
    glDeleteTextures(1,&mLutTextureKeyI);
    glDeleteTextures(1,&mLutTextureXor);

    glDeleteTextures(1,&mLutTextureBitmask);
    glDeleteTextures(1,&mLutTextureBitmaskI);
    glDeleteTextures(1,&mPositionTexturesX);
    glDeleteTextures(1,&mPositionTexturesY);
    glDeleteTextures(1,&mPositionTexturesXI);
    glDeleteTextures(1,&mPositionTexturesYI);
    glDeleteTextures(1,&mLutTexturePermute);
    glDeleteTextures(1,&mLutTexturePermuteI);
}

CMumblepadGlc::~CMumblepadGlc()
{
    mGlw->glDeleteProgram(mEncryptDiffuseProgram); 
    mGlw->glDeleteProgram(mEncryptConfuseProgram); 
    mGlw->glDeleteProgram(mDecryptDiffuseProgram); 
    mGlw->glDeleteProgram(mDecryptConfuseProgram); 
    DeleteFrameBuffers();
    DeleteLutTextures();
}

void CMumblepadGlc::UploadPrep(uint8_t *data)
{
    uint8_t *src = data;
    uint8_t *dst = mUploadBuffer + mUploadIter*MUM_CELLS_X*4;
    for (int y = 0; y < MUM_CELLS_MAX_Y; y++)
    {
        memcpy(dst, data, MUM_CELLS_X * 4);
        src += MUM_CELLS_X * 4;
        dst += mPrepOffset;
    }

    mUploadIter++;
}

void CMumblepadGlc::DownloadPrep(uint8_t *data)
{
    uint8_t *src = mDownloadBuffer + mDownloadIter*MUM_CELLS_X*4;
    uint8_t *dst = data;
    for (int y = 0; y < MUM_CELLS_MAX_Y; y++)
    {
        memcpy(dst, src, MUM_CELLS_X * 4);
        dst += MUM_CELLS_X * 4;
        src += mPrepOffset;
    }
    mDownloadIter++;
}

void CMumblepadGlc::EncryptUpload(uint8_t *data)
{
    UploadPrep(data);
    if (mUploadIter == mMumInfo->horizontalScaling)
    {
        mUploadIter = 0;
        mGlw->glBindTexture(GL_TEXTURE_2D, mPingPongTexture[0]);
        mGlw->glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, MUM_CELLS_X*mMumInfo->horizontalScaling,
            MUM_CELLS_MAX_Y, GL_RGBA, GL_UNSIGNED_BYTE, mUploadBuffer);
    }
}

void CMumblepadGlc::DecryptUpload(uint8_t *data)
{
    UploadPrep(data);
    if (mUploadIter == mMumInfo->horizontalScaling)
    {
        mUploadIter = 0;
        glBindTexture(GL_TEXTURE_2D, mPingPongTexture[0]);
        glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 7 * MUM_CELLS_MAX_Y, MUM_CELLS_X*mMumInfo->horizontalScaling,
            MUM_CELLS_MAX_Y, GL_RGBA, GL_UNSIGNED_BYTE, mUploadBuffer);
    }
}

bool CMumblepadGlc::CreateFrameBuffers()
{
    GLenum result;
    mGlw->glGenTextures(2, mPingPongTexture);
    mGlw->glGenFramebuffers(2, mPingPongFBuffer);

    uint32_t size = MUM_CELLS_X * MUM_GPUC_SCALE * MUM_CELLS_YB * 4;
    uint8_t *black = new uint8_t[size];
    memset(black, 0, size);
    mGlw->glBindTexture(GL_TEXTURE_2D, mPingPongTexture[0]);
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_REPEAT );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_REPEAT );
    mGlw->glTexImage2D( GL_TEXTURE_2D, 0, GL_RGBA, MUM_CELLS_X*MUM_GPUC_SCALE, MUM_CELLS_YB,
        0, GL_RGBA, GL_UNSIGNED_BYTE, black);
    mGlw->glBindFramebuffer(GL_FRAMEBUFFER, mPingPongFBuffer[0]);
    mGlw->glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, mPingPongTexture[0], 0);

    result = mGlw->glCheckFramebufferStatus(GL_FRAMEBUFFER);
    if (result != GL_FRAMEBUFFER_COMPLETE)
        return false;

    mGlw->glBindTexture(GL_TEXTURE_2D, mPingPongTexture[1]);
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_REPEAT );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_REPEAT );
    mGlw->glTexImage2D( GL_TEXTURE_2D, 0, GL_RGBA, MUM_CELLS_X*MUM_GPUC_SCALE, MUM_CELLS_YB,
        0, GL_RGBA, GL_UNSIGNED_BYTE, black);
    mGlw->glBindFramebuffer(GL_FRAMEBUFFER, mPingPongFBuffer[1]);
    mGlw->glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, mPingPongTexture[1], 0);
    delete[] black;
    result = mGlw->glCheckFramebufferStatus(GL_FRAMEBUFFER);
    if (result != GL_FRAMEBUFFER_COMPLETE)
        return false;
    mGlw->glBindFramebuffer(GL_FRAMEBUFFER, 0);
    return true;
}

bool CMumblepadGlc::CreateLutTextures()
{
    mGlw->glGenTextures(1,&mLutTextureKey);
    mGlw->glBindTexture( GL_TEXTURE_2D, mLutTextureKey );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_REPEAT );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_REPEAT );
    mGlw->glTexImage2D( GL_TEXTURE_2D, 0, GL_RGBA, MUM_CELLS_X, MUM_CELLS_YB,
        0, GL_RGBA, GL_UNSIGNED_BYTE, NULL );

    mGlw->glGenTextures(1,&mLutTextureKeyI);
    mGlw->glBindTexture( GL_TEXTURE_2D, mLutTextureKeyI );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_REPEAT );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_REPEAT );
    mGlw->glTexImage2D( GL_TEXTURE_2D, 0, GL_RGBA, MUM_CELLS_X, MUM_CELLS_YB,
        0, GL_RGBA, GL_UNSIGNED_BYTE, NULL );

    mGlw->glGenTextures(1,&mLutTextureXor);
    mGlw->glBindTexture( GL_TEXTURE_2D, mLutTextureXor );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE );
    mGlw->glTexImage2D( GL_TEXTURE_2D, 0, GL_LUMINANCE, MUM_NUM_8BIT_VALUES, MUM_NUM_8BIT_VALUES, 0, GL_LUMINANCE, 
        GL_UNSIGNED_BYTE, mMumInfo->xorTextureData );

    mGlw->glGenTextures(1,&mLutTextureBitmask);
    mGlw->glBindTexture( GL_TEXTURE_2D, mLutTextureBitmask );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_REPEAT ); 
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_REPEAT ); 
    mGlw->glTexImage2D( GL_TEXTURE_2D, 0, GL_LUMINANCE, MUM_NUM_8BIT_VALUES, MUM_MASK_TABLE_ROWS*MUM_NUM_ROUNDS, 0, GL_LUMINANCE, 
        GL_UNSIGNED_BYTE, NULL );

    mGlw->glGenTextures(1,&mLutTextureBitmaskI);
    mGlw->glBindTexture( GL_TEXTURE_2D, mLutTextureBitmaskI );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_REPEAT ); 
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_REPEAT ); 
    mGlw->glTexImage2D( GL_TEXTURE_2D, 0, GL_LUMINANCE, MUM_NUM_8BIT_VALUES, MUM_MASK_TABLE_ROWS*MUM_NUM_ROUNDS, 0, GL_LUMINANCE, 
        GL_UNSIGNED_BYTE, NULL );

    mGlw->glGenTextures(1,&mPositionTexturesX);
    mGlw->glBindTexture( GL_TEXTURE_2D, mPositionTexturesX );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE ); 
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE ); 
    mGlw->glTexImage2D( GL_TEXTURE_2D, 0, GL_RGBA, MUM_CELLS_X, MUM_CELLS_YB, 0, GL_RGBA,
        GL_UNSIGNED_BYTE, NULL );

    mGlw->glGenTextures(1,&mPositionTexturesY);
    mGlw->glBindTexture( GL_TEXTURE_2D, mPositionTexturesY );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE ); 
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE ); 
    mGlw->glTexImage2D( GL_TEXTURE_2D, 0, GL_RGBA, MUM_CELLS_X, MUM_CELLS_YB, 0, GL_RGBA,
        GL_UNSIGNED_BYTE, NULL );

    mGlw->glGenTextures(1,&mPositionTexturesXI);
    mGlw->glBindTexture( GL_TEXTURE_2D, mPositionTexturesXI );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE ); 
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE ); 
    mGlw->glTexImage2D( GL_TEXTURE_2D, 0, GL_RGBA, MUM_CELLS_X, MUM_CELLS_YB, 0, GL_RGBA,
        GL_UNSIGNED_BYTE, NULL );

    mGlw->glGenTextures(1,&mPositionTexturesYI);
    mGlw->glBindTexture( GL_TEXTURE_2D, mPositionTexturesYI );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE ); 
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE ); 
    mGlw->glTexImage2D( GL_TEXTURE_2D, 0, GL_RGBA, MUM_CELLS_X, MUM_CELLS_YB, 0, GL_RGBA,
        GL_UNSIGNED_BYTE, NULL );

    mGlw->glGenTextures(1,&mLutTexturePermute);
    mGlw->glBindTexture( GL_TEXTURE_2D, mLutTexturePermute );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_REPEAT ); 
    mGlw->glTexImage2D( GL_TEXTURE_2D, 0, GL_LUMINANCE, MUM_NUM_8BIT_VALUES, MUM_CELLS_YB, 0, GL_LUMINANCE, 
        GL_UNSIGNED_BYTE, NULL );

    mGlw->glGenTextures(1,&mLutTexturePermuteI);
    mGlw->glBindTexture( GL_TEXTURE_2D, mLutTexturePermuteI );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_REPEAT ); 
    mGlw->glTexImage2D( GL_TEXTURE_2D, 0, GL_LUMINANCE, MUM_NUM_8BIT_VALUES, MUM_CELLS_YB, 0, GL_LUMINANCE, 
        GL_UNSIGNED_BYTE, NULL );
    return true;
}

void CMumblepadGlc::InitKey()
{
    WriteTextures();
    mPrng = new CMumPrng(mMumInfo->subkeys[0], 0);
}

void CMumblepadGlc::WriteTextures()
{
    uint32_t indicesB[8] = { 6, 5, 4, 3, 2, 1, 0, 7 };

    for ( int r = 0; r < MUM_NUM_ROUNDS; r++ )
    {
        mGlw->glBindTexture( GL_TEXTURE_2D, mLutTextureKey );
        mGlw->glTexSubImage2D(GL_TEXTURE_2D, 0, 0, r*MUM_CELLS_MAX_Y, MUM_CELLS_X,
            MUM_CELLS_MAX_Y, GL_RGBA, GL_UNSIGNED_BYTE, mMumInfo->subkeys[r]);

        mGlw->glBindTexture( GL_TEXTURE_2D, mLutTextureKeyI );
        mGlw->glTexSubImage2D(GL_TEXTURE_2D, 0, 0, r*MUM_CELLS_MAX_Y, MUM_CELLS_X,
            MUM_CELLS_MAX_Y, GL_RGBA, GL_UNSIGNED_BYTE, mMumInfo->subkeys[indicesB[r]]);

        mGlw->glBindTexture( GL_TEXTURE_2D, mLutTexturePermute );
        mGlw->glTexSubImage2D(GL_TEXTURE_2D, 0, 0, r*MUM_CELLS_MAX_Y, MUM_NUM_8BIT_VALUES,
            MUM_CELLS_MAX_Y, GL_LUMINANCE, GL_UNSIGNED_BYTE, mMumInfo->permuteTextureData[r]);

        mGlw->glBindTexture( GL_TEXTURE_2D, mLutTexturePermuteI );
        mGlw->glTexSubImage2D(GL_TEXTURE_2D, 0, 0, r*MUM_CELLS_MAX_Y, MUM_NUM_8BIT_VALUES,
            MUM_CELLS_MAX_Y, GL_LUMINANCE, GL_UNSIGNED_BYTE, mMumInfo->permuteTextureDataI[indicesB[r]]);

        mGlw->glBindTexture( GL_TEXTURE_2D, mLutTextureBitmask );
        mGlw->glTexSubImage2D(GL_TEXTURE_2D, 0, 0, r*MUM_CELLS_MAX_Y, MUM_NUM_8BIT_VALUES,
            MUM_CELLS_MAX_Y, GL_LUMINANCE, GL_UNSIGNED_BYTE, mMumInfo->bitmaskTextureData[r]);

        mGlw->glBindTexture( GL_TEXTURE_2D, mLutTextureBitmaskI );
        mGlw->glTexSubImage2D(GL_TEXTURE_2D, 0, 0, (7-r)*MUM_CELLS_MAX_Y, MUM_NUM_8BIT_VALUES,
            MUM_CELLS_MAX_Y, GL_LUMINANCE, GL_UNSIGNED_BYTE, mMumInfo->bitmaskTextureData[r]);

        mGlw->glBindTexture( GL_TEXTURE_2D, mPositionTexturesX );
        mGlw->glTexSubImage2D(GL_TEXTURE_2D, 0, 0, r*MUM_CELLS_MAX_Y, MUM_CELLS_X,
            MUM_CELLS_MAX_Y, GL_RGBA, GL_UNSIGNED_BYTE, mMumInfo->positionTextureDataX[r]);

        mGlw->glBindTexture( GL_TEXTURE_2D, mPositionTexturesY );
        mGlw->glTexSubImage2D(GL_TEXTURE_2D, 0, 0, r*MUM_CELLS_MAX_Y, MUM_CELLS_X,
            MUM_CELLS_MAX_Y, GL_RGBA, GL_UNSIGNED_BYTE, mMumInfo->positionTextureDataYB[r]);

        mGlw->glBindTexture( GL_TEXTURE_2D, mPositionTexturesXI );
        mGlw->glTexSubImage2D(GL_TEXTURE_2D, 0, 0, (7-r)*MUM_CELLS_MAX_Y, MUM_CELLS_X,
            MUM_CELLS_MAX_Y, GL_RGBA, GL_UNSIGNED_BYTE, mMumInfo->positionTextureDataXI[r]);

        mGlw->glBindTexture( GL_TEXTURE_2D, mPositionTexturesYI );
        mGlw->glTexSubImage2D(GL_TEXTURE_2D, 0, 0, (7-r)*MUM_CELLS_MAX_Y, MUM_CELLS_X,
            MUM_CELLS_MAX_Y, GL_RGBA, GL_UNSIGNED_BYTE, mMumInfo->positionTextureDataYIB[r]);

    }
}

GLuint CMumblepadGlc::CreateShader(const char *vertShaderSrc, const char *fragShaderSrc)
{
    GLuint vertexShader;
    GLuint fragmentShader;
    GLuint programObject;
    GLint linked;

    vertexShader = mGlw->LoadShader ( GL_VERTEX_SHADER, vertShaderSrc );
    if ( vertexShader == 0 )
    {
        assert(0);
        return 0;
    }

    fragmentShader = mGlw->LoadShader ( GL_FRAGMENT_SHADER, fragShaderSrc );
    if ( fragmentShader == 0 )
    {
        mGlw->glDeleteShader( vertexShader );
        assert(0);
        return 0;
    }

    programObject = mGlw->glCreateProgram ( );
    if ( programObject == 0 )
    {
        assert(0);
        return 0;
    }

    mGlw->glAttachShader ( programObject, vertexShader );
    mGlw->glAttachShader ( programObject, fragmentShader );

    // Link the program
    mGlw->glLinkProgram ( programObject );

    // Check the link status
    mGlw->glGetProgramiv ( programObject, GL_LINK_STATUS, &linked );

    if ( !linked ) 
    {
        GLint infoLen = 0;
        mGlw->glGetProgramiv ( programObject, GL_INFO_LOG_LENGTH, &infoLen );
        if ( infoLen > 1 )
        {
            char* infoLog = (char* ) malloc (sizeof(char) * infoLen );
            mGlw->glGetProgramInfoLog ( programObject, infoLen, NULL, infoLog );
            free ( infoLog );
        }
        mGlw->glDeleteProgram ( programObject );
        return 0;
    }

    mGlw->glDeleteShader ( vertexShader );
    mGlw->glDeleteShader ( fragmentShader );

    return programObject;
}

bool CMumblepadGlc::CreateShaders()
{
    mEncryptDiffuseProgram = CreateShader(vertexShaderText,encryptDiffuseText); 
    mEncryptConfuseProgram = CreateShader(vertexShaderText,encryptConfuseText); 
    mDecryptDiffuseProgram = CreateShader(vertexShaderText,decryptDiffuseText); 
    mDecryptConfuseProgram = CreateShader(vertexShaderText,decryptConfuseText); 
    return 1;
}

bool CMumblepadGlc::InitTextures()
{
    mGlw->glEnable(GL_TEXTURE_2D);
    mGlw->glDisable(GL_BLEND);
    mGlw->glDisable(GL_DEPTH_TEST);

    if ( !CreateLutTextures() )
        return false;
    if ( !CreateFrameBuffers() )
        return false;
    if ( !CreateShaders() )
        return false;
    return true;
}

void CMumblepadGlc::EncryptDiffuse(uint32_t /*round*/)
{
    uint32_t location;
    uint32_t positionLoc;
    uint32_t texCoordLoc;

    // first pass for encrypt
    // destination is ping pong 1
    mGlw->glBindFramebuffer(GL_FRAMEBUFFER, mPingPongFBuffer[1]);
    mGlw->glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, mPingPongTexture[1], 0);
    mGlw->glViewport(0,0,MUM_CELLS_X*MUM_GPUC_SCALE,MUM_CELLS_YB);

    mGlw->glUseProgram ( mEncryptDiffuseProgram );
    location = mGlw->glGetUniformLocation ( mEncryptDiffuseProgram, "source" );
    mGlw->glUniform1i ( location, 0 );
    location = mGlw->glGetUniformLocation ( mEncryptDiffuseProgram, "bitmasks" );
    mGlw->glUniform1i ( location, 1 );
    location = mGlw->glGetUniformLocation ( mEncryptDiffuseProgram, "positionX" );
    mGlw->glUniform1i ( location, 2 );
    location = mGlw->glGetUniformLocation ( mEncryptDiffuseProgram, "positionY" );
    mGlw->glUniform1i ( location, 3 );

    // precompute!
    positionLoc = mGlw->glGetAttribLocation ( mEncryptDiffuseProgram, "a_position" );
    texCoordLoc = mGlw->glGetAttribLocation ( mEncryptDiffuseProgram, "a_texCoord" );

    mGlw->glVertexAttribPointer ( positionLoc, 3, GL_FLOAT, 
        GL_FALSE, 3 * sizeof(GLfloat), wholeSquareVertices );
    mGlw->glVertexAttribPointer ( texCoordLoc, 2, GL_FLOAT,
        GL_FALSE, 2 * sizeof(GLfloat), wholeSquareUv );
    mGlw->glEnableVertexAttribArray ( 0 );
    mGlw->glEnableVertexAttribArray ( 1 );

    mGlw->glActiveTexture(GL_TEXTURE0);
    // source is ping pong 0
    mGlw->glBindTexture( GL_TEXTURE_2D, mPingPongTexture[0] );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE );

    mGlw->glActiveTexture(GL_TEXTURE1);
    mGlw->glBindTexture( GL_TEXTURE_2D, mLutTextureBitmask );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE );

    mGlw->glActiveTexture(GL_TEXTURE2);
    mGlw->glBindTexture( GL_TEXTURE_2D, mPositionTexturesX );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE );

    mGlw->glActiveTexture(GL_TEXTURE3);
    mGlw->glBindTexture( GL_TEXTURE_2D, mPositionTexturesY );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE );

    mGlw->glDrawElements ( GL_TRIANGLES, 6, GL_UNSIGNED_SHORT, wholeSquareIndices );
    mGlw->glBindFramebuffer(GL_FRAMEBUFFER, 0);
}

void CMumblepadGlc::EncryptConfuse(uint32_t /*round*/)
{
    uint32_t location;
    uint32_t positionLoc;
    uint32_t texCoordLoc;

    // destination is ping pong 0
    mGlw->glBindFramebuffer(GL_FRAMEBUFFER, mPingPongFBuffer[0]);
    mGlw->glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, mPingPongTexture[0], 0);
    mGlw->glViewport(0,0,MUM_CELLS_X*MUM_GPUC_SCALE,MUM_CELLS_YB);

    mGlw->glUseProgram ( mEncryptConfuseProgram );
    location = mGlw->glGetUniformLocation ( mEncryptConfuseProgram, "source" );
    mGlw->glUniform1i ( location, 0 );
    location = mGlw->glGetUniformLocation ( mEncryptConfuseProgram, "lutKey" );
    mGlw->glUniform1i ( location, 1 );
    location = mGlw->glGetUniformLocation ( mEncryptConfuseProgram, "lutXor" );
    mGlw->glUniform1i ( location, 2 );
    location = mGlw->glGetUniformLocation ( mEncryptConfuseProgram, "lutPermute" );
    mGlw->glUniform1i ( location, 3 );

    // precompute!
    positionLoc = mGlw->glGetAttribLocation ( mEncryptConfuseProgram, "a_position" );
    texCoordLoc = mGlw->glGetAttribLocation ( mEncryptConfuseProgram, "a_texCoord" );

    mGlw->glVertexAttribPointer ( positionLoc, 3, GL_FLOAT, 
        GL_FALSE, 3 * sizeof(GLfloat), wholeSquareVertices );
    mGlw->glVertexAttribPointer ( texCoordLoc, 2, GL_FLOAT,
        GL_FALSE, 2 * sizeof(GLfloat), wholeSquareUvOffset );
    mGlw->glEnableVertexAttribArray ( 0 );
    mGlw->glEnableVertexAttribArray ( 1 );

    mGlw->glActiveTexture(GL_TEXTURE0);
    // source is ping pong 1
    mGlw->glBindTexture( GL_TEXTURE_2D, mPingPongTexture[1] );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_REPEAT ); 
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_REPEAT );

    mGlw->glActiveTexture(GL_TEXTURE1);
    mGlw->glBindTexture( GL_TEXTURE_2D, mLutTextureKey );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_REPEAT );

    mGlw->glActiveTexture(GL_TEXTURE2);
    mGlw->glBindTexture( GL_TEXTURE_2D, mLutTextureXor );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE );

    mGlw->glActiveTexture(GL_TEXTURE3);
    mGlw->glBindTexture( GL_TEXTURE_2D, mLutTexturePermute );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_REPEAT );

    mGlw->glDrawElements ( GL_TRIANGLES, 6, GL_UNSIGNED_SHORT, wholeSquareIndices );
    mGlw->glBindFramebuffer(GL_FRAMEBUFFER, 0);
}

void CMumblepadGlc::DecryptDiffuse(uint32_t /*round*/)
{
    uint32_t location;
    uint32_t positionLoc;
    uint32_t texCoordLoc;

    // second pass for decrypt
    // destination ping pong is 0
    mGlw->glBindFramebuffer(GL_FRAMEBUFFER, mPingPongFBuffer[0]);
    mGlw->glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, mPingPongTexture[0], 0);
    mGlw->glViewport(0,0,MUM_CELLS_X*MUM_GPUC_SCALE,MUM_CELLS_YB);

    mGlw->glUseProgram ( mDecryptDiffuseProgram );
    location = mGlw->glGetUniformLocation ( mDecryptDiffuseProgram, "source" );
    mGlw->glUniform1i ( location, 0 );
    location = mGlw->glGetUniformLocation ( mDecryptDiffuseProgram, "bitmasks" );
    mGlw->glUniform1i ( location, 1 );
    location = mGlw->glGetUniformLocation ( mDecryptDiffuseProgram, "positionX" );
    mGlw->glUniform1i ( location, 2 );
    location = mGlw->glGetUniformLocation ( mDecryptDiffuseProgram, "positionY" );
    mGlw->glUniform1i ( location, 3 );

    // precompute!
    positionLoc = mGlw->glGetAttribLocation ( mDecryptDiffuseProgram, "a_position" );
    texCoordLoc = mGlw->glGetAttribLocation ( mDecryptDiffuseProgram, "a_texCoord" );

    mGlw->glVertexAttribPointer ( positionLoc, 3, GL_FLOAT, 
        GL_FALSE, 3 * sizeof(GLfloat), wholeSquareVertices );
    mGlw->glVertexAttribPointer ( texCoordLoc, 2, GL_FLOAT,
        GL_FALSE, 2 * sizeof(GLfloat), wholeSquareUv );
    mGlw->glEnableVertexAttribArray ( 0 );
    mGlw->glEnableVertexAttribArray ( 1 );

    // second pass for decrypt
    // source ping pong is 1
    mGlw->glActiveTexture(GL_TEXTURE0);
    mGlw->glBindTexture( GL_TEXTURE_2D, mPingPongTexture[1] );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE ); 
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE );

    mGlw->glActiveTexture(GL_TEXTURE1);
    mGlw->glBindTexture( GL_TEXTURE_2D, mLutTextureBitmaskI );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE ); 
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE ); 

    mGlw->glActiveTexture(GL_TEXTURE2);
    mGlw->glBindTexture( GL_TEXTURE_2D, mPositionTexturesXI );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE );

    mGlw->glActiveTexture(GL_TEXTURE3);
    mGlw->glBindTexture( GL_TEXTURE_2D, mPositionTexturesYI );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE );

    mGlw->glDrawElements ( GL_TRIANGLES, 6, GL_UNSIGNED_SHORT, wholeSquareIndices );
    mGlw->glBindFramebuffer(GL_FRAMEBUFFER, 0);
}

void CMumblepadGlc::DecryptConfuse(uint32_t /*round*/)
{
    uint32_t location;
    uint32_t positionLoc;
    uint32_t texCoordLoc;

    // first pass for decrypt
    // destination ping pong is 1
    mGlw->glBindFramebuffer(GL_FRAMEBUFFER, mPingPongFBuffer[1]);
    mGlw->glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, mPingPongTexture[1], 0);
    mGlw->glViewport(0,0,MUM_CELLS_X*MUM_GPUC_SCALE,MUM_CELLS_YB);

    mGlw->glUseProgram ( mDecryptConfuseProgram );

    // precompute!
    location = mGlw->glGetUniformLocation ( mDecryptConfuseProgram, "source" );
    mGlw->glUniform1i ( location, 0 );
    location = mGlw->glGetUniformLocation ( mDecryptConfuseProgram, "lutKey" );
    mGlw->glUniform1i ( location, 1 );
    location = mGlw->glGetUniformLocation ( mDecryptConfuseProgram, "lutXor" );
    mGlw->glUniform1i ( location, 2 );
    location = mGlw->glGetUniformLocation ( mDecryptConfuseProgram, "lutPermute" );
    mGlw->glUniform1i ( location, 3 );

    // precompute!
    positionLoc = mGlw->glGetAttribLocation ( mDecryptConfuseProgram, "a_position" );
    texCoordLoc = mGlw->glGetAttribLocation ( mDecryptConfuseProgram, "a_texCoord" );

    mGlw->glVertexAttribPointer ( positionLoc, 3, GL_FLOAT, 
        GL_FALSE, 3 * sizeof(GLfloat), wholeSquareVertices );
    mGlw->glVertexAttribPointer ( texCoordLoc, 2, GL_FLOAT,
        GL_FALSE, 2 * sizeof(GLfloat), wholeSquareUvOffset );
    mGlw->glEnableVertexAttribArray ( 0 );
    mGlw->glEnableVertexAttribArray ( 1 );

    // first pass for decrypt
    // source ping pong is 0
    mGlw->glActiveTexture(GL_TEXTURE0);
    mGlw->glBindTexture( GL_TEXTURE_2D, mPingPongTexture[0] );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_REPEAT );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_REPEAT );

    mGlw->glActiveTexture(GL_TEXTURE1);
    mGlw->glBindTexture( GL_TEXTURE_2D, mLutTextureKeyI );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_REPEAT );

    mGlw->glActiveTexture(GL_TEXTURE2);
    mGlw->glBindTexture( GL_TEXTURE_2D, mLutTextureXor );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE );

    mGlw->glActiveTexture(GL_TEXTURE3);
    mGlw->glBindTexture( GL_TEXTURE_2D, mLutTexturePermuteI );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_REPEAT );

    mGlw->glDrawElements ( GL_TRIANGLES, 6, GL_UNSIGNED_SHORT, wholeSquareIndices );
    mGlw->glBindFramebuffer(GL_FRAMEBUFFER, 0);
    //mGlw->glFinish();
}

void CMumblepadGlc::EncryptDownload(uint8_t *data)
{
    if (mDownloadIter == 0)
    {
        mGlw->glBindFramebuffer(GL_FRAMEBUFFER, mPingPongFBuffer[0]);
        mGlw->glActiveTexture(GL_TEXTURE0);
        mGlw->glBindTexture(GL_TEXTURE_2D, mPingPongTexture[0]);
        mGlw->glReadPixels(0, 0, MUM_CELLS_X*mMumInfo->horizontalScaling, MUM_CELLS_MAX_Y, GL_RGBA, GL_UNSIGNED_BYTE, mDownloadBuffer);
        mGlw->glBindFramebuffer(GL_FRAMEBUFFER, 0);
    }
    DownloadPrep(data);
    if (mDownloadIter == mMumInfo->horizontalScaling)
        mDownloadIter = 0;
}

void CMumblepadGlc::DecryptDownload(uint8_t *data)
{
    if (mDownloadIter == 0)
    {
        mGlw->glBindFramebuffer(GL_FRAMEBUFFER, mPingPongFBuffer[0]);
        mGlw->glActiveTexture(GL_TEXTURE0);
        mGlw->glBindTexture(GL_TEXTURE_2D, mPingPongTexture[0]);
        mGlw->glReadPixels(0, 7 * MUM_CELLS_MAX_Y, MUM_CELLS_X*mMumInfo->horizontalScaling, MUM_CELLS_MAX_Y, GL_RGBA, GL_UNSIGNED_BYTE, mDownloadBuffer);
        mGlw->glBindFramebuffer(GL_FRAMEBUFFER, 0);
    }
    DownloadPrep(data);
    if (mDownloadIter == mMumInfo->horizontalScaling)
        mDownloadIter = 0;
}

#endif

