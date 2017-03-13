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


#include "stdio.h"
#include "malloc.h"
#include "assert.h"
#include "mumblepadgla.h"

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


static char *encryptDiffuseText = 
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
    gl_FragColor[0] = texture2D(bitmasks,vec2(src1[0],0.125))[0] + \
        texture2D(bitmasks,vec2(src2[2],0.375))[0] + \
        texture2D(bitmasks,vec2(src3[3],0.625))[0] + \
        texture2D(bitmasks,vec2(src4[1],0.875))[0];\n\
    gl_FragColor[1] = texture2D(bitmasks,vec2(src1[2],0.125))[0] + \
        texture2D(bitmasks,vec2(src2[3],0.375))[0] + \
        texture2D(bitmasks,vec2(src3[1],0.625))[0] + \
        texture2D(bitmasks,vec2(src4[0],0.875))[0];\n\
    gl_FragColor[2] = texture2D(bitmasks,vec2(src1[3],0.125))[0] + \
        texture2D(bitmasks,vec2(src2[1],0.375))[0] + \
        texture2D(bitmasks,vec2(src3[0],0.625))[0] + \
        texture2D(bitmasks,vec2(src4[2],0.875))[0];\n\
    gl_FragColor[3] = texture2D(bitmasks,vec2(src1[1],0.125))[0] + \
        texture2D(bitmasks,vec2(src2[0],0.375))[0] + \
        texture2D(bitmasks,vec2(src3[2],0.625))[0] + \
        texture2D(bitmasks,vec2(src4[3],0.875))[0];\n\
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
    gl_FragColor[0] = texture2D(bitmasks,vec2(src1[0],0.125))[0] + \
        texture2D(bitmasks,vec2(src2[3],0.375))[0] + \
        texture2D(bitmasks,vec2(src3[2],0.625))[0] + \
        texture2D(bitmasks,vec2(src4[1],0.875))[0];\n\
    gl_FragColor[1] = texture2D(bitmasks,vec2(src1[3],0.125))[0] + \
        texture2D(bitmasks,vec2(src2[2],0.375))[0] + \
        texture2D(bitmasks,vec2(src3[1],0.625))[0] + \
        texture2D(bitmasks,vec2(src4[0],0.875))[0];\n\
    gl_FragColor[2] = texture2D(bitmasks,vec2(src1[1],0.125))[0] + \
        texture2D(bitmasks,vec2(src2[0],0.375))[0] + \
        texture2D(bitmasks,vec2(src3[3],0.625))[0] + \
        texture2D(bitmasks,vec2(src4[2],0.875))[0];\n\
    gl_FragColor[3] = texture2D(bitmasks,vec2(src1[2],0.125))[0] + \
        texture2D(bitmasks,vec2(src2[1],0.375))[0] + \
        texture2D(bitmasks,vec2(src3[0],0.625))[0] + \
        texture2D(bitmasks,vec2(src4[3],0.875))[0];\n\
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
    vec4 xorKey;\n\
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


CMumblepadGla::CMumblepadGla(TMumInfo *mumInfo, CMumGlWrapper *mumGlWrapper) : CMumRenderer(mumInfo)
{
    uint32_t round;
    mMumInfo = mumInfo;
    mGlw = mumGlWrapper;
    mEncryptDiffuseProgram = -1;
    mEncryptConfuseProgram = -1;
    mDecryptDiffuseProgram = -1;
    mDecryptConfuseProgram = -1;

    mPingPongTexture[0] = -1;
    mPingPongFBuffer[0] = -1;
    mPingPongTexture[1] = -1;
    mPingPongFBuffer[1] = -1;

    for ( round = 0; round < MUM_NUM_ROUNDS; round++ )
    {
        mLutTextureKey[round] = -1;
        mLutTexturePermute[round] = -1;
        mLutTexturePermuteI[round] = -1;
        mLutTextureBitmask[round] = -1;
        mPositionTexturesX[round] = -1;
        mPositionTexturesY[round] = -1;
        mPositionTexturesXI[round] = -1;
        mPositionTexturesYI[round] = -1;
    }
    mLutTextureXor = -1;
    if ( !InitTextures() )
        assert(0);
}

void CMumblepadGla::DeleteFrameBuffers()
{
    mGlw->glDeleteTextures(2, mPingPongTexture);
    mGlw->glDeleteFramebuffers(2, mPingPongFBuffer);
}

void CMumblepadGla::DeleteLutTextures()
{
    uint32_t round;

    mGlw->glDeleteTextures(1,&mLutTextureXor);

    for ( round = 0; round < MUM_NUM_ROUNDS; round++ )
    {
        mGlw->glDeleteTextures(1,&mLutTextureKey[round]);
        mGlw->glDeleteTextures(1,&mLutTextureBitmask[round]);
        mGlw->glDeleteTextures(1,&mPositionTexturesX[round]);
        mGlw->glDeleteTextures(1,&mPositionTexturesY[round]);
        mGlw->glDeleteTextures(1,&mPositionTexturesXI[round]);
        mGlw->glDeleteTextures(1,&mPositionTexturesYI[round]);
        mGlw->glDeleteTextures(1,&mLutTexturePermute[round]);
        mGlw->glDeleteTextures(1,&mLutTexturePermuteI[round]);
    }
}

CMumblepadGla::~CMumblepadGla()
{
    mGlw->glDeleteProgram(mEncryptDiffuseProgram); 
    mGlw->glDeleteProgram(mEncryptConfuseProgram); 
    mGlw->glDeleteProgram(mDecryptDiffuseProgram); 
    mGlw->glDeleteProgram(mDecryptConfuseProgram); 
    DeleteFrameBuffers();
    DeleteLutTextures();
    if (mPrng != nullptr)
    {
        delete mPrng;
        mPrng = nullptr;
    }
}

void CMumblepadGla::EncryptUpload(uint8_t *data)
{
    mGlw->glBindTexture( GL_TEXTURE_2D, mPingPongTexture[0] );
    mGlw->glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, MUM_CELLS_X,
        mMumInfo->numRows, GL_RGBA, GL_UNSIGNED_BYTE, data);
}

void CMumblepadGla::DecryptUpload(uint8_t *data)
{
    EncryptUpload(data);
}



bool CMumblepadGla::CreateFrameBuffers()
{
    GLenum result;
    mGlw->glGenTextures(2, mPingPongTexture);
    mGlw->glGenFramebuffers(2, mPingPongFBuffer);

    mGlw->glBindTexture(GL_TEXTURE_2D, mPingPongTexture[0]);
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_REPEAT );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_REPEAT );
    mGlw->glTexImage2D( GL_TEXTURE_2D, 0, GL_RGBA, MUM_CELLS_X, mMumInfo->numRows,
        0, GL_RGBA, GL_UNSIGNED_BYTE, NULL );
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
    mGlw->glTexImage2D( GL_TEXTURE_2D, 0, GL_RGBA, MUM_CELLS_X, mMumInfo->numRows,
        0, GL_RGBA, GL_UNSIGNED_BYTE, NULL );
    mGlw->glBindFramebuffer(GL_FRAMEBUFFER, mPingPongFBuffer[1]);
    mGlw->glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, mPingPongTexture[1], 0);

    result = mGlw->glCheckFramebufferStatus(GL_FRAMEBUFFER);
    if (result != GL_FRAMEBUFFER_COMPLETE)
        return false;
    mGlw->glBindFramebuffer(GL_FRAMEBUFFER, 0);
    return true;
}

bool CMumblepadGla::CreateLutTextures()
{
    uint32_t round;

    mGlw->glGenTextures(1,&mLutTextureXor);
    mGlw->glBindTexture( GL_TEXTURE_2D, mLutTextureXor );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE );
    mGlw->glTexImage2D( GL_TEXTURE_2D, 0, GL_LUMINANCE, MUM_NUM_8BIT_VALUES, MUM_NUM_8BIT_VALUES, 0, GL_LUMINANCE, 
        GL_UNSIGNED_BYTE, mMumInfo->xorTextureData );

    for ( round = 0; round < MUM_NUM_ROUNDS; round++ )
    {
        mGlw->glGenTextures(1,&mLutTextureKey[round]);
        mGlw->glBindTexture( GL_TEXTURE_2D, mLutTextureKey[round] );
        mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST );
        mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST );
        mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_REPEAT );
        mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_REPEAT );
        mGlw->glTexImage2D( GL_TEXTURE_2D, 0, GL_RGBA, MUM_CELLS_X, mMumInfo->numRows,
            0, GL_RGBA, GL_UNSIGNED_BYTE, NULL );

        mGlw->glGenTextures(1,&mLutTextureBitmask[round]);
        mGlw->glBindTexture( GL_TEXTURE_2D, mLutTextureBitmask[round] );
        mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST );
        mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST );
        mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE );
        mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE );
        mGlw->glTexImage2D( GL_TEXTURE_2D, 0, GL_LUMINANCE, MUM_NUM_8BIT_VALUES, MUM_MASK_TABLE_ROWS, 0, GL_LUMINANCE, 
            GL_UNSIGNED_BYTE, NULL );

        mGlw->glGenTextures(1,&mPositionTexturesX[round]);
        mGlw->glBindTexture( GL_TEXTURE_2D, mPositionTexturesX[round] );
        mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST );
        mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST );
        mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE );
        mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE );
        mGlw->glTexImage2D( GL_TEXTURE_2D, 0, GL_RGBA, MUM_CELLS_X, mMumInfo->numRows, 0, GL_RGBA, 
            GL_UNSIGNED_BYTE, NULL );

        mGlw->glGenTextures(1,&mPositionTexturesY[round]);
        mGlw->glBindTexture( GL_TEXTURE_2D, mPositionTexturesY[round] );
        mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST );
        mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST );
        mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE );
        mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE );
        mGlw->glTexImage2D( GL_TEXTURE_2D, 0, GL_RGBA, MUM_CELLS_X, mMumInfo->numRows, 0, GL_RGBA, 
            GL_UNSIGNED_BYTE, NULL );

        mGlw->glGenTextures(1,&mPositionTexturesXI[round]);
        mGlw->glBindTexture( GL_TEXTURE_2D, mPositionTexturesXI[round] );
        mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST );
        mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST );
        mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE );
        mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE );
        mGlw->glTexImage2D( GL_TEXTURE_2D, 0, GL_RGBA, MUM_CELLS_X, mMumInfo->numRows, 0, GL_RGBA, 
            GL_UNSIGNED_BYTE, NULL );

        mGlw->glGenTextures(1,&mPositionTexturesYI[round]);
        mGlw->glBindTexture( GL_TEXTURE_2D, mPositionTexturesYI[round] );
        mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST );
        mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST );
        mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE );
        mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE );
        mGlw->glTexImage2D( GL_TEXTURE_2D, 0, GL_RGBA, MUM_CELLS_X, mMumInfo->numRows, 0, GL_RGBA, 
            GL_UNSIGNED_BYTE, NULL );

        mGlw->glGenTextures(1,&mLutTexturePermute[round]);
        mGlw->glBindTexture( GL_TEXTURE_2D, mLutTexturePermute[round] );
        mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST );
        mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST );
        mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE );
        mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE );
        mGlw->glTexImage2D( GL_TEXTURE_2D, 0, GL_LUMINANCE, MUM_NUM_8BIT_VALUES, mMumInfo->numRows, 0, GL_LUMINANCE, 
            GL_UNSIGNED_BYTE, NULL );

        mGlw->glGenTextures(1,&mLutTexturePermuteI[round]);
        mGlw->glBindTexture( GL_TEXTURE_2D, mLutTexturePermuteI[round] );
        mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST );
        mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST );
        mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE );
        mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE );
        mGlw->glTexImage2D( GL_TEXTURE_2D, 0, GL_LUMINANCE, MUM_NUM_8BIT_VALUES, mMumInfo->numRows, 0, GL_LUMINANCE, 
            GL_UNSIGNED_BYTE, NULL );
    }
    return true;
}


void CMumblepadGla::InitKey()
{
    WriteTextures();
    if (mPrng != nullptr)
    {
        delete mPrng;
        mPrng = nullptr;
    }
    mPrng = new CMumPrng(mMumInfo->subkeys[MUM_PRNG_SUBKEY_INDEX]);
}


void CMumblepadGla::WriteTextures()
{
    uint32_t round;

    for ( round = 0; round < MUM_NUM_ROUNDS; round++ )
    {
        mGlw->glBindTexture( GL_TEXTURE_2D, mLutTextureKey[round] );
        mGlw->glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, MUM_CELLS_X,
            mMumInfo->numRows, GL_RGBA, GL_UNSIGNED_BYTE, mMumInfo->subkeys[round]);

        mGlw->glBindTexture( GL_TEXTURE_2D, mLutTextureBitmask[round] );
        mGlw->glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, MUM_NUM_8BIT_VALUES, MUM_MASK_TABLE_ROWS, 
            GL_LUMINANCE, GL_UNSIGNED_BYTE, mMumInfo->bitmaskTextureData[round]);

        mGlw->glBindTexture( GL_TEXTURE_2D, mPositionTexturesX[round] );
        mGlw->glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, MUM_CELLS_X,
            mMumInfo->numRows, GL_RGBA, GL_UNSIGNED_BYTE, mMumInfo->positionTextureDataX[round]);

        mGlw->glBindTexture( GL_TEXTURE_2D, mPositionTexturesY[round] );
        mGlw->glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, MUM_CELLS_X,
            mMumInfo->numRows, GL_RGBA, GL_UNSIGNED_BYTE, mMumInfo->positionTextureDataY[round]);

        mGlw->glBindTexture( GL_TEXTURE_2D, mPositionTexturesXI[round] );
        mGlw->glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, MUM_CELLS_X,
            mMumInfo->numRows, GL_RGBA, GL_UNSIGNED_BYTE, mMumInfo->positionTextureDataXI[round]);

        mGlw->glBindTexture( GL_TEXTURE_2D, mPositionTexturesYI[round] );
        mGlw->glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, MUM_CELLS_X,
            mMumInfo->numRows, GL_RGBA, GL_UNSIGNED_BYTE, mMumInfo->positionTextureDataYI[round]);

        mGlw->glBindTexture( GL_TEXTURE_2D, mLutTexturePermute[round] );
        mGlw->glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, MUM_NUM_8BIT_VALUES,
            mMumInfo->numRows, GL_LUMINANCE, GL_UNSIGNED_BYTE, mMumInfo->permuteTextureData[round]);

        mGlw->glBindTexture( GL_TEXTURE_2D, mLutTexturePermuteI[round] );
        mGlw->glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, MUM_NUM_8BIT_VALUES,
            mMumInfo->numRows, GL_LUMINANCE, GL_UNSIGNED_BYTE, mMumInfo->permuteTextureDataI[round]);
    }
}

GLuint CMumblepadGla::CreateShader(const char *vertShaderSrc, const char *fragShaderSrc)
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

bool CMumblepadGla::CreateShaders()
{
    mEncryptDiffuseProgram = CreateShader(vertexShaderText,encryptDiffuseText); 
    mEncryptConfuseProgram = CreateShader(vertexShaderText,encryptConfuseText); 
    mDecryptDiffuseProgram = CreateShader(vertexShaderText,decryptDiffuseText); 
    mDecryptConfuseProgram = CreateShader(vertexShaderText,decryptConfuseText); 
    return true;
}

bool CMumblepadGla::InitTextures()
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

void CMumblepadGla::EncryptDiffuse(uint32_t round)
{
    uint32_t location;
    uint32_t positionLoc;
    uint32_t texCoordLoc;

    // 
    // destination is ping pong 1
    mGlw->glBindFramebuffer(GL_FRAMEBUFFER, mPingPongFBuffer[1]);
    mGlw->glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, mPingPongTexture[1], 0);
    mGlw->glViewport(0,0,MUM_CELLS_X,mMumInfo->numRows);

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

    mGlw->glActiveTexture(GL_TEXTURE1);
    mGlw->glBindTexture( GL_TEXTURE_2D, mLutTextureBitmask[round] );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE );

    mGlw->glActiveTexture(GL_TEXTURE2);
    mGlw->glBindTexture( GL_TEXTURE_2D, mPositionTexturesX[round] );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE );

    mGlw->glActiveTexture(GL_TEXTURE3);
    mGlw->glBindTexture( GL_TEXTURE_2D, mPositionTexturesY[round] );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE );

    mGlw->glDrawElements ( GL_TRIANGLES, 6, GL_UNSIGNED_SHORT, wholeSquareIndices );
    mGlw->glBindFramebuffer(GL_FRAMEBUFFER, 0);
}

void CMumblepadGla::EncryptConfuse(uint32_t round)
{
    uint32_t location;
    uint32_t positionLoc;
    uint32_t texCoordLoc;

    // destination is ping pong 0
    mGlw->glBindFramebuffer(GL_FRAMEBUFFER, mPingPongFBuffer[0]);
    mGlw->glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, mPingPongTexture[0], 0);
    mGlw->glViewport(0,0,MUM_CELLS_X,mMumInfo->numRows);

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
        GL_FALSE, 2 * sizeof(GLfloat), wholeSquareUv );
    mGlw->glEnableVertexAttribArray ( 0 );
    mGlw->glEnableVertexAttribArray ( 1 );

    mGlw->glActiveTexture(GL_TEXTURE0);
    // source is ping pong 1
    mGlw->glBindTexture( GL_TEXTURE_2D, mPingPongTexture[1] );

    mGlw->glActiveTexture(GL_TEXTURE1);
    mGlw->glBindTexture( GL_TEXTURE_2D, mLutTextureKey[round] );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE );

    mGlw->glActiveTexture(GL_TEXTURE2);
    mGlw->glBindTexture( GL_TEXTURE_2D, mLutTextureXor );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE );

    mGlw->glActiveTexture(GL_TEXTURE3);
    mGlw->glBindTexture( GL_TEXTURE_2D, mLutTexturePermute[round] );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE );

    mGlw->glDrawElements ( GL_TRIANGLES, 6, GL_UNSIGNED_SHORT, wholeSquareIndices );
    mGlw->glBindFramebuffer(GL_FRAMEBUFFER, 0);
}

void CMumblepadGla::DecryptDiffuse(uint32_t round)
{
    uint32_t location;
    uint32_t positionLoc;
    uint32_t texCoordLoc;

    // second pass for decrypt
    // destination ping pong is 0
    mGlw->glBindFramebuffer(GL_FRAMEBUFFER, mPingPongFBuffer[0]);
    mGlw->glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, mPingPongTexture[0], 0);
    mGlw->glViewport(0,0,MUM_CELLS_X,mMumInfo->numRows);

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

    mGlw->glActiveTexture(GL_TEXTURE1);
    mGlw->glBindTexture( GL_TEXTURE_2D, mLutTextureBitmask[round] );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE );

    mGlw->glActiveTexture(GL_TEXTURE2);
    mGlw->glBindTexture( GL_TEXTURE_2D, mPositionTexturesXI[round] );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE );

    mGlw->glActiveTexture(GL_TEXTURE3);
    mGlw->glBindTexture( GL_TEXTURE_2D, mPositionTexturesYI[round] );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE );

    mGlw->glDrawElements ( GL_TRIANGLES, 6, GL_UNSIGNED_SHORT, wholeSquareIndices );
    mGlw->glBindFramebuffer(GL_FRAMEBUFFER, 0);
}

void CMumblepadGla::DecryptConfuse(uint32_t round)
{
    uint32_t location;
    uint32_t positionLoc;
    uint32_t texCoordLoc;

    // first pass for decrypt
    // destination ping pong is 1
    mGlw->glBindFramebuffer(GL_FRAMEBUFFER, mPingPongFBuffer[1]);
    mGlw->glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, mPingPongTexture[1], 0);
    mGlw->glViewport(0,0,MUM_CELLS_X,mMumInfo->numRows);

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
        GL_FALSE, 2 * sizeof(GLfloat), wholeSquareUv );
    mGlw->glEnableVertexAttribArray ( 0 );
    mGlw->glEnableVertexAttribArray ( 1 );

    // first pass for decrypt
    // source ping pong is 0
    mGlw->glActiveTexture(GL_TEXTURE0);
    mGlw->glBindTexture( GL_TEXTURE_2D, mPingPongTexture[0] );

    mGlw->glActiveTexture(GL_TEXTURE1);
    mGlw->glBindTexture( GL_TEXTURE_2D, mLutTextureKey[round] );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE );

    mGlw->glActiveTexture(GL_TEXTURE2);
    mGlw->glBindTexture( GL_TEXTURE_2D, mLutTextureXor );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE );

    mGlw->glActiveTexture(GL_TEXTURE3);
    mGlw->glBindTexture( GL_TEXTURE_2D, mLutTexturePermuteI[round] );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE );
    mGlw->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE );

    mGlw->glDrawElements ( GL_TRIANGLES, 6, GL_UNSIGNED_SHORT, wholeSquareIndices );
    mGlw->glBindFramebuffer(GL_FRAMEBUFFER, 0);
}

void CMumblepadGla::EncryptDownload(uint8_t *data)
{
    mGlw->glBindFramebuffer(GL_FRAMEBUFFER, mPingPongFBuffer[0]);
    mGlw->glActiveTexture(GL_TEXTURE0);
    mGlw->glBindTexture( GL_TEXTURE_2D, mPingPongTexture[0] );
    mGlw->glReadPixels(0, 0, MUM_CELLS_X, mMumInfo->numRows, GL_RGBA, GL_UNSIGNED_BYTE, data);
    mGlw->glBindFramebuffer(GL_FRAMEBUFFER, 0);
}

void CMumblepadGla::DecryptDownload(uint8_t *data)
{
    EncryptDownload(data);
}


#endif
