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

#ifndef __MUMGLWRAPPER_H
#define __MUMGLWRAPPER_H

#include "windows.h"
#include "gl\gl.h"
#include "gl\glu.h"
#include "../mgl/glext.h"

#include "mumrenderer.h"


#ifdef USE_MUM_OPENGL



#define ESUTIL_API  __cdecl
#define ESCALLBACK  __cdecl


#define ES_WINDOW_RGB           0
#define ES_WINDOW_ALPHA         1 
#define ES_WINDOW_DEPTH         2 
#define ES_WINDOW_STENCIL       4
#define ES_WINDOW_MULTISAMPLE   8


typedef struct
{
    GLint width;
    GLint height;
    HWND  hWnd;
} ESContext;

//void ESUTIL_API esInitContext ( ESContext *esContext );
//GLboolean ESUTIL_API esCreateWindow ( ESContext *esContext, const char *title, GLint width, GLint height, GLuint flags );
//GLuint ESUTIL_API esLoadShader ( GLenum type, const char *shaderSrc );
//GLuint ESUTIL_API esLoadProgram ( const char *vertShaderSrc, const char *fragShaderSrc );

typedef void (APIENTRYP PFNGLBINDTEXTUREPROC ) ( GLenum target, GLuint texture );
typedef void (APIENTRYP PFNGLDELETETEXTURESPROC ) ( GLsizei n, const GLuint* textures );
typedef void (APIENTRYP PFNGLDISABLEPROC ) ( GLenum cap );
typedef void (APIENTRYP PFNGLDRAWELEMENTSPROC ) ( GLenum mode, GLsizei count, GLenum type, const GLvoid* indices );
typedef void (APIENTRYP PFNGLENABLEPROC ) ( GLenum cap );
typedef void (APIENTRYP PFNGLGENTEXTURESPROC ) ( GLsizei n, GLuint* textures );
typedef void (APIENTRYP PFNGLREADPIXELSPROC ) ( GLint x, GLint y, GLsizei width, GLsizei height, GLenum format, GLenum type, GLvoid* pixels );
typedef void (APIENTRYP PFNGLTEXIMAGE2DPROC ) ( GLenum target, GLint level, GLint internalformat, GLsizei width, GLsizei height, GLint border, GLenum format, GLenum type, const GLvoid* pixels );
typedef void (APIENTRYP PFNGLTEXPARAMETERIPROC ) ( GLenum target, GLenum pname, GLint param );
typedef void (APIENTRYP PFNGLTEXSUBIMAGE2DPROC ) ( GLenum target, GLint level, GLint xoffset, GLint yoffset, GLsizei width, GLsizei height, GLenum format, GLenum type, const GLvoid* pixels );
typedef void (APIENTRYP PFNGLVIEWPORTPROC ) ( GLint x, GLint y, GLsizei width, GLsizei height );

typedef HGLRC ( WINAPI* PFNWGLCREATECONTEXTPROC )( HDC );
typedef BOOL  ( WINAPI* PFNWGLDELETECONTEXTPROC )( HGLRC );
typedef HGLRC ( WINAPI* PFNWGLGETCURRENTCONTEXTPROC )( void );
typedef PROC  ( WINAPI* PFNWGLGETPROCADDRESSPROC )( LPCSTR );
typedef BOOL  ( WINAPI* PFNWGLMAKECURRENTPROC )( HDC, HGLRC );


class CMumGlWrapper
{
public:
    CMumGlWrapper();
    ~CMumGlWrapper();
    void Init();
    GLuint LoadShader ( GLenum type, const char *shaderSrc );

    PFNGLATTACHSHADERPROC glAttachShader;

    PFNGLBINDTEXTUREPROC glBindTexture;

    PFNGLCOMPILESHADERPROC glCompileShader;


    PFNGLGENTEXTURESPROC glGenTextures;
    PFNGLTEXIMAGE2DPROC glTexImage2D;
    PFNGLREADPIXELSPROC glReadPixels;
    PFNGLCREATEPROGRAMPROC glCreateProgram;

    PFNGLDELETESHADERPROC glDeleteShader;
    PFNGLDELETEPROGRAMPROC glDeleteProgram;
    PFNGLDELETETEXTURESPROC glDeleteTextures;
    PFNGLDRAWELEMENTSPROC glDrawElements;
    PFNGLDRAWBUFFERSPROC glDrawBuffers; 
    PFNGLDISABLEPROC glDisable;

    PFNGLENABLEPROC glEnable;

    PFNGLGETPROGRAMINFOLOGPROC glGetProgramInfoLog;
    PFNGLGETSHADERINFOLOGPROC glGetShaderInfoLog;

    PFNGLGETPROGRAMIVPROC glGetProgramiv;
    PFNGLLINKPROGRAMPROC glLinkProgram;
    PFNGLUSEPROGRAMPROC glUseProgram;
    PFNGLACTIVETEXTUREPROC glActiveTexture;
    PFNGLGETUNIFORMLOCATIONPROC glGetUniformLocation;
    PFNGLBINDFRAMEBUFFERPROC glBindFramebuffer;
    PFNGLDELETEFRAMEBUFFERSPROC glDeleteFramebuffers;
    PFNGLGENFRAMEBUFFERSPROC glGenFramebuffers;
    PFNGLFRAMEBUFFERTEXTURE2DPROC glFramebufferTexture2D;
    PFNGLCHECKFRAMEBUFFERSTATUSPROC glCheckFramebufferStatus;
    PFNGLFRAMEBUFFERTEXTUREPROC glFramebufferTexture;
    PFNGLUNIFORM1IPROC glUniform1i;
    PFNGLGETSHADERIVPROC glGetShaderiv;
    PFNGLGETATTRIBLOCATIONPROC glGetAttribLocation;
    PFNGLVERTEXATTRIBPOINTERPROC glVertexAttribPointer;
    PFNGLENABLEVERTEXATTRIBARRAYPROC glEnableVertexAttribArray;
    PFNGLBINDBUFFERPROC glBindBuffer;
    PFNGLGENBUFFERSPROC glGenBuffers;
    PFNGLBUFFERDATAPROC glBufferData;
    PFNGLCREATESHADERPROC glCreateShader;
    PFNGLSHADERSOURCEPROC glShaderSource;

    PFNGLTEXSUBIMAGE2DPROC glTexSubImage2D;
    PFNGLTEXPARAMETERIPROC glTexParameteri;

    PFNGLVIEWPORTPROC glViewport;


private:
    bool EnableOpenGL(ESContext *esContext);
    bool WinCreate ( ESContext *esContext, const char *title );
    bool esCreateWindow ( ESContext *esContext, const char* title, GLint width, GLint height, GLuint flags );
    GLuint LoadProgram ( const char *vertShaderSrc, const char *fragShaderSrc );

    HDC mHDC;
    HGLRC mHGLRC;
    ESContext mContext;
    HMODULE mOpenGlHandle;
    void *GetGlProcAddress(char * procName);

    PFNWGLCREATECONTEXTPROC     mwglCreateContext;
    PFNWGLDELETECONTEXTPROC     mwglDeleteContext;
    PFNWGLGETCURRENTCONTEXTPROC mwglGetCurrentContext;
    PFNWGLGETPROCADDRESSPROC    mwglGetProcAddress;
    PFNWGLMAKECURRENTPROC       mwglMakeCurrent;

};


#endif


#endif