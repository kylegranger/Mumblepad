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


#include "mumglwrapper.h"

#ifdef USE_MUM_OPENGL

CMumGlWrapper::CMumGlWrapper()
{
}

void CMumGlWrapper::Init()
{
    memset( this, 0, sizeof(CMumGlWrapper) );

    // use this to obtain GL 1.0 entry points
    mOpenGlHandle = ::LoadLibrary( "opengl32.dll" );

    // WGL
    mwglCreateContext =     (PFNWGLCREATECONTEXTPROC)     GetProcAddress( mOpenGlHandle, "wglCreateContext" );
    mwglDeleteContext =     (PFNWGLDELETECONTEXTPROC)     GetProcAddress( mOpenGlHandle, "wglDeleteContext" );
    mwglGetCurrentContext = (PFNWGLGETCURRENTCONTEXTPROC) GetProcAddress( mOpenGlHandle, "wglGetCurrentContext" );
    mwglGetProcAddress =    (PFNWGLGETPROCADDRESSPROC)    GetProcAddress( mOpenGlHandle, "wglGetProcAddress" );
    mwglMakeCurrent =       (PFNWGLMAKECURRENTPROC)       GetProcAddress( mOpenGlHandle, "wglMakeCurrent" );

    esCreateWindow ( &mContext, "MumEngine", 320, 240, ES_WINDOW_RGB );


    glActiveTexture = (PFNGLACTIVETEXTUREPROC) GetGlProcAddress("glActiveTexture");
    glAttachShader = (PFNGLATTACHSHADERPROC) GetGlProcAddress("glAttachShader");
    glBindBuffer = (PFNGLBINDBUFFERPROC) GetGlProcAddress("glBindBuffer");
    glBindFramebuffer = (PFNGLBINDFRAMEBUFFERPROC) GetGlProcAddress("glBindFramebuffer");
    glBindTexture = (PFNGLBINDTEXTUREPROC) GetGlProcAddress("glBindTexture");
    glBufferData = (PFNGLBUFFERDATAPROC) GetGlProcAddress("glBufferData");
    glCheckFramebufferStatus = (PFNGLCHECKFRAMEBUFFERSTATUSPROC) GetGlProcAddress("glCheckFramebufferStatus");
    glCompileShader = (PFNGLCOMPILESHADERPROC) GetGlProcAddress("glCompileShader");
    glCreateProgram = (PFNGLCREATEPROGRAMPROC) GetGlProcAddress("glCreateProgram");
    glCreateShader = (PFNGLCREATESHADERPROC) GetGlProcAddress("glCreateShader");
    glDeleteFramebuffers = (PFNGLDELETEFRAMEBUFFERSPROC) GetGlProcAddress("glDeleteFramebuffers");
    glDeleteProgram = (PFNGLDELETEPROGRAMPROC) GetGlProcAddress("glDeleteProgram");
    glDeleteShader = (PFNGLDELETESHADERPROC) GetGlProcAddress("glDeleteShader");
    glDeleteTextures = (PFNGLDELETETEXTURESPROC) GetGlProcAddress("glDeleteTextures");
    glDisable = (PFNGLDISABLEPROC) GetGlProcAddress("glDisable");
    glDrawBuffers = (PFNGLDRAWBUFFERSPROC) GetGlProcAddress("glDrawBuffers");
    glDrawElements = (PFNGLDRAWELEMENTSPROC) GetGlProcAddress("glDrawElements");
    glEnable = (PFNGLENABLEPROC) GetGlProcAddress("glEnable");
    glEnableVertexAttribArray = (PFNGLENABLEVERTEXATTRIBARRAYPROC) GetGlProcAddress("glEnableVertexAttribArray");

    glTexSubImage2D = (PFNGLTEXSUBIMAGE2DPROC) GetGlProcAddress("glTexSubImage2D");
    glGenTextures = (PFNGLGENTEXTURESPROC) GetGlProcAddress("glGenTextures");

    glGetProgramInfoLog = (PFNGLGETPROGRAMINFOLOGPROC) GetGlProcAddress("glGetProgramInfoLog");

    glGenFramebuffers = (PFNGLGENFRAMEBUFFERSPROC) GetGlProcAddress("glGenFramebuffers");
    glFramebufferTexture2D = (PFNGLFRAMEBUFFERTEXTURE2DPROC) GetGlProcAddress("glFramebufferTexture2D");
    glFramebufferTexture = (PFNGLFRAMEBUFFERTEXTUREPROC) GetGlProcAddress("glFramebufferTexture");
    glGetShaderiv = (PFNGLGETSHADERIVPROC) GetGlProcAddress("glGetShaderiv");
    glGenBuffers = (PFNGLGENBUFFERSPROC) GetGlProcAddress("glGenBuffers");
    glGetShaderInfoLog = (PFNGLGETSHADERINFOLOGPROC) GetGlProcAddress("glGetShaderInfoLog");
    glGetShaderiv = (PFNGLGETSHADERIVPROC) GetGlProcAddress("glGetShaderiv");
    glGetAttribLocation = (PFNGLGETATTRIBLOCATIONPROC) GetGlProcAddress("glGetAttribLocation");
    glGetProgramiv = (PFNGLGETPROGRAMIVPROC) GetGlProcAddress("glGetProgramiv");
    glGetUniformLocation = (PFNGLGETUNIFORMLOCATIONPROC) GetGlProcAddress("glGetUniformLocation");
    glLinkProgram = (PFNGLLINKPROGRAMPROC) GetGlProcAddress("glLinkProgram");
    glReadPixels = (PFNGLREADPIXELSPROC) GetGlProcAddress("glReadPixels");
    glShaderSource = (PFNGLSHADERSOURCEPROC) GetGlProcAddress("glShaderSource");
    glTexParameteri = (PFNGLTEXPARAMETERIPROC) GetGlProcAddress("glTexParameteri");
    glTexImage2D = (PFNGLTEXIMAGE2DPROC) GetGlProcAddress("glTexImage2D");
    glUniform1i = (PFNGLUNIFORM1IPROC) GetGlProcAddress("glUniform1i");
    glUseProgram = (PFNGLUSEPROGRAMPROC) GetGlProcAddress("glUseProgram");
    glVertexAttribPointer = (PFNGLVERTEXATTRIBPOINTERPROC) GetGlProcAddress("glVertexAttribPointer");
    glViewport = (PFNGLVIEWPORTPROC) GetGlProcAddress("glViewport");
}

bool CMumGlWrapper::EnableOpenGL(ESContext *esContext)
{
    PIXELFORMATDESCRIPTOR pfd;
    int format;
    BOOL res;
    
    mHDC = GetDC( esContext->hWnd );
    
    // set the pixel format for the DC
    ZeroMemory( &pfd, sizeof( pfd ) );
    pfd.nSize = sizeof( pfd );
    pfd.nVersion = 1;
    pfd.dwFlags = PFD_DRAW_TO_WINDOW | PFD_SUPPORT_OPENGL | PFD_DOUBLEBUFFER | PFD_STEREO; 
    pfd.iPixelType = PFD_TYPE_RGBA;
    pfd.cColorBits = 24;
    // pfd.cColorBits = 32;
    // pfd.cDepthBits = 0;
    pfd.cDepthBits = 16;
    pfd.cAccumBits = 0; 
    pfd.cStencilBits = 0; 
    pfd.iLayerType = PFD_MAIN_PLANE;
    pfd.dwLayerMask = PFD_MAIN_PLANE; 
    format = ChoosePixelFormat( mHDC, &pfd );
    res = SetPixelFormat( mHDC, format, &pfd );
    if (!res)
    {
        DWORD error = GetLastError();
        //sprintf(text,"Could not SetPixelFormat: format is %d, error is %d.",
        //    format, error );
        //MessageBox(NULL,text, "OpenGL Initialization", MB_OK );
    }
    
    // create and enable the render context (RC)
    mHGLRC = wglCreateContext( mHDC );
    BOOL result = wglMakeCurrent( mHDC, mHGLRC );
    return (result == TRUE);
}


LRESULT WINAPI ESWindowProc ( HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam ) 
{
    LRESULT lres = 1; 
    ESContext *esContext = NULL;

    switch (uMsg) 
    { 
        case WM_CREATE:
            break;
        case WM_PAINT:
            esContext = (ESContext*)(LONG_PTR) GetWindowLongPtr ( hWnd, -21 /*GWL_USERDATA*/ );
            ValidateRect( esContext->hWnd, NULL );
            break;
        case WM_DESTROY:
            PostQuitMessage(0);
            break; 
        case WM_CHAR:
            break;
        default: 
            lres = DefWindowProc (hWnd, uMsg, wParam, lParam); 
            break; 
    } 

    return lres; 
}



bool CMumGlWrapper::WinCreate ( ESContext *esContext, const char *title )
{
    WNDCLASS wndclass = {0}; 
    DWORD wStyle  = 0;
    RECT windowRect;
    HINSTANCE hInstance = GetModuleHandle(NULL);
    LPCSTR wstr = (LPCSTR) "opengles2.0";


    wndclass.style = CS_OWNDC;
    wndclass.lpfnWndProc   = (WNDPROC)ESWindowProc; 
    wndclass.hInstance     = hInstance; 
    wndclass.hbrBackground = (HBRUSH)GetStockObject(BLACK_BRUSH); 
    wndclass.lpszClassName = wstr; 

    if (!RegisterClass (&wndclass) ) 
        return FALSE; 

    wStyle = WS_VISIBLE | WS_POPUP | WS_BORDER | WS_SYSMENU | WS_CAPTION;
    
    // Adjust the window rectangle so that the client area has
    // the correct number of pixels
    windowRect.left = 0;
    windowRect.top = 0;
    windowRect.right = esContext->width;
    windowRect.bottom = esContext->height;

    AdjustWindowRect ( &windowRect, wStyle, FALSE );

    esContext->hWnd = CreateWindow(
        wstr,
        (LPCSTR) title,
        wStyle,
        0,
        0,
        windowRect.right - windowRect.left,
        windowRect.bottom - windowRect.top,
        NULL,
        NULL,
        hInstance,
        NULL);

    SetWindowLongPtr ( esContext->hWnd, -21 /*GWL_USERDATA*/, (LONG) (LONG_PTR) esContext );

    if ( esContext->hWnd == NULL )
        return GL_FALSE;

    ShowWindow ( esContext->hWnd, TRUE );

    return GL_TRUE;
}





bool CMumGlWrapper::esCreateWindow ( ESContext *esContext, const char* title, GLint width, GLint height, GLuint flags )
{
    esContext->width = width;
    esContext->height = height;

    if ( !WinCreate ( esContext, title) )
    {
        return GL_FALSE;
    }


    if ( !EnableOpenGL(esContext) )
        return false;

    return true;
}

GLuint CMumGlWrapper::LoadShader ( GLenum type, const char *shaderSrc )
{
    GLuint shader;
    GLint compiled;
    
    shader = glCreateShader ( type );
    if ( shader == 0 )
        return 0;

    glShaderSource ( shader, 1, &shaderSrc, NULL );
    glCompileShader ( shader );
    glGetShaderiv ( shader, GL_COMPILE_STATUS, &compiled );

    if ( !compiled ) 
    {
        GLint infoLen = 0;

        glGetShaderiv ( shader, GL_INFO_LOG_LENGTH, &infoLen );
        
        if ( infoLen > 1 )
        {
            char* infoLog = (char* ) malloc (sizeof(char) * infoLen );
            glGetShaderInfoLog ( shader, infoLen, NULL, infoLog );
            free ( infoLog );
        }

        glDeleteShader ( shader );
        return 0;
    }

    return shader;

}


GLuint CMumGlWrapper::LoadProgram ( const char *vertShaderSrc, const char *fragShaderSrc )
{
    GLuint vertexShader;
    GLuint fragmentShader;
    GLuint programObject;
    GLint linked;

    // Load the vertex/fragment shaders
    vertexShader = LoadShader ( GL_VERTEX_SHADER, vertShaderSrc );
    if ( vertexShader == 0 )
        return 0;

    fragmentShader = LoadShader ( GL_FRAGMENT_SHADER, fragShaderSrc );
    if ( fragmentShader == 0 )
    {
        glDeleteShader( vertexShader );
        return 0;
    }

    // Create the program object
    programObject = glCreateProgram ( );
    
    if ( programObject == 0 )
        return 0;

    glAttachShader ( programObject, vertexShader );
    glAttachShader ( programObject, fragmentShader );

    // Link the program
    glLinkProgram ( programObject );

    // Check the link status
    glGetProgramiv ( programObject, GL_LINK_STATUS, &linked );

    if ( !linked ) 
    {
        GLint infoLen = 0;

        glGetProgramiv ( programObject, GL_INFO_LOG_LENGTH, &infoLen );
        
        if ( infoLen > 1 )
        {
            char* infoLog = (char* ) malloc (sizeof(char) * infoLen );
            glGetProgramInfoLog ( programObject, infoLen, NULL, infoLog );
            free ( infoLog );
        }

        glDeleteProgram ( programObject );
        return 0;
    }

    // Free up no longer needed shader resources
    glDeleteShader ( vertexShader );
    glDeleteShader ( fragmentShader );

    return programObject;
}

void* CMumGlWrapper::GetGlProcAddress(char* procName) 
{
    void * procAddress = NULL;

    if (mwglGetProcAddress != NULL)
        procAddress = ( void* )mwglGetProcAddress( procName );
    if (procAddress == NULL)
        procAddress = GetProcAddress( mOpenGlHandle, procName );

    return procAddress;
}

#endif