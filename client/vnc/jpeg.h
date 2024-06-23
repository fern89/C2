#ifndef IMGLIB_INCL
#define IMGLIB_INCL
//credit to https://www.autohotkey.com/boards/viewtopic.php?t=67716 for the base code
#include <stdio.h>
#include <windows.h>
#include <stdlib.h>
#include <string.h>
typedef int WINAPI(*d_GdipCreateBitmapFromHBITMAP)(HBITMAP hbm, HPALETTE hpal, void** bitmap);
typedef int WINAPI(*d_GdiplusStartup)(ULONG_PTR* upt, void* a, unsigned int b);
typedef int WINAPI(*d_GdipSaveImageToStream)(void* image, IStream* stream, CLSID* clsidEncoder, unsigned int encoderParams);
typedef int WINAPI(*d_GdipDisposeImage)(void* image);
char* bmptojpg(HBITMAP hbitmap, int* sz){
    static CLSID cls;
    static d_GdipCreateBitmapFromHBITMAP GdipCreateBitmapFromHBITMAP;
    static d_GdipSaveImageToStream GdipSaveImageToStream;
    static d_GdiplusStartup GdiplusStartup;
    static d_GdipDisposeImage GdipDisposeImage;
    if(GdipCreateBitmapFromHBITMAP==NULL){
        //init code
        CLSIDFromString(L"{557CF406-1A04-11D3-9A73-0000F81EF32E}", &cls);
        void* gdip = LoadLibraryA("gdiplus.dll");
        GdipCreateBitmapFromHBITMAP = (d_GdipCreateBitmapFromHBITMAP)GetProcAddress(gdip, "GdipCreateBitmapFromHBITMAP");
        GdipSaveImageToStream = (d_GdipSaveImageToStream)GetProcAddress(gdip, "GdipSaveImageToStream");
        GdiplusStartup = (d_GdiplusStartup)GetProcAddress(gdip, "GdiplusStartup");
        GdipDisposeImage = (d_GdipDisposeImage)GetProcAddress(gdip, "GdipDisposeImage");
        
        //can use this to GdiplusShutdown if you want, but i don't see need
        ULONG_PTR a;
        unsigned char si[24] = {0};
        //set GdiplusVersion in GdiplusStartupInput to 1
        si[0] = 1;
        if(GdiplusStartup(&a, &si, 0)) return NULL;
    }
    //make gdi+ compat bitmap
    void* bmp;
    if(GdipCreateBitmapFromHBITMAP(hbitmap, 0, &bmp)) return NULL;
    
    //pipe to stream
    IStream* istream = NULL;
    HRESULT hr = CreateStreamOnHGlobal(NULL, TRUE, &istream);
    if(GdipSaveImageToStream(bmp, istream, &cls, 0)){
        GdipDisposeImage(bmp);
        return NULL;
    }
    
    //stream to buffer
    HGLOBAL hg = NULL;
    GetHGlobalFromStream(istream, &hg);
    int bufsize = GlobalSize(hg);
    char *buffer = calloc(bufsize, 1);
    LPVOID ptr = GlobalLock(hg);
    memcpy(buffer, ptr, bufsize);
    
    //cleanup
    GlobalUnlock(hg);
    GlobalFree(hg);
    GdipDisposeImage(bmp);
    *sz = bufsize;
    return buffer;
}
#endif