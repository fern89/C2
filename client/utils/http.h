#ifndef HTTPLIB_INCLUDED
#define HTTPLIB_INCLUDED
#include <windows.h>
#include <wininet.h>
//webreq("https://www.google.com", 10000, out, TRUE)
int webreq(const char* path, DWORD size, char* out, BOOL https){
    DWORD wrt;
    HINTERNET io=InternetOpenA("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",INTERNET_OPEN_TYPE_DIRECT,NULL,NULL,0);
    HINTERNET hreq=InternetOpenUrlA(io, path, NULL, 0, ((unsigned int)https)*INTERNET_FLAG_SECURE, 0);
    if(out==NULL){
        char tmp[10];
        if(!InternetReadFile(hreq,tmp,10,&wrt)) return -1;
    }else{
        if(!InternetReadFile(hreq,out,size-1,&wrt)) return -1;
    }
    InternetCloseHandle(io);
    InternetCloseHandle(hreq);
    return wrt;
}
#endif