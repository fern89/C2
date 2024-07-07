#ifndef HTTPLIB_INCLUDED
#define HTTPLIB_INCLUDED
#include <windows.h>
#include <wininet.h>
int split_url(const char *url, char *host, int* porti, char *path) {
    char *ptr;
    int https = 0;
    // Find the protocol
    char protocol[16] = {0};
    char port[10] = {0};
    ptr = strstr(url, "://");
    if (ptr) {
        strncpy(protocol, url, ptr - url);
        protocol[ptr - url] = '\0';
        url = ptr + 3;
    } else {
        strcpy(protocol, "http");
    }
    if(memcmp(protocol, "https", 5) == 0) https = 1;
    // Find the host
    ptr = strchr(url, ':');
    if (ptr) {
        strncpy(host, url, ptr - url);
        host[ptr - url] = '\0';
        url = ptr + 1;
        
        ptr = strchr(url, '/');
        if (ptr) {
            strncpy(port, url, ptr - url);
            port[ptr - url] = '\0';
            strcpy(path, ptr);
        } else {
            strcpy(port, url);
            strcpy(path, "/");
        }
    } else {
        ptr = strchr(url, '/');
        if (ptr) {
            strncpy(host, url, ptr - url);
            host[ptr - url] = '\0';
            strcpy(path, ptr);
        } else {
            strcpy(host, url);
            strcpy(path, "/");
        }
        if(https)
            strcpy(port, "443");
        else
            strcpy(port, "80");
    }
    *porti = atoi(port);
    return https;
}
int upload(const char* fname, char* url){
    const char* str_header = "Content-Type: multipart/form-data; boundary=----$$ABCdsjsndnmdsndnsmdnmdsnmdsXYZ$$";

    FILE *fp = NULL;
    fopen_s(&fp, fname, "rb");
    if(!fp)
        return -1;

    fseek(fp, 0, SEEK_END);
    long filesize = ftell(fp);
    rewind(fp);
    int datalen = filesize + 1000;
    char *data = calloc(datalen, 1);
    strcpy(data, "------$$ABCdsjsndnmdsndnsmdnmdsnmdsXYZ$$\r\nContent-Disposition: form-data; name=\"file\"; filename=\"");
    strcat(data, fname);
    strcat(data, "\"\r\nContent-Type: application/octet-stream\r\n\r\n");
    int currlen = strlen(data) + filesize;
    fread(data + strlen(data), 1, filesize, fp);
    strcpy(data + currlen, "\r\n------$$ABCdsjsndnmdsndnsmdnmdsnmdsXYZ$$--\r\n");

    HINTERNET io=InternetOpenA("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",INTERNET_OPEN_TYPE_DIRECT,NULL,NULL,0);
    char host[64], path[256];
    int port;
    int https = split_url(url, host, &port, path);
    
    HINTERNET hconnect = InternetConnectA(io, host, port, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET hrequest = HttpOpenRequestA(hconnect, "POST", path, NULL, NULL, NULL, INTERNET_FLAG_SECURE*https, 0);
    HttpSendRequestA(hrequest, str_header, (DWORD)-1, data, datalen);

    fclose(fp);
    InternetCloseHandle(io);
    InternetCloseHandle(hconnect);
    InternetCloseHandle(hrequest);

    return 0;
}
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