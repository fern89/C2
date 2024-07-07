#ifndef PROX_INCL
#define PROX_INCL
#include <windows.h>
#include <stdlib.h>
#include "../utils/sockslib.h"
int proxies[10] = {0};
int swap(int num){
    return ((num>>24)&0xff) | ((num<<8)&0xff0000) | ((num>>8)&0xff00) | ((num<<24)&0xff000000);
}
typedef struct _netpipes{
    SOCKET* from;
    SOCKET* to;
    int living;
} NETPIPE;
typedef struct _proxobj{
    char* ip;
    int port;
    int* alive;
} PROXOBJ;
int* gethole(int* id){
    for(int i=0;i<10;i++){
        if(proxies[i] == 0){
            proxies[i] = 1;
            *id = i;
            return &(proxies[i]);
        }
    }
}
void piper(NETPIPE* pipe){
    while(1){
        unsigned char datum[1000] = {0};
        int nb = sockrecva(pipe->from, datum, 1000);
        if(nb == -1) break;
        sendsock(pipe->to, datum, nb);
    }
    pipe->living = 0;
}
void newproxy(PROXOBJ* prox){
    SOCKET* sock = calloc(sizeof(SOCKET), 1);
    newsock(prox->ip, prox->port, sock);
    while(*(prox->alive)){
        unsigned char blank[1024] = {0};
        if(sockrecva(sock, blank, 1024) == -1) break;
        if(blank[0] != 5) continue;
        sendsock(sock, "\x05\x00", 2);
        memset(blank, 0, 1024);
        if(sockrecva(sock, blank, 1024) < 2) continue;
        if(blank[1] != 1) continue;
        int cl = 0;
        struct in_addr addr;
        
        if(blank[3] == 1){
            unsigned int data = 0;
            memcpy(&data, blank+4, 4);
            cl = 8;
            addr.s_addr = data;
        }else if(blank[3] == 3){
            char hostname[256] = {0};
            memcpy(hostname, blank+5, blank[4]);
            struct hostent *remoteHost;
            remoteHost = gethostbyname(hostname);

            addr.s_addr = *(u_long *) remoteHost->h_addr_list[0];
            cl = 5+blank[4];
        }
        int port = (blank[cl]*0x100) + blank[cl+1];
        
        SOCKET tsock;
        newsock(inet_ntoa(addr), port, &tsock);
        
        unsigned char resp[10] = "\x05\x00\x00\x01";
        memcpy(resp+4, &addr.s_addr, 4);
        resp[8] = blank[cl];
        resp[9] = blank[cl+1];
        sendsock(sock, resp, 10);
        NETPIPE pipes;
        pipes.from = &tsock;
        pipes.to = sock;
        pipes.living = 1;
        HANDLE thd = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)piper, &pipes, 0, NULL);
        while(pipes.living){
            unsigned char datum[1000] = {0};
            int nb = sockrecva(sock, datum, 1000);
            if(nb == -1 || memcmp(datum, "CLOSED", 6) == 0)
                break;
            sendsock(&tsock, datum, nb);
        }
        TerminateThread(thd, 0);
        closesock(&tsock);
    }
    closesock(sock);
    *(prox->alive) = 0;
    free(prox->ip);
    free(prox);
}
#endif