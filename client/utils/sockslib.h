#ifndef SOCKSLIB_INCLUDED
#define SOCKSLIB_INCLUDED
#include <ws2tcpip.h>
#include <winsock2.h>
#include <windows.h>
#include <stdlib.h>
#include <stdio.h>

int sendsock(const char* sendbuf, SOCKET* ConnectSocket, unsigned int len){
    int iResult;
    iResult = send(*ConnectSocket, sendbuf, len, 0);
    if (iResult == SOCKET_ERROR){
        closesocket(*ConnectSocket);
        WSACleanup();
        return 1;
    }
    return 0;
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
    if (iResult != 0){
        WSACleanup();
        return 1;
    }

    // Attempt to connect to an address until one succeeds
    // Create a SOCKET for connecting to server
    *ConnectSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (*ConnectSocket == INVALID_SOCKET){
        WSACleanup();
        return 1;
    }

    // Connect to server.
    iResult = connect( *ConnectSocket, result->ai_addr, (int)result->ai_addrlen);
    if (iResult == SOCKET_ERROR){
        closesocket(*ConnectSocket);
        *ConnectSocket = INVALID_SOCKET;
        return 1;
    }

    freeaddrinfo(result);

    if (*ConnectSocket == INVALID_SOCKET){
        WSACleanup();
        return 1;
    }
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
void closesock(SOCKET* ConnectSocket){
    closesocket(*ConnectSocket);
    WSACleanup();
}
#endif