#ifndef PS_INCL
#define PS_INCL
#include <windows.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <tlhelp32.h>
typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);

LPFN_ISWOW64PROCESS fnIsWow64Process;

BOOL IsWow64(HANDLE hand){
    BOOL bIsWow64 = FALSE;
    fnIsWow64Process = (LPFN_ISWOW64PROCESS) GetProcAddress(GetModuleHandle(TEXT("kernel32")),"IsWow64Process");
    fnIsWow64Process(hand,&bIsWow64);
    return bIsWow64;
}
char* enumProcesses(){
    HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0);
    PROCESSENTRY32 pEntry;
    pEntry.dwSize = sizeof (pEntry);
    BOOL hRes = Process32First(hSnapShot, &pEntry);
    char* data = calloc(100000, 1);
    while (hRes){
        HANDLE hProcess = OpenProcess(0x1000, 0, (DWORD) pEntry.th32ProcessID);
        if(!IsWow64(hProcess))
            sprintf(data + strlen(data), "%d - %s\n", (DWORD)pEntry.th32ProcessID, pEntry.szExeFile);
        CloseHandle(hProcess);
        hRes = Process32Next(hSnapShot, &pEntry);
    }
    CloseHandle(hSnapShot);
    return data;
}

#endif