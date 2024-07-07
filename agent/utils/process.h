#ifndef PROCESS_INCLUDED
#define PROCESS_INCLUDED
#include <windows.h>
#include <tlhelp32.h>
HANDLE processByPid(DWORD pid){
    return OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
}
HANDLE processByName(const char* name){
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    HANDLE hProcess = NULL;
    if (Process32First(snapshot, &entry)){
        while (Process32Next(snapshot, &entry)){
            if (stricmp(entry.szExeFile, name) == 0){
                hProcess = processByPid(entry.th32ProcessID);
                break;
            }
        }
    }

    CloseHandle(snapshot);
    return hProcess;
}
#endif