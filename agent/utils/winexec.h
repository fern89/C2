#ifndef WINEXEC_INCLUDED
#define WINEXEC_INCLUDED

#include <windows.h>
#include <stdio.h>
#include <string.h>
int exec(const char* cmd, char* out, int len){
    DWORD bytesRead;
    HANDLE readHandle;
    HANDLE writeHandle;

    SECURITY_ATTRIBUTES sa;

    ZeroMemory(&sa,sizeof(SECURITY_ATTRIBUTES));
   
    sa.bInheritHandle=TRUE;
    sa.lpSecurityDescriptor=NULL;
    sa.nLength=sizeof(SECURITY_ATTRIBUTES);
    if (!CreatePipe(&readHandle,&writeHandle,&sa,0)){
        return -1;
    }
    SetHandleInformation(readHandle, HANDLE_FLAG_INHERIT, 0);
    char output[10000] = {0}; 
    char cmd_line[500]="cmd /c \"";
    if(len == 0)
        strcat(cmd_line, cmd);
    else
        strncat(cmd_line, cmd, len);
    strcat(cmd_line,"\"");
    PROCESS_INFORMATION pi;
    STARTUPINFOA si;
    ZeroMemory( &si, sizeof(si) );
    si.cb = sizeof(si);
    ZeroMemory( &pi, sizeof(pi) );
    si.hStdOutput = writeHandle;
    si.hStdError = writeHandle;
    si.dwFlags |= STARTF_USESTDHANDLES;
    si.dwFlags |= STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    CreateProcessA( 0, cmd_line, 0, 0, TRUE, 0, 0, 0, & si, & pi);
    if(out==NULL) return 0;
    WaitForSingleObject(pi.hProcess, 5000);
    if (!ReadFile(readHandle,output,10000-1,&bytesRead,NULL))
        return -1;
    memcpy(out, output, bytesRead);
    out[bytesRead] = 0;
    return bytesRead;
}

#endif