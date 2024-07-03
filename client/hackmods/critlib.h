#include <windows.h>
typedef long WINAPI(*d_RtlSetProcessIsCritical)(BOOL a, PBOOL b, BOOL c);
d_RtlSetProcessIsCritical RtlSetProcessIsCritical = NULL;
BOOL EnablePriv(LPCSTR lpszPriv){
    HANDLE hToken;
    LUID luid;
    TOKEN_PRIVILEGES tkprivs;
    ZeroMemory(&tkprivs, sizeof(tkprivs));
     
    if(!OpenProcessToken(GetCurrentProcess(), (TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY), &hToken))
        return FALSE;
     
    if(!LookupPrivilegeValue(NULL, lpszPriv, &luid)){
        CloseHandle(hToken);
        return FALSE;
    }
     
    tkprivs.PrivilegeCount = 1;
    tkprivs.Privileges[0].Luid = luid;
    tkprivs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
     
    BOOL bRet = AdjustTokenPrivileges(hToken, FALSE, &tkprivs, sizeof(tkprivs), NULL, NULL);
    CloseHandle(hToken);
    return bRet;
}

int setCritical(int critical){
    if(RtlSetProcessIsCritical == NULL){
        EnablePriv(SE_DEBUG_NAME);
        RtlSetProcessIsCritical = (d_RtlSetProcessIsCritical)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlSetProcessIsCritical");
    }
    if(RtlSetProcessIsCritical == NULL) return -1;
    RtlSetProcessIsCritical(critical,0,0);
    return 0;
}
