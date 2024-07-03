#ifndef DESKTOPS_INCL
#define DESKTOPS_INCL
#include <stdio.h>
#include <windows.h>
char current_dsk[MAX_PATH] = {0};
char* desktops[30] = {0};

BOOL setWinSta(const char* sta){
    return SetProcessWindowStation(OpenWindowStationA(sta, FALSE, WINSTA_ALL_ACCESS));
}
BOOL setThdDsk(){
    return SetThreadDesktop(OpenDesktopA(current_dsk, 0, FALSE, GENERIC_ALL));
}
void getcurrdesktop(){
    memset(current_dsk, 0, MAX_PATH);
    GetUserObjectInformationA(GetProcessWindowStation(), UOI_NAME, current_dsk, MAX_PATH, NULL);
    current_dsk[strlen(current_dsk)] = '\\';
    GetUserObjectInformationA(GetThreadDesktop(GetCurrentThreadId()), UOI_NAME, current_dsk+strlen(current_dsk), MAX_PATH, NULL);
}
static BOOL CALLBACK edp(LPTSTR nm, LPARAM sta){
    int i = 0;
    while(desktops[i]!=0) i++;
    desktops[i] = calloc(MAX_PATH, 1);
    sprintf(desktops[i], "%s\\%s", sta, nm);
}
static BOOL CALLBACK ewsp(LPTSTR sta, LPARAM lparam){
    HWINSTA hwin = OpenWindowStationA(sta, FALSE, WINSTA_ENUMDESKTOPS);
    EnumDesktopsA(hwin, (DESKTOPENUMPROCA)&edp, (unsigned long long)sta);
}
static void cleandesktops(){
    for(int i=0;i<(sizeof(desktops)/sizeof(char*));i++){
        if(desktops[i]!=0){
            free(desktops[i]);
            desktops[i] = 0;
        }
    }
}
int getdesktops(){
    cleandesktops();
    EnumWindowStationsA((WINSTAENUMPROCA)&ewsp, 0);
    Sleep(100);
    return 0;
}
#endif