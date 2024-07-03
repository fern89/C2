# C2
## About
A simple C2 framework. Made in pure C for agent, Python for teamserver, web UI for clients.

Main panel:
![image](https://github.com/fern89/C2/assets/139056562/6de6d91e-4a50-41a5-8624-0b0500601e84)

Screenshare:
![image](https://github.com/fern89/C2/assets/139056562/7ed0d20d-8136-4c30-b4e0-8022051995cf)

HVNC example:
![image](https://github.com/fern89/C2/assets/139056562/d767750d-70af-49a7-8980-4eb1f15ee695)


## Features
- Scriptable
- Beacon object files
- Usermode unhooking
- Modular C2
- Traffic encryption
- Screenshare support
- HVNC
- SOCK5 proxy
- Process migration
- Revive on crash
- Privilege escalation

## Compilation
Designed to compile with the mingw GCC Compiler. Compile agent with `x86_64-w64-mingw32-gcc client/main.c -s -Os -lws2_32 -lwininet -m64 -luser32  -lgdi32 -lole32 -lshlwapi -ladvapi32 -o main.exe`, sample BOF with `x86_64-w64-mingw32-gcc bof/dlldemo.c -shared -o dlldemo.dll -m64`, run server with `python3 server/server.py`

## Scripting
Sample script:
```
unhook
sandbox
print "test" -> popint
bof_execute file(dlldemo.dll)
shc_inject_apc "C:\Windows\System32\notepad.exe" hex([hex]) FALSE
print "asdf"
exec "echo \"lorem ipsum dolor sit\""
msgbox "title" "data \"big data\""
exec "dir"
sleep 3000
exec "whoami"
swap_c2 socks 127.0.0.1 6968 1000
```

## Future plans
- Add more documentation
- Add more C2 (will add discord c2 soon)
- Add more commands
- Add persistence
- Make stager/shellcode
- Add agent builder UI
