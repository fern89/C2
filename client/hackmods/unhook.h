#ifndef UNHOOK_INCL
#define UNHOOK_INCL
#include <stdio.h>
#include <windows.h>
static char* names[10000]={0};
static void* ptrs[10000] = {0};
static int totalFns=0;
static unsigned long long int rop = 0;
static void bubbleSort(long long int arr[], char* nm[], int n){ 
    int i, j; 
    for (i = 0; i < n - 1; i++){
        for (j = 0; j < n - i - 1; j++){
            if (arr[j] > arr[j + 1]){
                long long int tmp = arr[j];
                arr[j]=arr[j+1];
                arr[j+1]=tmp;
                char* tmp2 = nm[j];
                nm[j]=nm[j+1];
                nm[j+1]=tmp2;
            }
        }
    }
}

static int hunt(){
    long long int ps[10000]={0};
    HMODULE peBase = GetModuleHandleA("ntdll.dll");
    PIMAGE_DOS_HEADER imageDosHeader = (PIMAGE_DOS_HEADER)peBase;
    PIMAGE_NT_HEADERS imageNtHeaders = (PIMAGE_NT_HEADERS)((unsigned char*)imageDosHeader + imageDosHeader->e_lfanew);
    PIMAGE_OPTIONAL_HEADER imageOptionalHeader = (PIMAGE_OPTIONAL_HEADER)&imageNtHeaders->OptionalHeader;
    PIMAGE_DATA_DIRECTORY imageExportDataDirectory = &(imageOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
    PIMAGE_EXPORT_DIRECTORY imageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((unsigned char*)peBase + imageExportDataDirectory->VirtualAddress);
    DWORD numberOfNames = imageExportDirectory->NumberOfNames;
    PDWORD exportAddressTable = (PDWORD)((unsigned char*)peBase + imageExportDirectory->AddressOfFunctions);
    PWORD nameOrdinalsPointer = (PWORD)((unsigned char*)peBase + imageExportDirectory->AddressOfNameOrdinals);
    PDWORD exportNamePointerTable = (PDWORD)((unsigned char*)peBase + imageExportDirectory->AddressOfNames);
    int c=0;
    int nameIndex = 0;
    for (nameIndex = 0; nameIndex < numberOfNames; nameIndex++){
        char* name = (char*)((unsigned char*)peBase + exportNamePointerTable[nameIndex]);
        if(memcmp(name, "Nt", 2)==0 && memcmp(name, "Ntdll", 5)!=0 && strcmp(name, "NtGetTickCount")!=0){
            WORD ordinal = nameOrdinalsPointer[nameIndex];
            unsigned char* targetFunctionAddress = ((unsigned char*)peBase + exportAddressTable[ordinal]);
            ps[c] = (long long int)targetFunctionAddress;
            names[c] = calloc(strlen(name)+1,1);
            strcpy(names[c], name);
            c++;
        }
    }
    bubbleSort(ps, names, c);
    totalFns=c;
    //now rophunt
    unsigned char* va = (unsigned char*)ps[0];
    unsigned char* vmax = (unsigned char*)ps[c-1];
    while (va <= vmax && (va[0]!='\x0f' || memcmp(va, "\x0f\x05\xc3", 3)!=0)) va++;
    if (va!=vmax) rop = (unsigned long long int)va;
    return 0;
}
static int getSysId(const char* name){
    for(int i=0;i<totalFns;i++)
        if(strcmp(name, names[i])==0) return i;
    return -1;
}

static void generate(){
    hunt();
    char code[] = {0x49, 0x89, 0xCA, 0x48, 0xB9, 0xEF, 0xBE, 0xAD, 0xDE, 0xEF, 0xBE, 0xAD, 0xDE, 0xB8, 0x78, 0x56, 0x34, 0x12, 0xFF, 0xE1};
    memcpy(code+5, &rop, 8);
    unsigned char* array = VirtualAlloc(NULL, totalFns*sizeof(code), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    for(unsigned int i=0;i<totalFns;i++){
        memcpy(code+14, &i, 4);
        memcpy(array+(sizeof(code)*i), code, sizeof(code));
        ptrs[i] = array+(sizeof(code)*i);
    }
    DWORD old;
    VirtualProtect(array, totalFns*sizeof(code), PAGE_EXECUTE_READ, &old);
}
int unhook(){
    generate();
    //kernel32.dll actually calls down to kernelbase.dll. unhooking kernel32.dll's IAT is fully ineffective.
    LPVOID imageBase = GetModuleHandleA("kernelbase.dll");
    PIMAGE_DOS_HEADER dosHeaders = (PIMAGE_DOS_HEADER)imageBase;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)imageBase + dosHeaders->e_lfanew);

    PIMAGE_IMPORT_DESCRIPTOR importDescriptor = NULL;
    IMAGE_DATA_DIRECTORY importsDirectory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(importsDirectory.VirtualAddress + (DWORD_PTR)imageBase);
    LPCSTR libraryName = NULL;
    PIMAGE_IMPORT_BY_NAME functionName = NULL; 
    while (importDescriptor->Name){
        libraryName = (LPCSTR)(importDescriptor->Name + imageBase);
        if(strcmp(libraryName, "ntdll.dll")==0)
            break;
        importDescriptor++;
    }
    PIMAGE_THUNK_DATA originalFirstThunk = NULL, firstThunk = NULL;
    originalFirstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)imageBase + importDescriptor->OriginalFirstThunk);
    firstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)imageBase + importDescriptor->FirstThunk);
    PIMAGE_THUNK_DATA bft = originalFirstThunk;
    while (bft->u1.AddressOfData) bft++;
    DWORD oldProtect = 0;
    LPVOID ft = (LPVOID)(&firstThunk->u1.Function);
    size_t sz = sizeof(void*) * (unsigned long long)(bft-originalFirstThunk);
    VirtualProtect((LPVOID)(&firstThunk->u1.Function), sz, PAGE_READWRITE, &oldProtect);
    while (originalFirstThunk->u1.AddressOfData){
        functionName = (PIMAGE_IMPORT_BY_NAME)(imageBase + (unsigned int)originalFirstThunk->u1.AddressOfData);
        char* name = functionName->Name;
        if (memcmp(name, "Nt", 2)==0 && memcmp(name, "Ntdll", 5)!=0){
            int syscall = getSysId(name);
            if(syscall!=-1)
                firstThunk->u1.Function = (DWORD_PTR)(ptrs[syscall]);
        }
        ++originalFirstThunk;
        ++firstThunk;
    }
    VirtualProtect((LPVOID)(&firstThunk->u1.Function), sz, oldProtect, &oldProtect);
    for(int i=0;i<10000;i++){
        if(names[i] == NULL) break;
        free(names[i]);
        names[i] = NULL;
    }
    memset(ptrs, 0, sizeof(ptrs));
}
#endif