#ifndef SANDBOX_INCL
#define SANDBOX_INCL
#include <windows.h>
#include <stdio.h>
#include <math.h>
#define THRESHOLD 5.0
#define ITERATIONS 1000000
static int notdone;
static long long c;
static DWORD WINAPI fp(void* data) {
    while(notdone){
        for(int i=0;i<10;i++) asm(".byte 0xd9\n\t.byte 0xf9"); //FYL2XP1
        c++;
    }
    return 0;
}

void sanddetect(char* output){
    notdone=1;
    c=0;
    HANDLE thread = CreateThread(NULL, 0, fp, NULL, 0, NULL);
    for(int i=0;i<ITERATIONS;i++) asm("push %rax\n\tpush %rbx\n\tpush %rcx\n\tpush %rdx\n\txor %rax, %rax\n\t.byte 0x0f\n\t.byte 0xa2\n\tpop %rdx\n\tpop %rcx\n\tpop %rbx\n\tpop %rax"); //CPUID
    notdone=0;
    WaitForSingleObject(thread, INFINITE);
    c*=10;
    double ration = ((double)c)/((double)ITERATIONS);
    double fscore = ((tanh(ration-THRESHOLD)+1)/2)*100;
    sprintf(output, "count=%lld, ratio=%f\n%f%% confident sandbox", c, ration, fscore);
}
#endif