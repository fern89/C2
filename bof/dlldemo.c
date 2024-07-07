/*
how to use:
#init
bof_execute file(dlldemo.dll)
server add_cmd MyMsgBox 6969 3 "do a messagebox"

#do messagebox 3 times
MyMsgBox title body 3
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include "beacon.h"
void mymsgbox(unsigned char** sp){
    String title = popstr(sp);
    String body = popstr(sp);
    int n_times = popint(sp);
    for(int i=0;i<n_times;i++)
        MessageBoxA(NULL, body.data, title.data, MB_OK);
    fs(title);
    fs(body);
    BeaconPrints("Done!");
    return;
}
int main(){
    add_fn(&mymsgbox, 6969);
    BeaconPrints("we are living");
    return 0;
}
