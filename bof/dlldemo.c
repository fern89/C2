#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include "beacon.h"

int main(){
    MessageBoxA(NULL, "pwn!", "Pwned", MB_OK);
    BeaconPrints("an epic printer");
    return 0;
}
