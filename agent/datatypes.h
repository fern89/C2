#ifndef DATATYPES_INC
#define DATATYPES_INC
enum Types{
    NUMBER,
    STRING
};
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
typedef struct strstruct{
    unsigned char* data;
    unsigned int len;
} String;
/*int peekType(unsigned char* sp){
    unsigned int sz = 0;
    memcpy(&sz, sp, 4);
    if((sz & 0x80000000) == 0)
        return NUMBER;
    return STRING;
}*/

String popstr(unsigned char** sp){
    String str;
    str.data = NULL;
    str.len = 0;
    unsigned int sz = 0;
    memcpy(&sz, *sp, 4);
    if((sz & (1<<31)) == 0){
        //printf("0x%x\n", sz);
        return str;
    }
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
#endif