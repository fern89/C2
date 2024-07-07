#ifndef CRYPT_INCLUDED
#define CRYPT_INCLUDED
void xor(unsigned char* data, int sz){
    for(int i=0;i<sz;i++)
        data[i] ^= 0x68;
}
#endif