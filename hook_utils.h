#ifndef hook_utils_h__
#define hook_utils_h__

#include <sys/mman.h>

#include "utilities.h"
/*
void* detour_func(unsigned char* src, const unsigned char* dst, const int len);

void PatchNOPs(void* OrigAddr, int Cnt);
unsigned int HookFunction_call(void *OrigAddr, void* NewAddr);
unsigned int HookDWord(uint32_t *OrigAddr, uint32_t NewDWord);*/
bool MProtect_Ex(void *addr, int npages);
unsigned int HookFunction(void *OrigAddr, void* NewAddr);
void placeJMP(BYTE *pAddress, DWORD dwJumpTo, DWORD dwLen);
#endif // hook_utils_h__