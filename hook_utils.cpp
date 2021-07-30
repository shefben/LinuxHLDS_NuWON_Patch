#include <sys/mman.h>
#include "hook_utils.h"

#pragma push()
#pragma pack(1)
struct FuncHook2_s {
	unsigned char _jmp; //e9
	int addr;
	};
#pragma pop()
	/*
void *detour_x86(void* org, void* new, int size)
	{
	unsigned long mask = ~(sysconf(_SC_PAGESIZE) - 1); // platform independant, 0xE9 however is not.
	unsigned long page = (unsigned long)org & mask;
	
	mprotect((void*)page, 5, PROT_READ|PROT_WRITE|PROT_EXEC);
	
	unsigned long jmprel = (unsigned long)new - (unsigned long)org - 5;
	
	unsigned char* gateway = malloc(size + 5);
	unsigned long page2 = (unsigned long)gateway & mask;
	
	mprotect((void*)page2, 5 + size, PROT_READ|PROT_WRITE|PROT_EXEC);
	
	memcpy(gateway, org, size);
	gateway[size] = 0xE9;
	*(unsigned long*)(gateway+size+1) = (unsigned long)(org+size) - (unsigned long)(gateway + size) - 5;
	
	unsigned char* p = (unsigned char*)org;
	p[0] = 0xE9;
	*(unsigned long*)(p+1) = jmprel;
	
	return gateway; // make sure you free() this when closing
	}

//Credits to h1web
//======================================================================
void* detour_func(unsigned char* src, const unsigned char* dst, const int len)
	{
	unsigned char* jmp = (unsigned char*)malloc(len+5);
	if (!jmp) return 0;
	
	unsigned long mask = ~(sysconf(_SC_PAGESIZE)-1);
	unsigned long page = (unsigned long)src & mask;
	
	mprotect((void*)page, len, PROT_READ|PROT_WRITE|PROT_EXEC);
	
	memcpy(jmp, src, len); 
	
	jmp += len;
	
	jmp[0] = 0xE9;
	*(unsigned long*)(jmp+1) = (unsigned long)(src+len - jmp) - 5;
	
	src[0] = 0xE9;
	*(unsigned long*)(src+1) = (unsigned long)(dst - src) - 5;	
	
	
	return (jmp-len);
	}
//======================================================================
*/
	#define PAGESIZE 4096
bool MProtect_Ex(void *addr, int npages) {
	void *paddr;
	paddr = (void *)(((size_t)addr) & ~(PAGESIZE-1));
	return !mprotect(paddr, PAGESIZE*(npages+1), PROT_READ | PROT_WRITE | PROT_EXEC);
	}

unsigned int HookFunction(void *OrigAddr, void* NewAddr) {
	FuncHook2_s* hook = (FuncHook2_s*) OrigAddr;
	unsigned int OrigVal = *((unsigned int*)OrigAddr);
	MProtect_Ex(OrigAddr, 1);
	hook->_jmp = 0xe9;
	hook->addr = (int)NewAddr - (int)OrigAddr - 5;
	return OrigVal;
	}
/*
unsigned int HookFunction_call(void *OrigAddr, void* NewAddr) {
	FuncHook2_s* hook = (FuncHook2_s*) OrigAddr;
	unsigned int OrigVal = *((unsigned int*)OrigAddr);
	MProtect_Ex(OrigAddr, 1);
	hook->_jmp = 0xe8;
	hook->addr = (int)NewAddr - (int)OrigAddr - 5;
	return OrigVal;
	}

unsigned int HookDWord(uint32_t *OrigAddr, uint32_t NewDWord) {
	unsigned int OrigVal = (unsigned int)*OrigAddr;
	MProtect_Ex(OrigAddr, 1);
	return OrigVal;
	}

void PatchNOPs(void* OrigAddr, int Cnt) {
	MProtect_Ex(OrigAddr, 1);
	memset(OrigAddr, 0x90, Cnt);
}
 //PatchJMP Is the same as placeJMP with the exception that it uses memset. I dont know which is better
void PatchJMP(DWORD* pAddress,DWORD dwJumpTo, DWORD dwLen) {
	DWORD dwRelAddr;
	MProtect_Ex(*pAddress, 1);
	dwRelAddr = (DWORD) (dwJumpTo - (DWORD) pAddress) - 5;    
	//*pAddress = 0xE9;
	memset(pAddress, 0xE9, 1);

	// Write the offset to where we're gonna jump
	//*((DWORD *)(pAddress + 0x1)) = dwRelAddr; 
	memset(pAddress + 0x1, dwRelAddr, 4);
	// Overwrite the rest of the bytes with NOPs
	for(DWORD x = 0x5; x < dwLen; x++)
		memset(pAddress + x,0x90,1); 
	}

//USE HOOKFUNCTION()!
*/
void placeJMP(BYTE *pAddress, DWORD dwJumpTo, DWORD dwLen)
	{
	DWORD dwRelAddr;
	
	MProtect_Ex(pAddress, 1);
    
	// Calculate the "distance" we're gonna have to jump - the size of the JMP instruction
	dwRelAddr = (DWORD) (dwJumpTo - (DWORD) pAddress) - 5;    
	
	// Write the JMP opcode @ our jump position...
	*pAddress = 0xE9;
	
	// Write the offset to where we're gonna jump
	*((DWORD *)(pAddress + 0x1)) = dwRelAddr; 
	
	// Overwrite the rest of the bytes with NOPs
	for(DWORD x = 0x5; x < dwLen; x++)
		*(pAddress + x) = 0x90; 
}