#ifndef utilities_h__
#define utilities_h__


#include <stdlib.h>
#include <dlfcn.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>


typedef int qboolean;
typedef int BOOL;
typedef unsigned short WORD;
typedef unsigned short word;
typedef unsigned int UNINT32;
typedef unsigned int uint32_t;
typedef unsigned short uint16_t;
typedef unsigned char uint8_t;
typedef unsigned long DWORD;
typedef unsigned char BYTE;
typedef unsigned char byte;
typedef unsigned long ULONG;

typedef char int8;
typedef unsigned char uint8;
typedef short int16;
typedef unsigned short uint16;
typedef int int32;
typedef unsigned int uint32;
typedef long long int64;
typedef unsigned long long uint64;

int isValid(char *info);
#endif // utilities_h__