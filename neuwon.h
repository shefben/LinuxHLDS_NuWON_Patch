#ifndef neuwon_h__
#define neuwon_h__


#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <linux/net.h> 
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <elf.h>
#include <limits.h>
#include <time.h>
#include <unistd.h>
#include "utilities.h"
#include "hook_utils.h"


#ifndef PAGESIZE
#define PAGESIZE 4096
#endif
#define	FCVAR_ARCHIVE		(1<<0)	// set to cause it to be saved to vars.rc
#define	FCVAR_USERINFO		(1<<1)	// changes the client's info string
#define	FCVAR_SERVER		(1<<2)	// notifies players when changed
#define FCVAR_EXTDLL		(1<<3)	// defined by external DLL
#define FCVAR_CLIENTDLL     (1<<4)  // defined by the client dll
#define FCVAR_PROTECTED     (1<<5)  // It's a server cvar, but we don't send the data since it's a password, etc.  Sends 1 if it's not bland/zero, 0 otherwise as value
#define FCVAR_SPONLY        (1<<6)  // This cvar cannot be changed by clients connected to a multiplayer server.
#define FCVAR_PRINTABLEONLY (1<<7)  // This cvar's string cannot contain unprintable characters ( e.g., used for player name etc ).
#define FCVAR_UNLOGGED		(1<<8)  // If this is a FCVAR_SERVER, don't log changes to the log file / console if we are creating a log


enum ALERT_TYPE 
{ 
at_notice,
at_console,	// same as at_notice, but forces a ConPrintf, not a message box
at_aiconsole,	// same as at_console, but only shown if developer level is 2!
at_warning,
at_error,
at_logged 
};

typedef struct cvar_s {
		char	*name;
		char	*string;
		int		flags;
		float	value;
		struct cvar_s *next;
	} cvar_t;

typedef struct sizebuf_s {
		const char *buffername;
		uint16 flags;
		byte *data;
		int maxsize;
		int cursize;
	} sizebuf_t;

struct net_message_t {
		int field_0;
		int field_4;
		int *buffer;
		int field_C;
		int msg_len;
	};

struct svs_t {
		int field_0;
		int *clients;
		int max_clients;
		int field_C;
	};
static cvar_t downloadurl = { "sv_downloadurl", "", FCVAR_SPONLY};// "Location from which clients can download missing files"};
static cvar_t AllowFragDL = { "sv_allow_frag_dl", "1", FCVAR_SPONLY};// "Location from which clients can download missing files"};

/* function-pointers for engine-functions */
typedef int(*torigWritelong)(int *, int); //int __cdecl MSG_WriteLong(int a1, int a2);
torigWritelong origMSG_WriteLong = NULL;
typedef char* (*torigWritebyte)(int *, char); //int __cdecl MSG_WriteByte(int a1, char a2)
torigWritebyte origMSG_WriteByte = NULL;
typedef int(*torigWritestring)(int *, const char*); //int __cdecl MSG_WriteString(int a1, void *src)
torigWritestring origMSG_WriteString = NULL;

typedef void (*torigSV_SendResources)(int*);
torigSV_SendResources origSV_SendResources = NULL;
typedef void(*torigSV_ConnectClient)(void);
torigSV_ConnectClient origSV_ConnectClient = NULL;
typedef int(*torigCmd_Argc)(void);
torigCmd_Argc origCmd_Argc = NULL;
typedef char*(*torigCmd_Argv)(int);
torigCmd_Argv origCmd_Argv = NULL;
typedef void(*torigSV_RejectConnection)(unsigned int[5], char*, unsigned int);
torigSV_RejectConnection origSV_RejectConnection = NULL;
typedef void(*torigServerPrint)(const char*);
torigServerPrint origServerPrint = NULL;
typedef void(*torigCon_Init)(void);
torigCon_Init origCon_Init = NULL;
typedef void(*torigAlertMessage)(ALERT_TYPE, char *szFmt, ...);
torigAlertMessage origAlertMessage = NULL;
typedef char(*toriginfo_ValueForKey)(const char, const char);
toriginfo_ValueForKey orig_ValueForKey = NULL;
typedef void(*torigInfo_SetValueForKey)(char, const char, const char, int);
torigInfo_SetValueForKey orig_SetValueForKey = NULL;
typedef void(*toriginfo_RemoveKey)(char, const char);
toriginfo_RemoveKey orig_RemoveKey = NULL;
typedef int(*Cvar_RegisterVariable_orig)(cvar_t a2);
Cvar_RegisterVariable_orig origCvar_RegisterVariable = NULL;
/*
typedef int (*SV_ParseResourceList_orig)(void);
SV_ParseResourceList_orig SV_ParseResourceList;
typedef void*(*torigSZ_GetSpace)(sizebuf_t *,int);
torigSZ_GetSpace origSZ_GetSpace;
typedef void*(*torigQ_memset)(void*,int,size_t);
torigQ_memset origQ_memset;
typedef signed int(*torigQ_memcmp)(DWORD,DWORD,signed int);
torigQ_memcmp origQ_memcmp;
typedef int (*SV_Parsefileconsistency_orig)(void);
SV_Parsefileconsistency_orig SV_Parsefileconsistency;
typedef int (*SV_SendConsistencyList_orig)(void);
SV_SendConsistencyList_orig origSV_SendConsistencyList;
//////////////////////////////////////////////////////////////////////////
//message write functions
typedef int (*MSG_StartBitWriting_orig)(int *);
MSG_StartBitWriting_orig origMSG_StartBitWriting;
typedef int (*MSG_EndBitWriting_orig)(int *);
MSG_EndBitWriting_orig origMSG_EndBitWriting;
typedef char* (*torigReadstring)(void);
torigReadstring origMSG_ReadString;
typedef int(*torigReadlong)(void);
torigReadlong origMSG_ReadLong;


typedef DWORD* (*MSG_WriteBits_orig)(unsigned int, int);
MSG_WriteBits_orig origMSG_WriteBits;
typedef DWORD* (*MSG_WriteBitString_orig)(const char*);
MSG_WriteBitString_orig origMSG_WriteBitString;
typedef int (*MSG_WriteBitData_orig)(void*, int);
MSG_WriteBitData_orig origMSG_WriteBitData;

*/
#endif // neuwon_h__