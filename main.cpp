/*
 * hlds 3.1.1.1 patch against
 *
 * buffer-overflow vulnerability in info-string handling
 *   and
 * wrong handling of malformed connection request to non-won servers
 *
 * by Virtual Master
 *
 * SV_DownloadURL
 * By NuWON Development 2021
 *
 */
#include "neuwon.h"

/* handle to engine shared object */
void* handle = NULL;

/* remeber that we already told the user about boffix loading */
int firsttime = 0;
// Forward Declaration of hooked functions so we can put the function towards the bottom of the page
void SV_SendResources_Hook();
char MBuffer[32768];

const char* GetFileName(const char *fpath) {
	int sl = strlen(fpath);
	const char *cp = fpath + sl;
	while (size_t(cp) > size_t(fpath)) {
		if (*cp == '\\' || *cp == '/') {
			return cp+1;
		}
		cp--;
	}
	return cp;
}

void* LocateLib(const char* libname) {
	char fname[128];
	char linebuf[512];
	char clib[256];
	const char *clp;
	FILE *fl;
	int sl;
	void* RegStart;
	void* RegEnd;
	Dl_info dli;

	sprintf(fname, "/proc/%d/maps", getpid());
	fl = fopen(fname, "r");
	if (fl == NULL) {
		return NULL;
	}

	setbuffer(fl, MBuffer, sizeof(MBuffer));
	while (fgets(linebuf, sizeof(linebuf), fl)) {
		sl = sscanf(linebuf, "%x-%x %s %s %s %s %s", &RegStart, &RegEnd, fname, fname, fname, fname, clib);
		if (sl != 7) {
			continue;
		}

		if (dladdr(RegStart, &dli) == 0) {
			continue;
		}

		clp = GetFileName(dli.dli_fname);
		if (strcmp(libname, clp) == 0) {
			fclose(fl);
			return dli.dli_fbase;
		}
	}
	fclose(fl);
	return NULL;
}

void getFnPtrs(void)
{
	char *error;
	void* lib;
	char* EngineFileName = NULL;
	char* EngineName = NULL;
	
	lib = LocateLib("engine_i686.so");
	if (lib == NULL) {
		lib = LocateLib("engine_amd.so");
		if (lib == NULL) {
			lib = LocateLib("engine_i486.so");
			if (lib == NULL) {
				return 0;
			} else {
				EngineName 		= "engine_i486.so";
				EngineFileName	= "./engine_i486.so";
			}
		} else {
			EngineName 			= "engine_amd.so";
			EngineFileName 		= "./engine_amd.so";
		}
	} else {
		EngineName 				= "engine_i686.so";
		EngineFileName 			= "./engine_i686.so";
	}
	
	if ( !handle )
		handle							= 								dlopen(EngineFileName, RTLD_NOW);
	if ( !origSV_ConnectClient )
		origSV_ConnectClient			= (torigSV_ConnectClient)		dlsym (handle, "SV_ConnectClient");
	if ( !origCmd_Argc )
		origCmd_Argc					= (torigCmd_Argc)				dlsym (handle, "Cmd_Argc");
	if ( !origCmd_Argv )
		origCmd_Argv					= (torigCmd_Argv)				dlsym (handle, "Cmd_Argv");
	if ( !origSV_RejectConnection )
		origSV_RejectConnection			= (torigSV_RejectConnection)	dlsym (handle, "SV_RejectConnection");
	if ( !origServerPrint )
		origServerPrint					= (torigServerPrint)			dlsym (handle, "ServerPrint");
	if ( !origCon_Init )
		origCon_Init					= (torigCon_Init)				dlsym (handle, "Con_Init");
	if ( !origAlertMessage )
		origAlertMessage				= (torigAlertMessage)			dlsym (handle, "AlertMessage");
	if ( !orig_ValueForKey )
		orig_ValueForKey				= (toriginfo_ValueForKey)		dlsym (handle, "Info_ValueForKey");
	if ( !orig_SetValueForKey )
		orig_SetValueForKey				= (torigInfo_SetValueForKey)	dlsym (handle, "Info_SetValueForKey");
	if ( !orig_RemoveKey )
		orig_RemoveKey					= (toriginfo_RemoveKey)			dlsym (handle, "Info_RemoveKey");
	if ( !origSV_SendResources )
		origSV_SendResources			= (torigSV_SendResources)		dlsym (handle, "SV_SendResources");
	if ( !origCvar_RegisterVariable )
		origCvar_RegisterVariable		= (Cvar_RegisterVariable_orig)	dlsym (handle, "Cvar_RegisterVariable");
	if ( !origMSG_WriteByte )
		origMSG_WriteByte				= (torigWritebyte)				dlsym (handle, "MSG_WriteByte");
	if ( !origMSG_WriteString )
		origMSG_WriteString				= (torigWritestring)			dlsym (handle, "MSG_WriteString");
	if ( !origMSG_WriteLong )
		origMSG_WriteLong				= (torigWritelong)				dlsym (handle, "MSG_WriteLong");

	//uint32_t *pSym =(uint32_t) dlsym(handle, "svs");
	if ( (error = dlerror()) != NULL ) {
		fprintf(stderr, "%s\n", error);
		exit(1);
	}

	origCvar_RegisterVariable(downloadurl);
	origCvar_RegisterVariable(AllowFragDL);
	
	placeJMP((BYTE*)(origSV_SendResources + 0x53), (DWORD)SV_SendResources_Hook, 6); //send download url if available
	//HookFunction( (void*) DSEngineData.CheckProto_haddr, (void*) &CheckProtocol_AsmHelper_LDyn);
}
/*
  SV_SendResources+53                   push    eax
  SV_SendResources+54                   call    _MSG_WriteLong  ; Call Procedure
  SV_SendResources+59   ; 11:   MSG_WriteByte(a1, 43);
  SV_SendResources+59                   add     esp, 20h        ; Add
*/

int a1;
DWORD ResHook_Ret_Addr = *(DWORD*)origSV_SendResources + 0x59;
__declspec(naked) void SV_SendResources_Hook() 
{	
	
	__asm
	{ 
	//	pushad
		push eax
		call  origMSG_WriteLong
		mov a1, eax
	}
	if (downloadurl.string)
	{	
		origMSG_WriteByte(&a1, 56);
		origMSG_WriteString(&a1, downloadurl.string);
	}
	__asm
	{
	//	popad
		jmp [ResHook_Ret_Addr]
	}
}

void Con_Init(void)
{
	getFnPtrs();

	if (firsttime == 0)
    {
		/* Tell user about successful hooking */
	//	origServerPrint("\nNeuWON Server Module Loaded Successfully\n);
		origServerPrint("\nNeuWON [Linux] Server Module Successfully Loaded.\n");
		firsttime = 1;
	}


}

void SV_ConnectClient(void)
{
	int argc = 0;
	char* argv[128];

	unsigned int netfrom[5], *pnetfrom;

	int i=0;

	getFnPtrs();
	pnetfrom = (unsigned int*) dlsym (handle, "net_from");
	
	// copy net_from structure required for SV_RejectConnection
	for (i=5; i>0; i--)
	{
		netfrom[5-i] = *(pnetfrom++);
	}

	argc = origCmd_Argc();
	/* Left for debug purposes...
	printf("netfrom: 0x%x 0x%x 0x%x 0x%x 0x%x\n", netfrom[0], netfrom[1], netfrom[2], netfrom[3], netfrom[4]);
	printf("Argument count: %d\n", argc); */
	
	argc = (argc < 128) ? argc : 127;
	
	for (i=1; i<argc; i++) {
		argv[i] = origCmd_Argv(i);
	}
	fflush(stdout);


	if (isValid(argv[3]) && isValid(argv[4])) {
		origSV_ConnectClient();
	}
	else {
		/* Tell console about reject... might be removed later */
		origServerPrint("Invalid userinfo in connect command, dropping connection attempt\n");
		/* Log address */
		//origAlertMessage(at_logged, "boffix: Possible overflow attack from %s\n",  inet_ntoa(netfrom[1]));
		/* Reject that connection */
		origSV_RejectConnection(netfrom, "Invalid userinfo in connect command", 0x3ff);
	}

}
