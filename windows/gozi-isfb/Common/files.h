//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ISFB project. Version 2.13.24.1
//	
// module: files.h
// $Revision: 407 $
// $Date: 2014-11-21 21:23:30 +0300 (Пт, 21 ноя 2014) $
// description:
//	CRM client dll. Files manipulation functions. 


#define	CRC_DIRECTORY				0xa2a84f43
#define	FILES_SCAN_SUBDIRECTORIES	1

#define	FFFLAG_RECURSIVE			0x1 // recursive search
#define	FFFLAG_SEARCH_FOLDERS		0x2 // search folders
#define	FFFLAG_SEARCH_FILES			0x4  // search files

typedef struct _FILE_DESCW
{
	LIST_ENTRY	Entry;
	HANDLE		Handle;
	ULONG		Flags;
	ULONG		Type;
	ULONG		TypeOffset;
	ULONG		SearchPathLen;	// length, in chars, of the initial path used to search files
	WCHAR		Path[0];
} FILE_DESCW, *PFILE_DESCW;


// Save file flags
#define	FILE_FLAG_OVERWRITE			1	// overwrite an existing file
#define	FILE_FLAG_APPEND			2	// append an existing file
#define	FILE_FLAG_WAIT_SHARE		4	// wait until a file could be shared


// Functions defined within FILES.C
PFILE_DESCW FileDescAlloc(ULONG Length);

ULONG	FilesScanW(PWCHAR Path, PWCHAR Mask, PLIST_ENTRY FilesList, PCRITICAL_SECTION FilesListLock, ULONG SearchPathLen, ULONG	SearchFlags);
ULONG	FilesScanA(PCHAR Path, PCHAR Mask, PLIST_ENTRY FilesList, PCRITICAL_SECTION FilesListLock, ULONG SearchPathLen, ULONG	SearchFlags);

LPSTR	FilesExpandEnvironmentVariablesA(LPSTR Path);
LPWSTR	FilesExpandEnvironmentVariablesW(LPWSTR Path);
LPWSTR	FilesExpandEnvironmentVariablesAtoW(LPSTR Path);

BOOL	FilesPathCombineW(LPWSTR dest, const LPWSTR dir, const LPWSTR file);
BOOL	FilesPathCombineA(LPSTR dest, const LPSTR dir, const LPSTR file);
DWORD	FileReadStringA(HANDLE hFile, LPSTR Buffer, DWORD Length);
DWORD	FileReadStringW(HANDLE hFile, LPWSTR Buffer, DWORD Length);
WINERROR FilesLoadFileA(LPSTR FileName, PCHAR* pBuffer, PULONG pSize);
WINERROR FilesSaveFileA(LPSTR FileName, PCHAR Buffer, ULONG Size, ULONG Flags);

WINERROR FilesClearDirectoryA(LPSTR DirPath, BOOL bClearSubfolders, BOOL bIgnoreErrors);
WINERROR FilesDeleteFile(LPTSTR pFilePath);
WINERROR FilesCreateDirectoryA(LPSTR pDirPath);
LPTSTR	FilesGetTempFile(ULONG Seed);

BOOL FilesIsDotsNameW(LPWSTR name);
BOOL FilesIsDotsNameA(LPWSTR name);


#if _UNICODE
	#define	FilesExpandEnvironmentVariables(x)	FilesExpandEnvironmentVariablesW(x)
	#define	FilesPathCombine	FilesPathCombineW
	#define	FilesIsDotsName		FilesIsDotsNameW
	#define	FileReadString		FileReadStringW
	#define	FilesScan			FilesScanW
	#define	FilesLoadFile		FilesLoadFileW
	#define	FilesSaveFile		FilesSaveFileW
	#define	FilesCreateDirectory	FilesCreateDirectoryW
	#define FilesClearDirectory		FilesClearDirectoryW
#else
	#define	FilesExpandEnvironmentVariables(x)	FilesExpandEnvironmentVariablesA(x)
	#define	FilesPathCombine	FilesPathCombineA
	#define	FilesIsDotsName		FilesIsDotsNameA
	#define	FileReadString		FileReadStringA
	#define	FilesScan			FilesScanA
	#define	FilesLoadFile		FilesLoadFileA
	#define	FilesSaveFile		FilesSaveFileA
	#define	FilesCreateDirectory	FilesCreateDirectoryA
	#define	FilesClearDirectory		FilesClearDirectoryA
#endif


DWORD FileReadStringExW(HANDLE hFile, LPWSTR Buffer, DWORD Length, LPWSTR Delimiters );

// file search
// search proc
typedef ULONG (FINDFILEPROC)(const LPWSTR path, const WIN32_FIND_DATAW *fileInfo, void *data);

VOID FilesScanExW(
	LPWSTR	path, 
	const LPWSTR *fileMasks, 
	LONG	fileMasksCount, 
	DWORD	flags, 
	FINDFILEPROC findFileProc, 
	void	*data, 
	HANDLE	stopEvent, 
	DWORD	subfolderDelay, 
	DWORD	foundedDelay
	);

BOOL FilePathCombineW(LPWSTR dest, const LPWSTR dir, const LPWSTR file);

// returns TRUE if file exists on filesystem
BOOL FileExistsW(IN LPWSTR FIleName);
BOOL FileExistsA(IN LPSTR FIleName);