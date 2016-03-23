//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ZipLib project. Version 1.0
//	
// module: platform.c
// $Revision: 14 $
// $Date: 2014-09-29 20:29:05 +0400 (Пн, 29 сен 2014) $
// description:
//	Win32-specific abstraction definitions.

#ifndef __PLATFORM_H__
#define __PLATFORM_H__

#include "..\common\main.h"
#include "..\common\memalloc.h"

typedef BOOL					PL_BOOLEAN;
typedef WINERROR				PL_ERROR;
typedef short					PL_WCHAR;
typedef char *					PL_VA_LIST;

#define PL_NULL					NULL
#define PL_MAX_PATH				255

#define PL_E_OK					NO_ERROR
#define PL_E_UNDEFINED			ERROR_INVALID_FUNCTION
#define PL_E_MALLOC				ERROR_NOT_ENOUGH_MEMORY
#define PL_E_INVALID_PARAM		ERROR_INVALID_PARAMETER
#define PL_E_NOT_FOUND			ERROR_FILE_NOT_FOUND
#define PL_E_NO_MORE_FILES		ERROR_NO_MORE_FILES
#define PL_E_ACCESS_DENIED		ERROR_ACCESS_DENIED
#define PL_E_FILE_NOT_FOUND		ERROR_FILE_NOT_FOUND
#define PL_E_PATH_NOT_FOUND		ERROR_PATH_NOT_FOUND
#define PL_E_INVALID_HANDLE		ERROR_INVALID_HANDLE
#define PL_E_MINIZ_ZIP			ERROR_BAD_FORMAT
#define	PL_E_WRITE				ERROR_WRITE_FAULT
#define	PL_E_READ				ERROR_READ_FAULT
#define PL_E_SHARING_VIOLATION	ERROR_SHARING_VIOLATION

#define	PL_ASSERT(x)			
#define PL_TRUNCATE				(size_t)-1

typedef struct _PL_DIR_ENTRY {
	PL_BOOLEAN	 IsDir;
	PL_WCHAR FileName[PL_MAX_PATH];	
} PL_DIR_ENTRY, *PPL_DIR_ENTRY;

typedef struct _PL_DIR_ITER {
	void *Handle;
} PL_DIR_ITER, *PPL_DIR_ITER;

typedef struct _PL_FILE {
	void *Handle;
} PL_FILE, *PPL_FILE;


__inline void * PlMemCpy ( void * _Dst, const void * _Src, size_t _Size )
{
	return memcpy(_Dst, _Src, _Size);
}

__inline void *PlMalloc(size_t _Size)
{
	return(AppAlloc((ULONG)_Size));
}

__inline void *PlRealloc(void *_Mem, size_t _Size)
{
	if (_Mem)
		return(AppRealloc(_Mem, (ULONG)_Size));
	else
		return(AppAlloc((ULONG)_Size));
}

__inline void *PlMemSet(void *_Dst, int _Val, size_t _Size) 
{
	return memset(_Dst, _Val, (ULONG)_Size);
}

__inline void PlFree(void *_Memory)
{
	if (_Memory)
		AppFree(_Memory);
}

__inline size_t PlStrLen(const char *str)
{
	return strlen(str);
}

__inline size_t PlWcsLen(const PL_WCHAR *str)
{
	return wcslen(str);
}

__inline int PlWcsnCmp(const PL_WCHAR *str1, const PL_WCHAR *str2, size_t maxCount)
{
	return wcsncmp(str1, str2, maxCount);
}

__inline int PlMemCmp(const void *_Buf1, const void *_Buf2, size_t _Size)
{
	return memcmp(_Buf1, _Buf2, _Size);
}


PL_ERROR PlWideStrToUTF8(PL_WCHAR *Str, char **pResult);

void PlDirEntryInit(PPL_DIR_ENTRY DirEntry);

PL_ERROR PlDirFindFirstFile(PL_WCHAR *Path, PPL_DIR_ENTRY pFirstDirEntry, PPL_DIR_ITER pDirIter);

PL_ERROR PlDirFindNextFile(PPL_DIR_ITER DirIter, PPL_DIR_ENTRY FoundDirEntry);

PL_ERROR PlDirFindClose(PPL_DIR_ITER DirIter);

PL_ERROR PlWideStrSubCopy(PL_WCHAR *Src, size_t pos, size_t extra, PL_WCHAR **pResult);

void PlPathWinToUnixInPlace(PL_WCHAR *Str);


#define PL_FILE_OPEN_ALWAYS		OPEN_ALWAYS
#define PL_FILE_CREATE_ALWAYS	CREATE_ALWAYS
#define PL_FILE_APPEND_DATA		FILE_APPEND_DATA		
#define PL_FILE_GENERIC_WRITE	GENERIC_WRITE
#define PL_FILE_GENERIC_READ	GENERIC_READ

#define PL_FILEPOS_BEGIN		FILE_BEGIN
#define PL_FILEPOS_CURRENT		FILE_CURRENT
#define PL_FILEPOS_END			FILE_END

PL_ERROR PlFileCreate(PPL_FILE File, const PL_WCHAR *Path, ULONG dwDesiredAccess, ULONG dwCreationDisposition);
PL_ERROR PlFileReopen(PPL_FILE File, const PL_WCHAR *FileName, ULONG dwDesiredAccess, ULONG dwCreationDisposition);
PL_ERROR PlFileWrite(PPL_FILE File, const void *Buf, unsigned long Size);
PL_ERROR PlFileAppend(PPL_FILE File, void *Buf, unsigned long Size);
PL_ERROR PlFileRead(PPL_FILE File, void *Buf, unsigned long Size);
PL_ERROR PlFileClose(PPL_FILE File);
PL_BOOLEAN PlFileValid(PPL_FILE File);
PL_BOOLEAN PlFileAtEOF(PPL_FILE File, PL_BOOLEAN *pIsEOF);

PL_ERROR PlFileSeek(PPL_FILE File, __int64 Offset, int MoveMethod, __int64 *pResult);
PL_ERROR PlFileTell(PPL_FILE File, __int64 *pResult);
PL_ERROR PlFileFlush(PPL_FILE File);
PL_ERROR PlFileDelete(const PL_WCHAR *FileName);
PL_BOOLEAN PlFileExists(const PL_WCHAR *FileName);


size_t PlStrLen(const char *str);
size_t PlWcsLen(const PL_WCHAR *str);
int PlWcsnCmp(const PL_WCHAR *str1, const PL_WCHAR *str2, size_t maxCount);
int PlMemCmp(const void *_Buf1, const void *_Buf2, size_t _Size);

int PlVsnPrintf_s(
   char *buffer,
   size_t sizeOfBuffer,
   size_t count,
   const char *format,
   PL_VA_LIST argptr 
);

int PlVsnWPrintf_s(
   PL_WCHAR *buffer,
   size_t sizeOfBuffer,
   size_t count,
   const PL_WCHAR *format,
   PL_VA_LIST argptr 
);

int PlSnWprintf_s(
   PL_WCHAR *buffer,
   size_t sizeOfBuffer,
   size_t count,
   const PL_WCHAR *format,
   ... 
);


#define PL_LOG_ENABLED			FALSE
#define PL_LOG_USE_PRINTF		FALSE
#define PL_LOG_USE_FILE			TRUE
#define PL_LOG_USE_DBG_OUTPUT	FALSE

#define PL_LOG_FILE L"c:\\pl.log"

void PlLogPrintf(char *fmt, ...);

#if PL_LOG_ENABLED
#define PLPRINTF(x)        PlLogPrintf##x
#else
#define PLPRINTF(x)        
#endif

#endif
