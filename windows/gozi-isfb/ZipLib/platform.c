//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ZipLib project. Version 1.0
//	
// module: platform.c
// $Revision: 14 $
// $Date: 2014-09-29 20:29:05 +0400 (Пн, 29 сен 2014) $
// description:
//	Win32-specific abstractions.

#include "platform.h"

#if _DEBUG	/* Just for memory leaks detection */
#define _CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h>
#endif

//#include <Windows.h>
//#include <tchar.h>
//#include <stdio.h>
//#include <stdlib.h>
//#include <stdarg.h>

#include "..\common\main.h"
#include "..\common\memalloc.h"

int PlVsnPrintf_s(
   char *buffer,
   size_t sizeOfBuffer,
   size_t count,
   const char *format,
   PL_VA_LIST argptr 
)
{
	UNREFERENCED_PARAMETER(sizeOfBuffer);
	return _vsnprintf(buffer, count, format, argptr);
}


int PlVsnWPrintf_s(
   PL_WCHAR *buffer,
   size_t sizeOfBuffer,
   size_t count,
   const PL_WCHAR *format,
   PL_VA_LIST argptr 
)
{
	UNREFERENCED_PARAMETER(sizeOfBuffer);
	return _vsnwprintf(buffer, count, format, argptr);
}

int PlSnWprintf_s(
   PL_WCHAR *buffer,
   size_t sizeOfBuffer,
   size_t count,
   const PL_WCHAR *format,
   ... 
)
{
	int res;
	va_list args;
	va_start(args, format);
	res = PlVsnWPrintf_s(buffer, sizeOfBuffer, count, format, args);
	va_end(args);
	return res;
}


PL_ERROR PlWideStrToUTF8(PL_WCHAR *Str, char **pResult)
{
	char *output = NULL;
	int output_len = WideCharToMultiByte(CP_UTF8, 0, Str, -1, NULL, 0, NULL, NULL);

	if (output_len == 0) 
	{
		return(GetLastError());
	}

	output = PlMalloc(output_len*sizeof(char));
	if (!output) {
		return PL_E_MALLOC;
	}

	if (output_len != WideCharToMultiByte(CP_UTF8, 0, Str, -1, output, output_len, NULL, NULL)) 
	{
		PL_ERROR Err = GetLastError();
		PlFree(output);
		return(Err);
	}

	*pResult = output;

	return PL_E_OK;
}

void PlDirEntryInit(PPL_DIR_ENTRY DirEntry)
{
	PlMemSet(DirEntry, 0, sizeof(PL_DIR_ENTRY));
}

PL_ERROR PlWin32FindDataToDirEntry(WIN32_FIND_DATAW *ffd, PPL_DIR_ENTRY DirEntry)
{
	PlDirEntryInit(DirEntry);

	if ((PlWcsLen(ffd->cFileName) + 1)*sizeof(PL_WCHAR) > sizeof(DirEntry->FileName))
		return PL_E_INVALID_PARAM;

	PlMemCpy(DirEntry->FileName, ffd->cFileName, (PlWcsLen(ffd->cFileName) + 1)*sizeof(PL_WCHAR));
	if ((ffd->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
		DirEntry->IsDir = TRUE;
	} else {
		DirEntry->IsDir = FALSE;
	}

	return PL_E_OK;
}

PL_ERROR PlDirFindFirstFile(PL_WCHAR *Path, PPL_DIR_ENTRY pFirstDirEntry, PPL_DIR_ITER pDirIter)
{
	WIN32_FIND_DATAW ffd;
	PL_ERROR err;
	HANDLE hFile;
	PL_WCHAR searchPath[MAX_PATH];
	
	PlSnWprintf_s(searchPath, MAX_PATH, _TRUNCATE, L"%ws\\*", Path);

	PlMemSet(pDirIter, 0, sizeof(PL_DIR_ITER));

	hFile = FindFirstFileW(searchPath, &ffd);
	if (hFile == INVALID_HANDLE_VALUE) {
		return PL_E_NOT_FOUND;
	}

	err = PlWin32FindDataToDirEntry(&ffd, pFirstDirEntry);
	if (err) {
		return err;
	}

	pDirIter->Handle = hFile;
	return PL_E_OK;
}


PL_ERROR PlDirFindNextFile(PPL_DIR_ITER DirIter, PPL_DIR_ENTRY FoundDirEntry)
{
	WIN32_FIND_DATAW ffd;

	if (FindNextFile(DirIter->Handle, &ffd)) {
		PL_ERROR err;
		err = PlWin32FindDataToDirEntry(&ffd, FoundDirEntry);
		if (err) {
			return err;
		}
		return err;
	} else {
		return (GetLastError());
	}
}


PL_ERROR PlDirFindClose(PPL_DIR_ITER DirIter)
{
	if (FindClose(DirIter->Handle))
		return PL_E_OK;
	else
		return (GetLastError());
}

PL_ERROR PlWideStrSubCopy(PL_WCHAR *Src, size_t pos, size_t extra, PL_WCHAR **pResult)
{
	PL_WCHAR *dst = NULL;
	size_t len = PlWcsLen(Src) + 1;
	if (len <= pos)
		return PL_E_INVALID_PARAM;
	
	len -= pos;
	dst = PlMalloc((len + extra)*sizeof(PL_WCHAR));
	if (!dst)
		return PL_E_MALLOC;

	PlMemCpy(dst, &Src[pos], len*sizeof(PL_WCHAR));
	*pResult = dst;
	return PL_E_OK;
}

void PlPathWinToUnixInPlace(PL_WCHAR *Str)
{
	size_t i;
	for (i = 0; i < PlWcsLen(Str); i++) {
		if (Str[i] == L'\\')
			Str[i] = L'/';
	}
}

PL_ERROR PlFileCreate(PPL_FILE File, const PL_WCHAR *FileName, ULONG dwDesiredAccess, ULONG dwCreationDisposition)
{
	HANDLE hFile = NULL;

	PlMemSet(File, 0, sizeof(PL_FILE));

	hFile = CreateFileW(FileName, dwDesiredAccess, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, dwCreationDisposition, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return (GetLastError());
	}

	File->Handle = hFile;
	return PL_E_OK;
}

PL_ERROR PlFileReopen(PPL_FILE File, const PL_WCHAR *FileName, ULONG dwDesiredAccess, ULONG dwCreationDisposition)
{
	PL_ERROR err;
	err = PlFileClose(File);
	if (err)
		return err;

	return PlFileCreate(File, FileName, dwDesiredAccess, dwCreationDisposition);
}

PL_ERROR PlFileAppend(PPL_FILE File, const void *Buf, unsigned long Size)
{
	PL_ERROR err;

	err = PlFileSeek(File, 0, PL_FILEPOS_END, NULL);
	if (err)
		return err;

	return PlFileWrite(File, Buf, Size);
}

PL_ERROR PlFileWrite(PPL_FILE File, const void *Buf, unsigned long Size)
{
	unsigned long Wrote;

	if (!File->Handle || !Buf || !Size)
		return PL_E_INVALID_PARAM;

	if (!WriteFile(File->Handle, Buf, Size, &Wrote, NULL)) {
		return (GetLastError());
	} else {
		if (Wrote != Size)
			return PL_E_WRITE;
		else
			return PL_E_OK;
	}
}

PL_ERROR PlFileRead(PPL_FILE File, void *Buf, unsigned long Size)
{
	unsigned long Read;

	if (!File->Handle || !Buf || !Size)
		return PL_E_INVALID_PARAM;

	if (!ReadFile(File->Handle, Buf, Size, &Read, NULL)) {
		return (GetLastError());
	} else {
		if (Read != Size)
			return PL_E_READ;
		else
			return PL_E_OK;
	}
}

PL_ERROR PlFileClose(PPL_FILE File)
{
	if (!File->Handle)
		return PL_E_INVALID_PARAM;

	if (CloseHandle(File->Handle)) {
		PlMemSet(File, 0, sizeof(PL_FILE));
		return PL_E_OK;
	} else {
		return (GetLastError());
	}
}

PL_BOOLEAN PlFileValid(PPL_FILE File)
{
	return (File->Handle) ? TRUE : FALSE;
}

PL_BOOLEAN PlFileAtEOF(PPL_FILE File, PL_BOOLEAN *pIsEOF)
{
	__int64 curPos, endPos;
	PL_ERROR err;

	err = PlFileTell(File, &curPos);
	if (err)
		return FALSE;

	endPos = 0;
	err = PlFileSeek(File, endPos, PL_FILEPOS_END, &endPos);
	if (err)
		return FALSE;

	return (endPos == curPos) ? TRUE : FALSE;
}

PL_ERROR PlFileSeek(PPL_FILE File, __int64 Offset, int MoveMethod, __int64 *pResult)
{
	PL_ERROR err;
	LARGE_INTEGER lOffset, lResult;

	if (!File->Handle)
		return PL_E_INVALID_PARAM;

	lOffset.QuadPart = Offset;
	if (!SetFilePointerEx(File->Handle, lOffset, &lResult, MoveMethod)) {
		err = (GetLastError());
	} else {
		if (pResult)
			*pResult = lResult.QuadPart;
		err = PL_E_OK;
	}

	return err;
}

PL_ERROR PlFileTell(PPL_FILE File, __int64 *pResult)
{
	return PlFileSeek(File, 0, PL_FILEPOS_CURRENT, pResult);
}

PL_ERROR PlFileFlush(PPL_FILE File)
{
	if (!File->Handle)
		return PL_E_INVALID_PARAM;

	if (FlushFileBuffers(File->Handle)) {
		return PL_E_OK;
	} else {
		return (GetLastError());
	}
}

PL_ERROR PlFileDelete(const PL_WCHAR *FileName)
{
	if (DeleteFileW(FileName))
		return PL_E_OK;
	else
		return (GetLastError());
}

PL_BOOLEAN PlFileExists(const PL_WCHAR *FileName)
{
	DWORD attrs = GetFileAttributesW(FileName);
	if (attrs == INVALID_FILE_ATTRIBUTES) {
		return FALSE;
	} else {
		return TRUE;
	}
}

void PlLogPrintf(char *fmt, ...)
{
#define BUF_SIZE 1024
	va_list args;
	char buffer[BUF_SIZE];

	va_start(args, fmt);
	PlVsnPrintf_s(buffer, BUF_SIZE, PL_TRUNCATE, fmt, args);
	buffer[BUF_SIZE - 1] = '\0';
#if PL_LOG_USE_PRINTF
	printf("%s", buffer);
#endif
#if PL_LOG_USE_DBG_OUTPUT
	OutputDebugStringA("%s", buffer);
#endif
#if PL_LOG_USE_FILE
	{
		PL_FILE fp;
		PL_ERROR err;	
		err = PlFileCreate(&fp, PL_LOG_FILE, PL_FILE_APPEND_DATA, PL_FILE_OPEN_ALWAYS);
		if (!err) {
			PlFileAppend(&fp, buffer, (unsigned long)PlStrLen(buffer));
			PlFileClose(&fp);
		}
	}
#endif
	va_end(args);
}
