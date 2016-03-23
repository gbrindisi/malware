//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ISFB project. Version 2.13.24.1
//	
// module: str.h
// $Revision: 441 $
// $Date: 2014-12-15 18:55:51 +0300 (Пн, 15 дек 2014) $
// description:
//	strings manipulation routines.

#define	szEmpty				""
#define	wczEmpty			L""

//#define	szSpace				" "
#define	wszSpace			L" "
#define	szCRLF				"\r\n"
#define	wczCRLF				L"\r\n"
#define wczSM				L";"
#define czSM				";"
#define wczComma            L","
#define czComma             ","

#if _UNICODE
	#define	CRLF	szCRLF
#else
	#define	CRLF	wczCRLF
#endif

BOOL HexStrToBufferW(LPWSTR HexStr,PCHAR Buffer);
BOOL HexStrToBufferA(LPSTR HexStr,PCHAR Buffer);

#if _UNICODE
	#define	HexStrToBuffer	HexStrToBufferW
#else
	#define	HexStrToBuffer	HexStrToBufferA
#endif

void StrByteToCharW(BYTE bt, LPWSTR buf);
void StrByteToCharA(BYTE bt, LPSTR buf);

#if _UNICODE
	#define	StrByteToChar	StrByteToCharW
#else
	#define	StrByteToChar	StrByteToCharA
#endif

void StrBufferToHexW(const void *binary, DWORD binarySize, LPWSTR string);
void StrBufferToHexA(const void *binary, DWORD binarySize, LPSTR string);

#if _UNICODE
	#define	StrBufferToHex	StrBufferToHexW
#else
	#define	StrBufferToHex	StrBufferToHexA
#endif

BOOL StrIsValidMultiStringW(const LPWSTR string, DWORD size);
BOOL StrIsValidMultiStringA(const LPSTR string, DWORD size);

#if _UNICODE
	#define	StrIsValidMultiString	StrIsValidMultiStringW
#else
	#define	StrIsValidMultiString	StrIsValidMultiStringA
#endif

LPSTR StrMultiStringGetIndexA(LPSTR string, int index);
LPWSTR StrMultiStringGetIndexW(LPWSTR string, int index);

#if _UNICODE
	#define	StrMultiStringGetIndex	StrMultiStringGetIndexW
#else
	#define	StrMultiStringGetIndex	StrMultiStringGetIndexA
#endif

LPSTR	StrExpandEnvironmentVariablesA(LPSTR Path);
LPWSTR	StrExpandEnvironmentVariablesW(LPWSTR Path);

#if _UNICODE
	#define	StrExpandEnvironmentVariables(x)	StrExpandEnvironmentVariablesW(x)
#else
	#define	StrExpandEnvironmentVariables(x)	StrExpandEnvironmentVariablesA(x)
#endif

LPTSTR StrCatAlloc(LPTSTR pFirst, LPTSTR pSecond);

// string conversion
#define USES_CONVERSION int _convert = 0;  LPCWSTR _lpw = NULL; LPCSTR _lpa = NULL; _lpa; _convert; _lpw

__inline LPSTR WINAPI W2AHelper(LPSTR lpa, LPCWSTR lpw, int nChars)
{
	// verify that no illegal character present
	// since lpa was allocated based on the size of lpw
	// don't worry about the number of chars
	lpa[0] = '\0';
	WideCharToMultiByte(CP_ACP, 0, lpw, -1, lpa, nChars, NULL, NULL);
	return lpa;
}

__inline LPWSTR WINAPI A2WHelper(LPWSTR lpw, LPCSTR lpa, int nChars)
{
	// verify that no illegal character present
	// since lpw was allocated based on the size of lpa
	// don't worry about the number of chars
	lpw[0] = '\0';
	MultiByteToWideChar(CP_ACP, 0, lpa, -1, lpw, nChars);
	return lpw;
}

#define W2A(lpw) (\
	((_lpw = lpw) == NULL) ? NULL : (\
	_convert = (lstrlenW(_lpw)+1)*2,\
	W2AHelper((LPSTR) alloca(_convert), _lpw, _convert)))

#define A2W(lpa) (\
	((_lpa = lpa) == NULL) ? NULL : (\
	_convert = (lstrlenA(_lpa)+1),\
	A2WHelper((LPWSTR) alloca(_convert*2), _lpa, _convert)))


#ifndef _UNICODE

__inline LPSTR T2A(LPTSTR lp) { return lp; }
__inline LPSTR A2T(LPTSTR lp) { return lp; }

#define W2T(lpw) W2A(lpw)
#define T2W(lpa) A2W(lpa)

#else

__inline LPWSTR T2W(LPTSTR lp) { return lp; }
__inline LPTSTR W2T(LPWSTR lp) { return lp; }

#define T2A(lpw) W2A(lpw)
#define A2T(lpa) A2W(lpa)

#endif


BYTE HexToByteW(WCHAR c);
LPWSTR	AllocateAndCopyStringToWideString(LPCSTR inputString);
LPTSTR	StrDupEx(LPTSTR pSource, ULONG MaxLength);