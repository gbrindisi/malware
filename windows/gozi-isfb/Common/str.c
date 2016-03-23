//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ISFB project. Version 2.13.24.1
//	
// module: str.c
// $Revision: 441 $
// $Date: 2014-12-15 18:55:51 +0300 (Пн, 15 дек 2014) $
// description:
//	CRM client dll. Strings manipulation functions. 

#include "..\common\common.h"
//
// converts hex string to binary 
//

BOOL HexStrToBufferW(
	LPWSTR	HexStr,
	PCHAR	Buffer
	)
{
	BOOL	Ret = FALSE;
	ULONG	Len = lstrlenW(HexStr);
	CHAR	Byte;

	while(Len)
	{
		WCHAR	c;
		CHAR	b;

		c = *HexStr;

		if (c >= L'0' && c <= L'9')
			b = (CHAR)(c - L'0');
		else if (c >= L'A' && c <= L'F')
			b = (CHAR)(c - L'A' + 0xa);
		else if (c >= L'a' && c <= L'f')
			b = (CHAR)(c - L'a' + 0xa);
		else
			break;

		if (Len % 2)
		{
			Byte += b;
			*Buffer = Byte;
			Buffer += 1;
		}
		else
			Byte = (b << 4);

		HexStr += 1;
		Len -= 1;
	}	// while(Len)

	if (Len == 0)
		Ret = TRUE;

	return(Ret);
}

BOOL HexStrToBufferA(
	LPSTR	HexStr,
	PCHAR	Buffer
	)
{
	BOOL	Ret = FALSE;
	ULONG	Len = lstrlenA(HexStr);
	CHAR	Byte;

	while(Len)
	{
		CHAR	c;
		CHAR	b;

		c = *HexStr;

		if (c >= '0' && c <= '9')
			b = (CHAR)(c - '0');
		else if (c >= 'A' && c <= 'F')
			b = (CHAR)(c - 'A' + 0xa);
		else if (c >= 'a' && c <= 'f')
			b = (CHAR)(c - 'a' + 0xa);
		else
			break;

		if (Len % 2)
		{
			Byte += b;
			*Buffer = Byte;
			Buffer += 1;
		}
		else
			Byte = (b << 4);

		HexStr += 1;
		Len -= 1;
	}	// while(Len)

	if (Len == 0)
		Ret = TRUE;

	return(Ret);
}

// byte to wchar
void StrByteToCharW(BYTE bt, LPWSTR buf)
{
	buf[0] = (BYTE)(bt >> 4);
	buf[1] = (BYTE)(bt & 0xF);

	buf[0] += (buf[0] > 0x9 ? ('A' - 0xA) : '0');
	buf[1] += (buf[1] > 0x9 ? ('A' - 0xA) : '0');
}

void StrByteToCharA(BYTE bt, LPSTR buf)
{
	buf[0] = (BYTE)(bt >> 4);
	buf[1] = (BYTE)(bt & 0xF);

	buf[0] += (buf[0] > 0x9 ? ('A' - 0xA) : '0');
	buf[1] += (buf[1] > 0x9 ? ('A' - 0xA) : '0');
}

// convert buffer to hex char string
void StrBufferToHexW(const void *binary, DWORD binarySize, LPWSTR string)
{
	DWORD i;
	for( i = 0; i < binarySize; i++, string += 2)StrByteToCharW(((LPBYTE)binary)[i], string);
	*string = 0;
}

void StrBufferToHexA(const void *binary, DWORD binarySize, LPSTR string)
{
	DWORD i;
	for( i = 0; i < binarySize; i++, string += 2)StrByteToCharA(((LPBYTE)binary)[i], string);
	*string = 0;
}

// 
// validates multisz string
// 
BOOL StrIsValidMultiStringW(const LPWSTR string, DWORD size)
{
	return (string != NULL && size >= 2 && string[size - 1] == 0 && (string)[size - 2] == 0);
}

BOOL StrIsValidMultiStringA(const LPSTR string, DWORD size)
{
	return (string != NULL && size >= 2 && string[size - 1] == 0 && (string)[size - 2] == 0);
}

//
// returns substring from multisz
//
LPSTR StrMultiStringGetIndexA(LPSTR string, int index)
{
	int i;
	if(index == 0)return string;
	for(i = 0; ; string++){
		if(*string == 0)
		{
			LPSTR c = string + 1;
			if(*c == 0)break; //eol.
			if(++i == index)return c;
		}
	}
	return NULL;
}

LPWSTR StrMultiStringGetIndexW(LPWSTR string, int index)
{
	int i;
	if(index == 0){
		return string;
	}
	for( i = 0; ; string++){
		if(*string == 0)
		{
			LPWSTR c = string + 1;
			if(*c == 0)break; //eol.
			if(++i == index)return c;
		}
	}
	return NULL;
}

//
//	Checks the specified path string if it contains an environment variable and if so resolves it's value.
//	Returns new resolved path string or NULL.
//
LPWSTR	StrExpandEnvironmentVariablesW(
	LPWSTR	Path	// target path string to resolve
	)
{
	LPWSTR	NewPath = NULL;
	ULONG	Len;

	if (Len = ExpandEnvironmentStringsW(Path, NULL, 0))
	{
		if (NewPath = AppAlloc(Len * sizeof(WCHAR)))
		{
			if (!ExpandEnvironmentStringsW(Path, NewPath, Len))
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
LPSTR	StrExpandEnvironmentVariablesA(
	LPSTR	Path	// target path string to resolve
	)
{
	LPSTR	NewPath = NULL;
	ULONG	Len;

	if (Len = ExpandEnvironmentStringsA(Path, NULL, 0))
	{
		if (NewPath = AppAlloc(Len))
		{
			if (!ExpandEnvironmentStringsA(Path, NewPath, Len))
			{
				AppFree(NewPath);
				NewPath = NULL;
			}	// if (!ExpandEnvironmentStringsW(Path, NewPath, Len))
		}	// if (NewPath = AppAlloc(Len))
	}	// if ((Len = ExpandEnvironmentStringsW(Path, NULL, 0)) && Len > OldLen)

	return(NewPath);
}


//
//	Allocates a memory buffer and concatinates two specified strings into it.
//
LPTSTR	StrCatAlloc(
	LPTSTR	pFirst,
	LPTSTR	pSecond
	)
{
	LPTSTR pResult;

	if (pResult = AppAlloc((lstrlen(pFirst) + lstrlen(pSecond) + 1) * sizeof(_TCHAR)))
	{
		lstrcpy(pResult, pFirst);
		lstrcat(pResult, pSecond);
	}
	return(pResult);
}


// converts hex char to digit
BYTE HexToByteW(WCHAR c )
{
	BYTE	b = 0;
	if (c >= L'0' && c <= L'9')
		b = (CHAR)(c - '0');
	else if (c >= L'A' && c <= L'F')
		b = (CHAR)(c - L'A' + 0xa);
	else if (c >= L'a' && c <= L'f')
		b = (CHAR)(c - L'a' + 0xa);
	return b;
}



LPWSTR AllocateAndCopyStringToWideString(LPCSTR inputString)
{
	LPWSTR outputString = NULL;
	int Length = strlen(inputString) + 1;

	outputString = (LPWSTR)AppAlloc(Length * sizeof(WCHAR));
	if (outputString != NULL)
	{
		A2WHelper(outputString, inputString,Length);
	}
	return outputString;
}


LPTSTR	StrDupEx(
	LPTSTR	pSource,
	ULONG	MaxLength
	)
{
	ULONG	Len = lstrlen(pSource), MaxLen = max(Len, MaxLength); 
	LPTSTR	pTarget;

	if (pTarget = AppAlloc((MaxLen + 1) * sizeof(_TCHAR)))
	{
		memcpy(pTarget, pSource, Len * sizeof(_TCHAR));
		memset(pTarget + Len, 0, (MaxLen - Len + 1) * sizeof(_TCHAR));
	}

	return(pTarget);
}