//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// SOCKS project. Version 1.3
//	
// module: socks.c
// $Revision: 64 $
// $Date: 2014-10-17 21:18:21 +0400 (Пт, 17 окт 2014) $
// description:
//	Socks server main code module.

#include "..\common\common.h"
#include "proxy.h"
#include "sockssrv.h"
#include "socks.h"
#include <mstcpip.h>


//
//	Performs SOCKS5 protocol handshake.
//	If successed, establishes connection to a destination host.
//	If fails returns corresponding WIN32 error code. If the SOCKS handshake successed but the specified within the request
//	 host either not resolved or not connected returns ERROR_HOST_UNREACHABLE.
//
static WINERROR Socks5Handshake(
	PPROXY_SESSION pSession
	)
{
	WINERROR Status = NO_ERROR;
	UCHAR	Method, i, NumberMethods;
	LONG	bSize, ReplyLength = 0;
	UCHAR	Methods[256];
	SOCKS5_REPLY0	Reply0;
	SOCKS5_MESSAGE	Request;
	SOCKADDR_IN		TargetAddr = {0};

	TargetAddr.sin_family = AF_INET;

	do	// not a loop
	{
		// Reading number of authentication methods supported by the client
		if ((Status = ProxyReadSocket(pSession->ClientSocket, (PCHAR)&NumberMethods, sizeof(UCHAR))) != NO_ERROR)
			break;

		// Reading authentication methods array
		if ((Status = ProxyReadSocket(pSession->ClientSocket, (PCHAR)&Methods, NumberMethods)) != NO_ERROR)
			break;

		// Looking for a supported authentication method
		for (i=0; i<NumberMethods; i++)
		{
			if ((Method = Methods[i]) == SOCKS_AUTH_NO)
				break;
		}

		if (i == NumberMethods)
			Method = SOCKS_AUTH_UNKNOWN;

		Reply0.Version = 05;
		Reply0.Method = Method;

		if ((bSize = _tsend(pSession->ClientSocket, (PCHAR)&Reply0, sizeof(SOCKS5_REPLY0), 0)) != sizeof(SOCKS5_REPLY0))
		{
			Status = ERROR_CONNECTION_ABORTED;
			break;
		}

		if (Method != SOCKS_AUTH_NO)
		{
			Status = ERROR_INVALID_PARAMETER;
			break;
		}

		// Reading connection request
		if ((Status = ProxyReadSocket(pSession->ClientSocket, (PCHAR)&Request.Header, sizeof(SOCKS5_HEADER))) != NO_ERROR)
			break;

		ReplyLength = sizeof(SOCKS5_HEADER);

		// Verifying connection request
		if (Request.Header.Version != 5 || (Request.Header.Command != SOCKS_CMD_CONNECT) || 
			(Request.Header.AddressType != SOCKS_ADDR_IP4 && Request.Header.AddressType != SOCKS_ADDR_DNAME))
		{
			Status = ERROR_INVALID_PARAMETER;
			break;
		}

		if (Request.Header.AddressType == SOCKS_ADDR_IP4)
		{
			// Reading target IP address
			if ((Status = ProxyReadSocket(pSession->ClientSocket, (PCHAR)&Request.Ip4, sizeof(SOCKS5_IP4))) != NO_ERROR)
				break;

			ReplyLength += sizeof(SOCKS5_IP4);

			TargetAddr.sin_addr.S_un.S_addr = Request.Ip4.Address;
			TargetAddr.sin_port = Request.Ip4.Port;
		}
		else
		{
			struct hostent*	pHostEnt;

			ASSERT(Request.Header.AddressType == SOCKS_ADDR_DNAME);

			// Reading name length
			if ((Status = ProxyReadSocket(pSession->ClientSocket, (PCHAR)&Request.DName.Length, sizeof(UCHAR))) != NO_ERROR)
				break;

			ReplyLength += sizeof(UCHAR);

			if (Request.DName.Length == 0)
			{
				Status = ERROR_INVALID_PARAMETER;
				break;
			}

			// Reading domain name
			if ((Status = ProxyReadSocket(pSession->ClientSocket, (PCHAR)&Request.DName.Name, Request.DName.Length)) != NO_ERROR)
				break;

			ReplyLength += Request.DName.Length;
			Request.DName.Name[Request.DName.Length] = 0;

			// Resolving host address by the given name
			pHostEnt = _tgethostbyname((PCHAR)&Request.DName.Name);

			// Reading host TCP port
			if ((Status = ProxyReadSocket(pSession->ClientSocket, (PCHAR)&Request.DName.Name[Request.DName.Length], sizeof(USHORT))) != NO_ERROR)
				break;

			ReplyLength += sizeof(USHORT);

			// Checking the address resolved
			if (!pHostEnt || pHostEnt->h_addrtype != AF_INET || pHostEnt->h_length != sizeof(ULONG))
			{
				// The specified host not resloved
				Status = ERROR_HOST_UNREACHABLE;
				break;
			}
			TargetAddr.sin_addr.S_un.S_addr = *(PULONG)(*pHostEnt->h_addr_list);
			TargetAddr.sin_port = *(PUSHORT)&Request.DName.Name[Request.DName.Length];
		}
	} while(FALSE);

	if (Status == NO_ERROR)
	{
		// Creating target TCP\IP port
		if ((pSession->TargetSocket = _tsocket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) != INVALID_SOCKET)
		{
			// Connecting target server
			if (!_tconnect(pSession->TargetSocket, (struct sockaddr*)&TargetAddr, sizeof(SOCKADDR_IN)))
			{
				ASSERT(Status == NO_ERROR);
			}
			else
			{
				// The specified host not connected
				ProxyShutdownSocket(&pSession->TargetSocket);
				Status = ERROR_HOST_UNREACHABLE;
			}
		}	// if ((pSession->TargetSocket = _tsocket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) != INVALID_SOCKET)
		else
			Status = GetLastError();
	}	// if (Status == NO_ERROR)

	if (ReplyLength)
	{
		//	We have a part or complete SOCKS5 request received.
		//	We need to send a reply anyway.

		if (Status == NO_ERROR)
			Request.Header.Status = SOCKS5_OK;
		else
			Request.Header.Status = SOCKS5_FAILED;

		// Sending reply to the client
		if ((bSize = _tsend(pSession->ClientSocket, (PCHAR)&Request, ReplyLength, 0)) != ReplyLength)
			Status = ERROR_CONNECTION_ABORTED;
	}	// if (ReplyLength)

	return(Status);
}


//
//	Performs SOCKS4 protocol handshake.
//	If successed, establishes connection to a destination host.
//	If fails returns corresponding WIN32 error code. If the SOCKS handshake successed but the specified within the request
//	 host not connected returns ERROR_HOST_UNREACHABLE.
//
static WINERROR Socks4Handshake(
	PPROXY_SESSION pSession
	)
{
	WINERROR Status = ERROR_INVALID_PARAMETER;
	LONG	bSize;
	SOCKS4_REQUEST	Request;
	SOCKS4_REPLY	Reply= {0};
	SOCKADDR_IN		TargetAddr = {0};


	do	// not a loop
	{
		// Reseiving socks request
		if ((Status = ProxyReadSocket(pSession->ClientSocket, (PCHAR)&Request, sizeof(SOCKS4_REQUEST))) != NO_ERROR)
			break;

		Status = ERROR_INVALID_PARAMETER;

		// Analyzing request fields
		if (Request.Command != SOCKS_CMD_CONNECT && Request.Command != SOCKS_CMD_BIND)
			break;

		if (Request.User)
		{
			// There is user name specified. Reading it.
			do 
			{
				bSize = _trecv(pSession->ClientSocket, (PCHAR)&Request.User, sizeof(UCHAR), 0);
			} while(bSize > 0 && Request.User != 0);

			if (Request.User)
				break;
		}	// if (Request.User)

		// Creating target TCP\IP port
		if ((pSession->TargetSocket = _tsocket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) != INVALID_SOCKET)
		{
			TargetAddr.sin_family = AF_INET;
			TargetAddr.sin_port = Request.Port;
			TargetAddr.sin_addr.S_un.S_addr = Request.Ip;

			// Connecting taget server
			if (!_tconnect(pSession->TargetSocket, (struct sockaddr*)&TargetAddr, sizeof(SOCKADDR_IN)))
			{
				Status = NO_ERROR;
			}
			else
			{
				// The specified host not connected
				ProxyShutdownSocket(&pSession->TargetSocket);
				Status = ERROR_HOST_UNREACHABLE;
			}
		}	// if ((pSession->TargetSocket = _tsocket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) != INVALID_SOCKET)
		else
			Status = GetLastError();

		if (Status == NO_ERROR)
			Reply.Status = SOCKS_RPL_GRANTED;
		else
			Reply.Status = SOCKS_RPL_FAILED;

		// Sending reply to the client
		if ((bSize = _tsend(pSession->ClientSocket, (PCHAR)&Reply, sizeof(SOCKS4_REPLY), 0)) <= 0)
			Status = ERROR_CONNECTION_ABORTED;
	
	} while(FALSE);

	return(Status);
}


//
//	Reads and checks desired SOCKS protocol version.
//
static WINERROR WINAPI SocksVersion(
	PPROXY_SESSION	pSession,
	SOCKET			ClientSocket
	)
{
	WINERROR Status;

	do
	{
		pSession->ProxyVersion = 0xff;

		if ((Status = ProxyReadSocket(ClientSocket, (PCHAR)&pSession->ProxyVersion, sizeof(UCHAR))) == NO_ERROR)
		{
			if (pSession->ProxyVersion != 4 && pSession->ProxyVersion != 5)
				Status = ERROR_INVALID_PARAMETER;
		}
#ifdef _BC_CLIENT
		// Seems to be BC KEEPALIVE packet
 #if _DBG
		if (pSession->ProxyVersion == 0)
			DbgPrint("SOCKS: BC KeepAlive packet received.\n");
 #endif
	} while(pSession->ProxyVersion == 0);
#else
	} while(FALSE);
#endif

	return(Status);
}


static WINERROR SocksHandshake(
	PPROXY_SESSION pSession
	)
{
	WINERROR Status = ERROR_INVALID_FUNCTION;

	do 
	{
		// Checking socks version
		if (pSession->ProxyVersion == 4)
			Status = Socks4Handshake(pSession);
		else if (pSession->ProxyVersion == 5)
			Status = Socks5Handshake(pSession);
		else
		{
			// Invalid socks version
			ASSERT(FALSE);
		}

#ifdef _KEEP_CONNECTION
		if (Status == ERROR_HOST_UNREACHABLE)
		{
			// Handshake complete but we are unable to connect the host specified within the request
			// Waiting for the new request
			DbgPrint("SOCKS: Failed to connect the specified target host. Waiting for a new request.\n");
			if (SocksVersion(pSession, pSession->ClientSocket) != NO_ERROR)
				break;
		}
	} while(Status == ERROR_HOST_UNREACHABLE);
#else
	} while(FALSE);
#endif

	return(Status);
}

// ---- Socks server startup and cleanup routines --------------------------------------------------------------------------


//
//	Stops the socks server. Cleans up all structures.
//
VOID SocksStopServer(
	PVOID	ServerHandle	// SOCKS server handle returned by SocksStartServer() function
	)
{
	ProxyStopServer(ServerHandle);
}
	

//
//	Starts the socks server.
//
WINERROR SocksStartServer(
	PVOID*			pServerHandle,	// receives SOCKS server handle
	SOCKADDR_IN*	pServerAddress,	// specifies BC-server address or, if no IP specified, AC-server port
	HANDLE			hServerMutex,	// handle to a mutex object wich will be held until the server stops
	LPSTR			pClientId		// client ID string
	)
{
	return(ProxyStartServer(pServerHandle, pServerAddress, hServerMutex, pClientId, &SocksVersion, &SocksHandshake));
}

