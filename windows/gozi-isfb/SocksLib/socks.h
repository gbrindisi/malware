//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// SOCKS project. Version 1.3
//	
// module: socks.h
// $Revision: 46 $
// $Date: 2014-03-16 14:31:01 +0300 (Вс, 16 мар 2014) $
// description:
//	Socks library main header file.

//
//	Starts the socks server.
//
WINERROR SocksStartServer(
	PVOID*			pServerHandle,	// receives SOCKS server handle
	SOCKADDR_IN*	pServerAddress,	// specifies BC-server address or, if no IP specified, AC-server port
	HANDLE			hServerMutex,	// handle to a mutex object wich will be held until the server stops
	LPSTR			pClientId		// client ID string
	);

//
//	Stops the socks server. Cleans up all structures.
//
VOID SocksStopServer(
	PVOID	ServerHandle
	);

