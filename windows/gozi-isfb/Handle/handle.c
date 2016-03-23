//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ISFB project. Version 2.13.24.1
//	
// module: handle.c
// $Revision: 246 $
// $Date: 2014-06-01 23:38:46 +0400 (Вс, 01 июн 2014) $
// description:
//	A lightweight handle management engine. 
//	Implements a handle table to link a Key-value (handle) with the corresponding table record (context).

#include "..\common\main.h"
#include "handle.h"


// ---- Handle table read\write lock implementation ------------------------------------------------------------------------------

static VOID LockTableShared(PHANDLE_TABLE HTable)
{
	EnterCriticalSection(&HTable->TableLock);
	_InterlockedIncrement(&HTable->LockCount);
	LeaveCriticalSection(&HTable->TableLock);
	
}

static VOID UnlockTableShared(PHANDLE_TABLE HTable)
{
	_InterlockedDecrement(&HTable->LockCount);
}

static VOID LockTableExclusive(PHANDLE_TABLE HTable)
{
	EnterCriticalSection(&HTable->TableLock);
	while(HTable->LockCount)
		Sleep(10);
}

static VOID UnlockTableExclusive(PHANDLE_TABLE HTable)
{
	LeaveCriticalSection(&HTable->TableLock);
}


// ---- Handle table API ---------------------------------------------------------------------------------------------------------

//
//	Allocates and initializes new handle table.
//
WINERROR	HandleAllocateTable(
	PHANDLE_TABLE*			pHTable,			// Returns pointer for the newly allocated hadndle table
	ULONG					ContextSize,		// Specifies size of the handle context buffer in bytes
	HANDLE_INIT_ROUTINE		InitCallback,		// Pointer to a callback function that called each time a new handle created
	HANDLE_CLEANUP_ROUTINE	CleanupCallback		// Pointer to a callback function that called each time a handle deleted
	)
{
	WINERROR	Status = NO_ERROR;
	PHANDLE_TABLE HTable = (PHANDLE_TABLE)hAlloc(sizeof(HANDLE_TABLE));
	if (HTable)
	{
		ULONG i;
#ifdef _DEBUG
		HTable->Magic = HANDLE_TABLE_MAGIC;
#endif
		InitializeCriticalSection(&HTable->TableLock);
		InitializeListHead(&HTable->RecordListHead);

		for (i=0; i<HANDLE_ROOT_COUNT; i++)
			InitializeListHead(&HTable->KeyRoot[i]);

		HTable->Flags = 0;
		HTable->LockCount = 0;
		HTable->Records = 0;
		HTable->ContextSize = ContextSize;
		HTable->InitCallback = InitCallback;
		HTable->CleanupCallBack = CleanupCallback;
		*pHTable = HTable;
	}
	else
		Status = GetLastError();

	return(Status);
}

//
//	Allocates and pre-initializes new handle record.
//
static PHANDLE_RECORD HandleAllocate(
	ULONG ContextSize	// Size of a context buffer in bytes
	)
{
	PHANDLE_RECORD	pHRec = (PHANDLE_RECORD)hAlloc(sizeof(HANDLE_RECORD) + ContextSize);
	if (pHRec)
	{
		memset(pHRec, 0, sizeof(HANDLE_RECORD) + ContextSize);
#ifdef _DEBUG
		pHRec->Magic = HANDLE_RECORD_MAGIC;
#endif
		InitializeListHead(&pHRec->Entry);
		InitializeListHead(&pHRec->RecordListEntry);
	}
	return(pHRec);
}

//
//	Releases the specified handle record, frees memory.
//
static VOID HandleFree(
	PHANDLE_RECORD	pHRec
	)
{
	ASSERT_HANDLE_RECORD(pHRec);
	hFree(pHRec);
}

//
//	Deletes the specified handle record from the specified handle table.
//	The handle table assumed to be locked.
//
static VOID	HandleDeleteLocked(
	PHANDLE_TABLE HTable,	// Pointer to the handle table to delete record from
	PHANDLE_RECORD pHRec	// Pointer to the handle record to delete
	)
{
	ASSERT_HANDLE_TABLE(HTable);
	ASSERT(pHRec->RefCount == 0);

	RemoveEntryList(&pHRec->Entry);
	RemoveEntryList(&pHRec->RecordListEntry);
	HTable->Records -= 1;

	if (HTable->CleanupCallBack)
		(HTable->CleanupCallBack)(pHRec->Key, (PVOID)&pHRec->Context);

	HandleFree(pHRec);
}


//
//	Creates new handle and returns it's context. 
//	If there is a context for the specified handle alreay exists the function checks table flags if it can be reused.
//
BOOL	HandleCreate(
	PHANDLE_TABLE	HTable,		// Handle table 
	HANDLE			Key,		// Handle key (value or index)
	PVOID*			pContext	// Variable to receive handle context 
	)
{
	BOOL	Ret = FALSE;
	PHANDLE_RECORD pHRec = NULL;
	PLIST_ENTRY pHead, pEntry;

	ASSERT_HANDLE_TABLE(HTable);

	LockTableExclusive(HTable);

	pHead = &HTable->KeyRoot[(((ULONG_PTR)Key) >> HANDLE_SHIFT) & (HANDLE_ROOT_COUNT-1)];
	pEntry = pHead->Flink;

	while (pEntry != pHead)
	{
		pHRec = CONTAINING_RECORD(pEntry, HANDLE_RECORD, Entry);
		if (pHRec->Key >= Key)
			break;
		pEntry = pEntry->Flink;
	}

	if (!pHRec || pHRec->Key != Key)
	{
		// No such handle found, creating a new one
		if (pHRec = HandleAllocate(HTable->ContextSize))
		{
			pHRec->Key = Key;
			pHRec->HTable = HTable;

			if (HTable->InitCallback)
				Ret = (HTable->InitCallback)(Key, (PVOID)&pHRec->Context);

			if (Ret)
			{
				if (pContext)
					*pContext = &pHRec->Context;
				pHRec->RefCount = 1;

				InsertTailList(pEntry, &pHRec->Entry);
				InsertTailList(&HTable->RecordListHead, &pHRec->RecordListEntry);
				HTable->Records += 1;
			}
			else
				HandleFree(pHRec);
		}	// if (pHRec = HandleAllocate())
	}	// if (!pHRec || pHRec->Key != Key)
	else
	{
		// Handle already exists, check if we can reuse it
		if (HTable->Flags & TF_REUSE_HANDLE)
		{
			if (HTable->Flags & TF_REREFERENCE)
				InterlockedIncrement(&pHRec->RefCount);
			if (pContext)
				*pContext = &pHRec->Context;
			Ret = TRUE;
		}
	}

	UnlockTableExclusive(HTable);

	return(Ret);
}


//
//	Searches for and opens an existing handle, increments it's reference count and returns pointer to it's context buffer.
//
BOOL	HandleOpen(
	PHANDLE_TABLE	HTable,		// Handle table to search handle within
	HANDLE			Key,		// Key to search handle for
	PVOID*			pContext	// Receives pointer to a context buffer if found
	)
{
	BOOL	Ret = FALSE;
	PHANDLE_RECORD pHRec = NULL;
	PLIST_ENTRY pHead, pEntry;

	ASSERT_HANDLE_TABLE(HTable);

	LockTableShared(HTable);

	pHead = &HTable->KeyRoot[(((ULONG_PTR)Key) >> HANDLE_SHIFT) & (HANDLE_ROOT_COUNT-1)];
	pEntry = pHead->Flink;

	while (pEntry != pHead)
	{
		pHRec = CONTAINING_RECORD(pEntry, HANDLE_RECORD, Entry);
		if (pHRec->Key >= Key)
			break;
		pEntry = pEntry->Flink;
	}

	if (pHRec && pHRec->Key == Key)
	{
		_InterlockedIncrement(&pHRec->RefCount);
		if (pContext)
			*pContext = pHRec->Context;
	
		Ret = TRUE;
	}

	UnlockTableShared(HTable);

	return(Ret);
}


//
//	Closes a handle specified either by Key value or by pHRec pointer.
//
BOOL	HandleClose(
	PHANDLE_TABLE	HTable,		// Pointer to a handle table
	HANDLE			Key,		// OPTIONAL: Key value to search handle for
	PHANDLE_RECORD	pHRec		// OPTIONAL: Pointer to a handle record structure to close
	)
{
	BOOL Ret = FALSE;
	PLIST_ENTRY	pEntry, pHead;

	if (pHRec)
	{
		ASSERT(pHRec->RefCount > 0);
		Key = pHRec->Key;
		HTable = pHRec->HTable;
	}

	ASSERT_HANDLE_TABLE(HTable);


	if (!pHRec)
	{
		// Looking for the table record
		LockTableShared(HTable);
		ASSERT(Key);

		pHead = &HTable->KeyRoot[(((ULONG_PTR)Key) >> HANDLE_SHIFT) & (HANDLE_ROOT_COUNT-1)];
		pEntry = pHead->Flink;

		while (pEntry != pHead)
		{
			pHRec = CONTAINING_RECORD(pEntry, HANDLE_RECORD, Entry);
			if (pHRec->Key >= Key)
				break;
			pEntry = pEntry->Flink;
		}
		UnlockTableShared(HTable);
	}

	if (pHRec && pHRec->Key == Key)
	{	
		// Decrementing record's reference count
		ASSERT(pHRec->RefCount > 0);

		if (_InterlockedDecrement(&pHRec->RefCount) == 0)
		{
			LockTableExclusive(HTable);
			if (pHRec->RefCount == 0)
				HandleDeleteLocked(HTable, pHRec);
			UnlockTableExclusive(HTable);
		}
		Ret = TRUE;
	}

	return(Ret);
}


//
//	Searches for the handle with the specifed Index.
//  This function is used to enumerate all handles one by one.
//
BOOL HandleEnum(
	PHANDLE_TABLE	HTable,		// Pointer to a handle table to enumerate handles from
	ULONG			Index,		// Handle index
	PVOID			Context,	// Current handle context (to get the next one)
	PVOID*			pContext	// Receives handle context for the specified index
	)
{
	BOOL	Ret = FALSE;
	PLIST_ENTRY	pEntry;
	PHANDLE_RECORD	pHRec;

	ASSERT_HANDLE_TABLE(HTable);

	LockTableShared(HTable);

	if (Context)
	{
		pHRec = CONTAINING_RECORD(Context, HANDLE_RECORD, Context);
		ASSERT_HANDLE_RECORD(pHRec);
		ASSERT(pHRec->RefCount > 0);

		if (pHRec->RecordListEntry.Flink != &HTable->RecordListHead)
		{
			pHRec = CONTAINING_RECORD(pHRec->RecordListEntry.Flink, HANDLE_RECORD, RecordListEntry);
			ASSERT_HANDLE_RECORD(pHRec);
			ASSERT(pHRec->RefCount > 0);

			_InterlockedIncrement(&pHRec->RefCount);
			if (pContext)
				*pContext = &pHRec->Context;
			Ret = TRUE;
		}
	}
	else if (Index < HTable->Records)
	{
		pEntry = HTable->RecordListHead.Flink;

		while(Index)
		{
			pEntry = pEntry->Flink;
			Index -= 1;
		}

		pHRec = CONTAINING_RECORD(pEntry, HANDLE_RECORD, RecordListEntry);
		ASSERT_HANDLE_RECORD(pHRec);
		ASSERT(pHRec->RefCount > 0);

		_InterlockedIncrement(&pHRec->RefCount);
		if (pContext)
			*pContext = &pHRec->Context;
		Ret = TRUE;
	}	// if (Index < HTable->Records)
	UnlockTableShared(HTable);
	
	return(Ret);
}


//
//	Releases the specified handle table. Deletes all existing handles. Frees memory.
//
WINERROR	HandleReleaseTable(
	PHANDLE_TABLE	HTable
	)
{
	WINERROR	Status = NO_ERROR;
	ULONG		i;
	PLIST_ENTRY	pHead, pEntry;
	PHANDLE_RECORD	pHRec;
	ASSERT_HANDLE_TABLE(HTable);

	LockTableExclusive(HTable);

	for (i=0; i<HANDLE_ROOT_COUNT; i++)
	{
		pHead = &HTable->KeyRoot[i];
		pEntry = pHead->Flink;
		while (pEntry != pHead)
		{
			pHRec = CONTAINING_RECORD(pEntry, HANDLE_RECORD, Entry);
			pEntry = pEntry->Flink;
			ASSERT(HTable->Records > 0);
			ASSERT(pHRec->RefCount == 1);
			pHRec->RefCount -= 1;
			HandleDeleteLocked(HTable, pHRec);
		}
	}

	ASSERT(HTable->Records == 0);	
	UnlockTableExclusive(HTable);

#if _DEBUG
	HTable->Magic = 0;
#endif
	hFree(HTable);
	return(Status);
}
