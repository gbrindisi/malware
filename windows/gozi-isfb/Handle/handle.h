//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ISFB project. Version 2.13.24.1
//	
// module: handle.h
// $Revision: 246 $ 
// $Date: 2014-06-01 23:38:46 +0400 (Вс, 01 июн 2014) $
// description:
//	A lightweight handle management engine. 

#define HANDLE_ROOT_COUNT		0x100
#ifdef _WIN64
	#define HANDLE_SHIFT		3
#else
	#define HANDLE_SHIFT		2
#endif

#define HANDLE_TABLE_MAGIC		'baTH'
#define HANDLE_RECORD_MAGIC		'ceRH'

typedef struct _HANDLE_RECORD HANDLE_RECORD, *PHANDLE_RECORD;

typedef BOOL	(_stdcall* HANDLE_INIT_ROUTINE)		(HANDLE Key, PVOID* pContext);
typedef BOOL	(_stdcall* HANDLE_CLEANUP_ROUTINE)	(HANDLE Key, PVOID* pContext);	

typedef struct _HANDLE_TABLE
{
#ifdef _DEBUG
	ULONG				Magic;
#endif
	CRITICAL_SECTION		TableLock;
	LONG	volatile		LockCount;
	ULONG					Records;
	ULONG					ContextSize;
	ULONG					Flags;
	HANDLE_INIT_ROUTINE		InitCallback;
	HANDLE_CLEANUP_ROUTINE	CleanupCallBack;
	LIST_ENTRY				RecordListHead;
	LIST_ENTRY				KeyRoot[HANDLE_ROOT_COUNT];
} HANDLE_TABLE, *PHANDLE_TABLE;

#define	TF_REUSE_HANDLE		1
#define	TF_REREFERENCE		2

#pragma pack(push)
#pragma pack(1)
typedef struct _HANDLE_RECORD
{
#ifdef _DEBUG
	ULONG		Magic;
#endif
	LIST_ENTRY		Entry;
	LIST_ENTRY		RecordListEntry;
	PHANDLE_TABLE	HTable;
	HANDLE			Key;
	LONG volatile	RefCount;
	CHAR			Context[0];
} HANDLE_RECORD, *PHANDLE_RECORD;
#pragma pack(pop)


#define ASSERT_HANDLE_TABLE(x)	ASSERT(x->Magic == HANDLE_TABLE_MAGIC)
#define ASSERT_HANDLE_RECORD(x) ASSERT(x->Magic == HANDLE_RECORD_MAGIC)

WINERROR	HandleAllocateTable(PHANDLE_TABLE* pHTable, ULONG ContextSize, HANDLE_INIT_ROUTINE	InitCallback, HANDLE_CLEANUP_ROUTINE CleanupCallback);
WINERROR	HandleReleaseTable(PHANDLE_TABLE HTable);
BOOL	HandleCreate(PHANDLE_TABLE	HTable, HANDLE Key, PVOID* pContext);
BOOL	HandleOpen(PHANDLE_TABLE HTable, HANDLE Key, PVOID* pContext);
BOOL	HandleClose(PHANDLE_TABLE HTable, HANDLE Key, PHANDLE_RECORD pHRec);
BOOL	HandleEnum(PHANDLE_TABLE HTable, ULONG Index, PVOID Context, PVOID* pContext);
