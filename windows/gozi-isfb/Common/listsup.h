//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ISFB project. Version 2.13.24.1
//	
// module: listsup.h
// $Revision: 70 $
// $Date: 2013-06-27 19:51:07 +0400 (Чт, 27 июн 2013) $
// description:
//	Linked list implementation.

#define InitializeListHead(ListHead) (\
    (ListHead)->Flink = (ListHead)->Blink = (ListHead))

#define IsListEmpty(ListHead) \
    ((ListHead)->Flink == (ListHead))

#define IsSingleEntryList(ListHead)	\
	((ListHead)->Flink != (ListHead) && (ListHead)->Flink == (ListHead)->Blink)

#define RemoveEntryList(Entry) {\
    PLIST_ENTRY _EX_Blink;\
    PLIST_ENTRY _EX_Flink;\
    _EX_Flink = (Entry)->Flink;\
    _EX_Blink = (Entry)->Blink;\
    _EX_Blink->Flink = _EX_Flink;\
    _EX_Flink->Blink = _EX_Blink;\
    }

#define RemoveHeadList(ListHead) \
    (ListHead)->Flink;\
    {RemoveEntryList((ListHead)->Flink)}

#define RemoveTailList(ListHead) \
    (ListHead)->Blink;\
    {RemoveEntryList((ListHead)->Blink)}


#define InsertTailList(ListHead,Entry) {\
    PLIST_ENTRY _EX_Blink;\
    PLIST_ENTRY _EX_ListHead;\
    _EX_ListHead = (ListHead);\
    _EX_Blink = _EX_ListHead->Blink;\
    (Entry)->Flink = _EX_ListHead;\
    (Entry)->Blink = _EX_Blink;\
    _EX_Blink->Flink = (Entry);\
    _EX_ListHead->Blink = (Entry);\
    }


#define InsertHeadList(ListHead,Entry) {\
    PLIST_ENTRY _EX_Flink;\
    PLIST_ENTRY _EX_ListHead;\
    _EX_ListHead = (ListHead);\
    _EX_Flink = _EX_ListHead->Flink;\
    (Entry)->Flink = _EX_Flink;\
    (Entry)->Blink = _EX_ListHead;\
    _EX_Flink->Blink = (Entry);\
    _EX_ListHead->Flink = (Entry);\
    }

typedef PLIST_ENTRY LIST_HEAD;

#define HASH_TABLE_LOCK CRITICAL_SECTION

#define LOCKED_LIST(x)	\
	LIST_ENTRY			x##Head;	\
	CRITICAL_SECTION	x##Lock;	\
	_inline VOID x##_Init(VOID)		{ InitializeCriticalSection(&x##Lock); InitializeListHead(&x##Head); } \
	_inline VOID x##_Lock(VOID)		{ EnterCriticalSection(&x##Lock); }		\
	_inline VOID x##_Unlock(VOID)	{ LeaveCriticalSection(&x##Lock); }		\
	_inline	VOID x##_Cleanup(VOID)	{ DeleteCriticalSection(&x##Lock);}

