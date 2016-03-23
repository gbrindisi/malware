//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ISFB project. Version 2.13.24.1
//	
// module: dbg.h
// $Revision: 449 $
// $Date: 2015-01-15 18:52:26 +0300 (Чт, 15 янв 2015) $
// description:
//	Debug-build support routines: DbgPrint(), ASSERT() and checked pool allocations.

#pragma once

#include <crtdbg.h>

#if _DEBUG
	#define _DBG			TRUE
	#define _TRACE_ALLOC	TRUE
#endif

#define BAD_PTR		(LONG_PTR)0xBAADF00D
#define	PAGE_SIZE	0x1000

#define	SIGN_LOCAL	0xcccccccc
#define	SIGN_HEAP	0x99999999

extern	HANDLE	g_AppHeap;


#ifdef _TRACE_ALLOC

typedef struct _DBG_ALLOC
{
	unsigned long Size;
	unsigned long Sign;
	char  Buffer[1];
}DBG_ALLOC,*PDBG_ALLOC;


__inline void* DbgAlloc(size_t Size)
{
	void* mem = malloc(Size + 12);
	if (mem)
	{
		PDBG_ALLOC pd = (PDBG_ALLOC) mem;
		memset(mem, (UCHAR)SIGN_LOCAL, Size + 12);
		pd->Size = (unsigned long) Size;
		return(&pd->Buffer);
	}
	return(mem);
}

__inline void DbgFree(void* mem)
{
	PDBG_ALLOC pd = CONTAINING_RECORD(mem, DBG_ALLOC, Buffer);
	if (*(unsigned long*)((PCHAR)pd->Buffer + pd->Size)!= SIGN_LOCAL)
		__debugbreak();
	if (pd->Sign != SIGN_LOCAL)
		__debugbreak();
	free(pd);

}


__inline void* DbgRealloc(void* Mem, size_t Size)
{
	void* mem = malloc(Size + 12);
	if (mem)
	{
		PDBG_ALLOC pd = (PDBG_ALLOC) mem;
		PDBG_ALLOC pd1 = CONTAINING_RECORD(Mem, DBG_ALLOC, Buffer);
		if (pd1->Sign != SIGN_LOCAL)
			__debugbreak();

		memset(mem, (UCHAR)SIGN_LOCAL, Size + 12);
		pd->Size = (unsigned long) Size;
		memcpy(&pd->Buffer, &pd1->Buffer, pd1->Size);
	
		DbgFree(Mem);
		return(&pd->Buffer);
	}

	return(mem);
}

__inline void* DbgHeapAlloc(size_t Size)
{
	void* mem;
	if (g_AppHeap == 0)
		__debugbreak();
	if (Size == 0)
		__debugbreak();

	mem = HeapAlloc(g_AppHeap, 0, Size + 12);
	if (mem)
	{
		PDBG_ALLOC pd = (PDBG_ALLOC) mem;
		memset(mem, (UCHAR)SIGN_HEAP, Size + 12);
		pd->Size = (unsigned long) Size;
		return(&pd->Buffer);
	}
	return(mem);
}

__inline void DbgHeapFree(void* mem)
{
	PDBG_ALLOC pd = CONTAINING_RECORD(mem, DBG_ALLOC, Buffer);
	if (g_AppHeap == 0)
		__debugbreak();
	if (*(unsigned long*)((PCHAR)pd->Buffer + pd->Size)!= SIGN_HEAP)
		__debugbreak();
	if (pd->Sign != SIGN_HEAP)
		__debugbreak();
	HeapFree(g_AppHeap, 0, pd);

}


__inline void* DbgHeapRealloc(void* Mem, size_t Size)
{
	void* mem = HeapAlloc(g_AppHeap, 0, Size + 12);
	if (mem)
	{
		PDBG_ALLOC pd = (PDBG_ALLOC) mem;
		PDBG_ALLOC pd1 = CONTAINING_RECORD(Mem, DBG_ALLOC, Buffer);
		if (g_AppHeap == 0)
			__debugbreak();

		if (pd1->Sign != SIGN_HEAP)
			__debugbreak();
		if (*(unsigned long*)((PCHAR)pd1->Buffer + pd1->Size)!= SIGN_HEAP)
			__debugbreak();

		memset(mem, (UCHAR)SIGN_HEAP, Size + 12);
		pd->Size = (unsigned long) Size;
		memcpy(&pd->Buffer, &pd1->Buffer, pd1->Size);
	
		DbgHeapFree(Mem);
		return(&pd->Buffer);
	}

	return(mem);
}




#define Alloc(x)		DbgAlloc(x)
#define Free(x)			{DbgFree(x); *(PVOID*)&x = (PVOID)BAD_PTR;}
#define Realloc(x,y)	DbgRealloc(x,y)

#define hAlloc(x)		DbgHeapAlloc(x)
#define hFree(x)		{DbgHeapFree(x);*(PVOID*)&x = (PVOID)BAD_PTR;}
#define hRealloc(x,y)	DbgHeapRealloc(x,y)

#else

#define Alloc(x)		malloc(x)
#define Free(x)			free(x)
#define Realloc(x,y)	realloc(x,y)

#define hAlloc(x)		HeapAlloc(g_AppHeap, 0, x)
#define hFree(x)		HeapFree(g_AppHeap, 0, x)
#define hRealloc(x,y)	HeapReAlloc(g_AppHeap, 0, x, y)


#endif


#define vAlloc(x)		VirtualAlloc(0, x, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
#define vFree(x)		VirtualFree(x, 0, MEM_RELEASE)


#ifdef _DBG



#pragma warning(disable:4996) // 'sprintf': This function or variable may be unsafe.
 #ifdef _DBG_PRINT_TIME
  #define  DbgPrint(args, ...) \
		{ char* buff = (char*)LocalAlloc(LPTR, 0x1000); \
			SYSTEMTIME	SysTime;	\
			ULONG	Size;	\
			GetLocalTime(&SysTime);	\
			Size = wsprintfA(buff, "%02u:%02u:%02u ", SysTime.wHour, SysTime.wMinute, SysTime.wSecond);	\
		  wsprintfA(buff + Size, args, __VA_ARGS__); \
		  OutputDebugStringA((LPCSTR)buff); \
		  LocalFree(buff); } 
 #else
  #define  DbgPrint(args, ...) \
		{ char* buff = (char*)LocalAlloc(LPTR, 0x1000); \
		  wsprintfA(buff, args, __VA_ARGS__); \
		  OutputDebugStringA((LPCSTR)buff); \
		  LocalFree(buff); } 
#endif

#define  DbgPrintW(args, ...) \
		{ wchar_t* buff = (wchar_t*)LocalAlloc(LPTR, 0x2000); \
		  wsprintfW(buff, args, __VA_ARGS__); \
		  OutputDebugStringW((LPCWSTR)buff); \
		  LocalFree(buff); } 

#define ASSERT(x) _ASSERT(x)
  

#else
	#define DbgPrint(x, ...) 
	#define DbgPrintW(x, ...) 
	#define ASSERT(x)
/*
#define Alloc(x)		malloc(x)
#define Free(x)			free(x)
#define Realloc(x,y)	realloc(x,y)

*/	
#endif

