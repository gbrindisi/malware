//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ISFB project. Version 2.13.24.1
//	
// module: memalloc.h
// $Revision: 321 $
// $Date: 2014-09-10 17:57:02 +0400 (Ср, 10 сен 2014) $
// description:
//	memory allocator that should be implemented by application that use this library

#ifndef __MEMALLOC_H_
#define __MEMALLOC_H_

#ifdef	__cplusplus
 extern "C" {
#endif
	PVOID	__stdcall AppAlloc(ULONG Size);
	VOID	__stdcall AppFree(PVOID pMem);
	PVOID	__stdcall AppRealloc(PVOID pMem, ULONG Size);
	ULONG	__stdcall AppRand(VOID);
#ifdef	__cplusplus
 }	// extern "C"
#endif

#endif //__MEMALLOC_H_