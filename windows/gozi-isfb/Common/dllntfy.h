//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ISFB project. Version 2.13.24.1
//	
// module: dllntfy.h
// $Revision: 94 $
// $Date: 2013-08-13 17:45:07 +0400 (Вт, 13 авг 2013) $
// description:
//	Undocumented NT DLL-loader functions and structures.

#pragma once

// DLL load notification

typedef struct _LDR_DLL_DESCRIPTOR {
    ULONG			Flags;					//	Reserved.
    PUNICODE_STRING FullDllName;			//	Full path to the DLL module.
    PUNICODE_STRING BaseDllName;			//	Short name of the DLL module.
    PVOID			DllBase;                //	Base address of the DLL in memory.
    ULONG			SizeOfImage;            //	Size of the DLL image, in bytes.
} LDR_DLL_DESCRIPTOR, *PLDR_DLL_DESCRIPTOR;


typedef union _LDR_DLL_NOTIFICATION_DATA {
    LDR_DLL_DESCRIPTOR	Loaded;
    LDR_DLL_DESCRIPTOR	Unloaded;
} LDR_DLL_NOTIFICATION_DATA, *PLDR_DLL_NOTIFICATION_DATA;


typedef struct _LDR_DLL_NOTIFICATION_DESCRIPTOR {
#if	_DEBUG
	ULONG		Magic;
#endif
	LIST_ENTRY	Entry;
	PVOID		NotificationRoutine;
	PVOID		NotificationContext;
} LDR_DLL_NOTIFICATION_DESCRIPTOR, *PLDR_DLL_NOTIFICATION_DESCRIPTOR;

#define	LDR_DLL_NOTIFICATION_DESCRIPTOR_MAGIC	'NLLD'
#define	ASSERT_DLL_NOTIFICATION_DESCRIPTOR(x)	ASSERT(x->Magic == LDR_DLL_NOTIFICATION_DESCRIPTOR_MAGIC)

#define	LDR_DLL_NOTIFICATION_REASON_LOADED		1
#define LDR_DLL_NOTIFICATION_REASON_UNLOADED	2


//	Windows defined DLL-load notification callback routine.
//	This is only notification function, it doesn't return a value, and Windows doesn't care if it's completed successfully or not. 
typedef VOID (__stdcall* LOAD_DLL_NOTIFICATION_CALLBACK)
	(ULONG NotificationReason, PLDR_DLL_NOTIFICATION_DATA NotificationData, PVOID Context);


// DLL load/unload notification routines, avaliable for Vista and higher OSes
typedef NTSTATUS (__stdcall *TYPE_LdrRegisterDllNotification)
	(ULONG Flags, PVOID NotificationFunction, PVOID Context, PVOID* pNotificationDescriptor);

typedef NTSTATUS (__stdcall *TYPE_LdrUnregisterDllNotification)
	(PVOID NotificationDescriptor);


// Functions to enable/disable DLL load notifications for the current process

//
//	Sets DLL load/unload notification callback function.
//
WINERROR	SetDllNotificationCallback(
	LOAD_DLL_NOTIFICATION_CALLBACK	pCallback,				// caller-specified callback function
	PVOID							Context,				// caller-specified context value that will be passed to the callback function
	PVOID*							pNotificationDescriptor	// receives notification descriptor for the specified callback
	);

//
//	Removes DLL load/unload notification callback function.
//
WINERROR	RemoveDllNotificationCallback(
	PVOID	pNotificationDescriptor		// notification callback descriptor previously returned by SetDllNotificationCallback() function
	);


// Dll notification initialization function
WINERROR	InitDllNotification(VOID);