//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ActiveDLL project. Version 1.4
//	
// module: activdll.h
// $Revision: 3 $
// $Date: 2012-11-28 22:51:39 +0400 (Ср, 28 ноя 2012) $
// description: 
//	Contains structures, constants and definitions used to create, initialize and execute PE-image without a file.



typedef NTSTATUS (_stdcall* FUNC_LOAD_LIBRARY)	(PWCHAR PathToFile, ULONG Flags, PUNICODE_STRING ModuleFileName, PHANDLE ModuleHandle); 
typedef NTSTATUS (_stdcall* FUNC_PROC_ADDRESS)	(PVOID ModuleHandle, PANSI_STRING FunctionName, WORD Oridinal, PVOID* FunctionAddress);
typedef NTSTATUS (_stdcall* FUNC_PROTECT_MEM)	(HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR* ProtectSize, ULONG NewProtect, PULONG OldProtect);	
typedef ULONG	 (_stdcall* FUNC_DLL_MAIN)		(PVOID hinstDLL, DWORD fdwReason, PVOID lpvReserved);

typedef	LPSTR	(_stdcall* AC_CMD_LINE_MODIFY_CALLBACKA) (LPSTR pApplicationName, LPSTR	pCommandLine);
typedef	LPWSTR	(_stdcall* AC_CMD_LINE_MODIFY_CALLBACKW) (LPWSTR pApplicationName, LPWSTR pCommandLine);

#define		LOADER_STUB_MAX		0x800						// maximum size of a loader stub in bytes
#define		LOADER_PATH_MAX		(MAX_PATH*sizeof(WCHAR))	// bytes

#pragma pack(push)
#pragma pack(1)

// Following structures are used by inject stubs (LoadDllStub, LoadDllStubArch).
// Changing a field within requies rebuilding all inject stubs.

// ActiveDll context structure that is must be passed by the loader to the DllMain as the 3d parameter
typedef struct _AD_CONTEXT
{
	ULONGLONG	pModule32;
	ULONGLONG	pModule64;
	ULONG		Module32Size;
	ULONG		Module64Size;
} AD_CONTEXT, *PAD_CONTEXT;

typedef struct _AD_CONTEXT_EX
{
	AD_CONTEXT	Context;
	ULONG		Flags;
	ULONG		NameLen;
	CHAR		Name[];
} AD_CONTEXT_EX, *PAD_CONTEXT_EX;

// Imported functions that are used for image initialization
typedef struct	_PROCESS_IMPORT
{
	ULONGLONG	pLdrLoadDll;
	ULONGLONG	pLdrGetProcedureAddress;
	ULONGLONG	pNtProtectVirtualMemory;
} PROCESS_IMPORT, *PPROCESS_IMPORT;

// Loader stub context
typedef struct	_LOADER_CONTEXT
{
	PROCESS_IMPORT		Import;
	AD_CONTEXT			AdContext;
	ULONGLONG			ImageBase;
	UNICODE_STRING		uDllPath;
	UCHAR				LoaderStub[LOADER_STUB_MAX];
	WCHAR				wDllPath[LOADER_PATH_MAX];
} LOADER_CONTEXT, *PLOADER_CONTEXT;

#pragma pack(pop)


// ---- from stubs.c

UCHAR	LoadDllStubArch[];

//
//	Initializes mapped image of a DLL: processes import, restores section protection. Executes image entry.
//
VOID _stdcall LoadDllStub(
	PLOADER_CONTEXT	LdrCtx
	);


// ---- from image.c

//
//	Builds PE image at the specfied address. Applies relocations.
//
WINERROR AcBuildImage(
	PCHAR	ImageBase,	// Address to build the image at
	PCHAR	ImageFile,	// Source PE-file
	PCHAR	NewBase		// OPTIONAL: New image base to recalculate relocation
	);

//
//	Creates a section object of the specified size and maps it into the current process.
//
WINERROR ImgAllocateSection(
	ULONG	SizeOfSection,	// specifies the size of the section
	PCHAR*	pSectionBase,	// returns the base of a newly created section within the current process
	PHANDLE	pSectionHandle	// OPTIONAL: returns the handle for a newly created section
	);

//
//	Maps the specified section into the specified process.
//
WINERROR ImgMapSection(
	HANDLE	hSection,		// handle of the section to map
	HANDLE	hProcess,		// handle of the target process to map the section to
	PVOID*	pSectionBase	// receives base address of the section mapped within the target process
	);

//
//	Unmaps the specifed section from the specified process.
//
WINERROR ImgUnmapSection(
	HANDLE	hProcess,		// handle of the target process
	PVOID	SectionBase		// base address of the section within the target process
	);


// ---- from acivdll.c

//
//	Injects current DLL image into the target process without creating a file.
//
WINERROR AdInjectImage(
	LPPROCESS_INFORMATION lpProcessInformation,	// Target process and it's main thread information
	PAD_CONTEXT		pAdContext,					// pointer to AD_CONTEXT structure to inject image from
	ULONG			InjectFlags,				// Inject control flags	
	PVOID*			pImageBase					// OPTIONAL: Receives BASE of the newly loaded image
	);


WINERROR AcStartup(
	PVOID	pContext,	// ActiveDll context pointer passed to the DLL when it is being injected as PE-image
	BOOL	bSetHooks,	// Specify TRUE to set ActiveDLL hooks
	AC_CMD_LINE_MODIFY_CALLBACKA	CmdLineModifyCallbackA,
	AC_CMD_LINE_MODIFY_CALLBACKW	CmdLineModifyCallbackW	
	);


WINERROR ProcessInjectDll(
	LPPROCESS_INFORMATION lpProcessInformation, 
	DWORD		ProcessCreateFlags, 
	ULONG_PTR	ProcessEntry,
	BOOL		bInjectImage
	);

//
//	Creates remote thread within the specified process and injects client.dll into it using this thread.
//
WINERROR ProcessInjectDllWithThread(
	ULONG	Pid
	);
