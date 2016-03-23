//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ISFB project. Version 2.13.24.1
//	
// module: pesup.h
// $Revision: 150 $
// $Date: 2013-11-27 07:53:11 +0300 (Ср, 27 ноя 2013) $
// description: 
//	PE file header support functions and types.

#pragma once
#include <winnt.h>

#define		_ALIGN(x, y)	((x + (y - 1)) & ~(y - 1))

typedef union _SECTION_NAME
{
	UCHAR	Byte[8];
	ULONG	Dword[2];
} SECTION_NAME, *PSECTION_NAME;

typedef struct _LINKED_BUFFER  LINKED_BUFFER, *PLINKED_BUFFER;

typedef struct _LINKED_BUFFER
{
	PLINKED_BUFFER	Next;		// Next buffer in list, 0 if current is the last one
	PCHAR			Buffer;		// Pointer to memory buffer
	ULONG			Size;		// Size of the memory buffer in bytes
} LINKED_BUFFER, *PLINKED_BUFFER;

typedef struct _IMAGE_DELAY_IMPORT_DESCRIPTOR
{
	DWORD		Flags;
	DWORD		Name;
	DWORD		Module;
	DWORD		FirstThunk;
	DWORD		OriginalFirstThunk;
	DWORD		BoundIAT;
	DWORD		UnloadIAT;
	DWORD		TimeDateStamp;
} IMAGE_DELAY_IMPORT_DESCRIPTOR, *PIMAGE_DELAY_IMPORT_DESCRIPTOR;


typedef ULONG_PTR	IAT_ENTRY;
typedef IAT_ENTRY*	PIAT_ENTRY;

typedef ULONG			EXPORT_ENTRY;
typedef EXPORT_ENTRY*	PEXPORT_ENTRY;

#define		IMAGE_PE_HEADER(Base)	(PIMAGE_NT_HEADERS)((PCHAR)Base + ((PIMAGE_DOS_HEADER)Base)->e_lfanew)


#define		PeSupGetOptionalField(PeHeader, Field)												\
			(((PIMAGE_NT_HEADERS32)PeHeader)->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 ?	\
				((PIMAGE_NT_HEADERS64)PeHeader)->OptionalHeader.##Field :								\
				((PIMAGE_NT_HEADERS32)PeHeader)->OptionalHeader.##Field)

#define		PeSupSetOptionalField(PeHeader, Field, Value)										\
			(((PIMAGE_NT_HEADERS32)PeHeader)->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 ?	\
				((PIMAGE_NT_HEADERS64)PeHeader)->OptionalHeader.##Field = Value :						\
				((PIMAGE_NT_HEADERS32)PeHeader)->OptionalHeader.##Field = Value)

#define		PeSupPtrOptionalField(PeHeader, Field)										\
			(((PIMAGE_NT_HEADERS32)PeHeader)->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 ?	\
				&((PIMAGE_NT_HEADERS64)PeHeader)->OptionalHeader.##Field:						\
				&((PIMAGE_NT_HEADERS32)PeHeader)->OptionalHeader.##Field)


#define		PeSupGetDirectoryEntryPtr(PeHeader, Entry)												\
			(((PIMAGE_NT_HEADERS32)PeHeader)->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 ?		\
				&((PIMAGE_NT_HEADERS64)PeHeader)->OptionalHeader.DataDirectory[##Entry] :					\
				&((PIMAGE_NT_HEADERS32)PeHeader)->OptionalHeader.DataDirectory[##Entry])


_inline PVOID PeSupGetImagePeHeader(PCHAR DosHeader)
{
	PIMAGE_NT_HEADERS pe = (PIMAGE_NT_HEADERS)(DosHeader + ((PIMAGE_DOS_HEADER)DosHeader)->e_lfanew);
	return((PVOID)pe);
}


_inline ULONG PeSupGetSectionRva(PVOID Section)
{
	PIMAGE_SECTION_HEADER sections = (PIMAGE_SECTION_HEADER)Section;
	return(sections->VirtualAddress);
}


_inline ULONG PeSupGetSectionVSize(PVOID Section)
{
	PIMAGE_SECTION_HEADER sections = (PIMAGE_SECTION_HEADER)Section;
	return(sections->Misc.VirtualSize);
}

_inline ULONG PeSupGetSectionRSize(PVOID Section)
{
	PIMAGE_SECTION_HEADER sections = (PIMAGE_SECTION_HEADER)Section;
	return(sections->SizeOfRawData);
}


_inline ULONG PeSupAlign(ULONG Size, ULONG Alignment)
{
	ULONG AlignedSize = Size & ~(Alignment-1);
				
	if (Size != AlignedSize)
		AlignedSize += Alignment;

	return(AlignedSize);
}


_inline PVOID PeSupRvaToVa(ULONG Rva, PCHAR ImageBase)
{
	return((PVOID)((ULONG_PTR)Rva + (ULONG_PTR)ImageBase));
}


_inline PVOID PeSupGetFirstWritableSection(PCHAR DosHeader)
{
	PIMAGE_NT_HEADERS Pe = (PIMAGE_NT_HEADERS)(DosHeader + ((PIMAGE_DOS_HEADER)DosHeader)->e_lfanew);
	PIMAGE_SECTION_HEADER Section = IMAGE_FIRST_SECTION(Pe);
	ULONG NumberOfSections = Pe->FileHeader.NumberOfSections;

	while(NumberOfSections)
	{
		if (Section->Characteristics & IMAGE_SCN_MEM_WRITE)
			return((PVOID)Section);

		Section += 1;
		NumberOfSections -= 1;
	}

	return(NULL);
}


typedef	BOOL (__stdcall* PTR_IS_IAT_ENTRY)(PVOID Address, PCHAR FunctionName);

#ifdef __cplusplus
 extern "C" {
#endif

PIAT_ENTRY		PeSupGetIatEntry (HMODULE TargetModule, PCHAR ImportedModule, PCHAR ImportedFunction, PTR_IS_IAT_ENTRY pIsIatEntry, PCHAR* ppName);
PEXPORT_ENTRY	PeSupGetExportEntry(HMODULE TargetModule, PCHAR ExportedFunction, PCHAR* ppName);
PIAT_ENTRY		PeSupGetDelayIatEntry (HMODULE TargetModule, PCHAR ImportedModule, PCHAR ImportedFunction, PCHAR* ppName);
PLINKED_BUFFER	PeSupGetSectionFreeBuffers(HMODULE	TargetModule, ULONG	SectionFlags);
ULONG			PeSupRvaToFileOffset(HMODULE hModule, ULONG	Rva);
PVOID			PeSupFindSectionByName(PCHAR DosHeader, PSECTION_NAME SecName);

#ifdef __cplusplus
 }
#endif


#define PeSupGetFreeCodeSpace(x)	PeSupGetSectionFreeBuffers(x, IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_DISCARDABLE)