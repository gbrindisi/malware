//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ActiveDLL project. Version 1.4
//	
// module: image.c
// $Revision: 3 $
// $Date: 2012-11-28 22:51:39 +0400 (Ср, 28 ноя 2012) $
// description: 
//	Contains routines used to create, initialize and execute PE-image without a file.

#include "..\common\common.h"

//
//	Maps the specified section into the specified process.
//
WINERROR ImgMapSection(
	HANDLE	hSection,		// handle of the section to map
	HANDLE	hProcess,		// handle of the target process to map the section to
	PVOID*	pSectionBase	// receives base address of the section mapped within the target process
	)
{
	NTSTATUS	ntStatus;
	SIZE_T		ViewSize = 0, SectionSize = 0;
	LARGE_INTEGER	SectionOffset = {0};

	ntStatus = NtMapViewOfSection(hSection, hProcess, pSectionBase, 0, SectionSize, &SectionOffset, 
		&ViewSize, ViewUnmap, 0, PAGE_EXECUTE_READWRITE);

	if (NT_SUCCESS(ntStatus))
	{
		DbgPrint("ACTIVDLL_%04x: A section of %u bytes mapped to the target process at 0x%p\n", g_CurrentProcessId, SectionSize, *pSectionBase);
	}
	else
	{
		DbgPrint("ACTIVDLL_%04x: Failed mapping a section to the target process, status 0x%x\n", g_CurrentProcessId, ntStatus);
	}

	return(RtlNtStatusToDosError(ntStatus));
}


//
//	Unmaps the specifed section from the specified process.
//
WINERROR ImgUnmapSection(
	HANDLE	hProcess,		// handle of the target process
	PVOID	SectionBase		// base address of the section within the target process
	)
{
	return(RtlNtStatusToDosError(NtUnmapViewOfSection(hProcess, SectionBase)));
}


//
//	Creates a section object of the specified size and maps it into the current process.
//
WINERROR ImgAllocateSection(
	ULONG	SizeOfSection,	// specifies the size of the section
	PCHAR*	pSectionBase,	// returns the base of a newly created section within the current process
	PHANDLE	pSectionHandle	// OPTIONAL: returns the handle for a newly created section
	)
{
	WINERROR	Status = NO_ERROR;
	HANDLE		hSection	= 0;
	SIZE_T		ViewSize	= 0;
	NTSTATUS	ntStatus	= STATUS_SUCCESS;
	PVOID		SectionBase	= NULL;
	OBJECT_ATTRIBUTES	oa = {0};
	LARGE_INTEGER		SectionSize = {0}, SectionOffset = {0};

	SectionSize.LowPart = SizeOfSection;
	ASSERT(SectionSize.QuadPart == (ULONGLONG)SectionSize.LowPart);

	InitializeObjectAttributes(&oa, NULL, OBJ_CASE_INSENSITIVE, 0, NULL);
	ntStatus = NtCreateSection(&hSection, SECTION_ALL_ACCESS, &oa, &SectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, 0);
	if (NT_SUCCESS(ntStatus))
	{
		if ((Status = ImgMapSection(hSection, NtCurrentProcess(), &SectionBase)) == NO_ERROR)
		{
			memset(SectionBase, 0, SectionSize.LowPart);
			*pSectionBase = (PCHAR)SectionBase;
			if (pSectionHandle)
				*pSectionHandle = hSection;
		}	// if (NT_SUCCESS(ntStatus))
	}	// if (NT_SUCCESS(ntStatus))
	else
	{
		Status = RtlNtStatusToDosError(ntStatus);
		DbgPrint("ACTIVDLL_%04x: Failed creating an image section of %u bytes, status 0x%x\n", g_CurrentProcessId, SizeOfSection, ntStatus);
	}

	if (hSection && !pSectionHandle)
		ZwClose(hSection);

	return(Status);
}

//
//	Builds PE image at the specfied address. Applies relocations.
//
WINERROR AcBuildImage(
	PCHAR	ImageBase,	// Address to build the image at
	PCHAR	ImageFile,	// Source PE-file
	PCHAR	NewBase		// OPTIONAL: New image base to recalculate relocation
	)
{
	WINERROR	Status = NO_ERROR;
	ULONG		i, NumberSections, FileAlign, bSize;
	LONG		RelocSize;
	PIMAGE_DOS_HEADER	Mz = (PIMAGE_DOS_HEADER)ImageFile;
	PIMAGE_NT_HEADERS	Pe = (PIMAGE_NT_HEADERS)((PCHAR)Mz + Mz->e_lfanew);
	PIMAGE_SECTION_HEADER	Section = IMAGE_FIRST_SECTION(Pe);
	PIMAGE_DATA_DIRECTORY	DataDir;
	
	NumberSections	= Pe->FileHeader.NumberOfSections;
	FileAlign		= PeSupGetOptionalField(Pe, FileAlignment);
	
	// Copying the file headers
	memcpy(ImageBase, ImageFile, PeSupGetOptionalField(Pe, SizeOfHeaders));

	// Copying image sections
	for(i=0; i<NumberSections; i++)
	{
		bSize = _ALIGN(Section->SizeOfRawData, FileAlign);
		if (bSize)
			memcpy(ImageBase + Section->VirtualAddress, ImageFile + Section->PointerToRawData, bSize);
		Section += 1;
	}

	if (!NewBase)
		NewBase = ImageBase;

	// Processing relocs
	DataDir = PeSupGetDirectoryEntryPtr(Pe, IMAGE_DIRECTORY_ENTRY_BASERELOC);
	if (DataDir->VirtualAddress && (RelocSize = DataDir->Size))
	{
		ULONG_PTR	BaseDelta = ((ULONG_PTR)NewBase - (ULONG_PTR)PeSupGetOptionalField(Pe, ImageBase));
		ULONGLONG	BaseDelta64 = (ULONGLONG)NewBase - ((PIMAGE_NT_HEADERS64)Pe)->OptionalHeader.ImageBase;
		PIMAGE_BASE_RELOCATION_EX	Reloc = (PIMAGE_BASE_RELOCATION_EX)(ImageBase + DataDir->VirtualAddress);

		while(RelocSize > sizeof(IMAGE_BASE_RELOCATION))
		{
			ULONG	NumberRelocs = (Reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);
			PCHAR	PageVa = ImageBase + Reloc->VirtualAddress;

			if (RelocSize >= (LONG)Reloc->SizeOfBlock)
			{
				for (i=0; i<NumberRelocs; i++)
				{
					USHORT	RelocType = (Reloc->TypeOffset[i] >> IMAGE_REL_BASED_SHIFT);

					switch(RelocType)
					{
					case IMAGE_REL_BASED_ABSOLUTE:
						// Do nothing. This one is used just for alingment.
						break;
					case IMAGE_REL_BASED_HIGHLOW:
						*(PULONG)(PageVa + (Reloc->TypeOffset[i] & IMAGE_REL_BASED_MASK)) += (ULONG)BaseDelta;
						break;
					case IMAGE_REL_BASED_DIR64:
						*(PULONG64)(PageVa + (Reloc->TypeOffset[i] & IMAGE_REL_BASED_MASK)) += BaseDelta64;
						break;
					default:
						ASSERT(FALSE);
						break;
					}	// switch(RelocType)
				}	// for (i=0; i<NumberRelocs; i++)
			}	// if (RelocSize >= (LONG)Reloc->SizeOfBlock)
			RelocSize -= (LONG)Reloc->SizeOfBlock;
			Reloc = (PIMAGE_BASE_RELOCATION_EX)((PCHAR)Reloc + Reloc->SizeOfBlock);
		}	// while(RelocSize > IMAGE_SIZEOF_BASE_RELOCATION)
	}	// if (!ImageAtBase && DataDir->VirtualAddress && (RelocSize = DataDir->Size)

	return(Status);
}
