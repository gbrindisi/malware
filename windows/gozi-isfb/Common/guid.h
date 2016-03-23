//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ISFB project. Version 2.13.24.1
//	
// module: guid.h
// $Revision: 253 $
// $Date: 2014-06-10 21:16:12 +0400 (Вт, 10 июн 2014) $
// description:
//	Pseudo-random GUIDs.

#define		GUID_STR_LENGTH		16*2+4+2	// length of the GUID string in chars (not including NULL-char)

VOID	GenGuid(GUID* pGuid, PULONG pSeed);
LPTSTR	GenGuidName(PULONG pSeed, LPTSTR Prefix OPTIONAL, LPTSTR Postfix OPTIONAL, BOOL bQuoted);
VOID	FillGuidName(PULONG	pSeed, LPTSTR pGuidName);
LPTSTR	GuidToString(GUID* pGuid, BOOL bQuoted);
ULONG	GuidToBuffer(GUID* pGuid, LPTSTR pBuffer, BOOL bQuoted);
