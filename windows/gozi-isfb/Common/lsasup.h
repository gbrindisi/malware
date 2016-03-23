//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ISFB project. Version 2.13.24.1
//	
// module: lsasup.h
// $Revision: 352 $
// $Date: 2014-09-24 20:47:14 +0400 (Ср, 24 сен 2014) $
// description:
//	 NT security support routines: user SID and so on.


// Since there's kinda shit with sddl definitions together with ntdll, we have to redefine theese two functions manually
#if !defined(ConvertStringSecurityDescriptorToSecurityDescriptor)

WINADVAPI
BOOL
WINAPI
ConvertStringSecurityDescriptorToSecurityDescriptorA(
    IN  LPCSTR StringSecurityDescriptor,
    IN  DWORD StringSDRevision,
    OUT PSECURITY_DESCRIPTOR  *SecurityDescriptor,
    OUT PULONG  SecurityDescriptorSize OPTIONAL
    );
WINADVAPI
BOOL
WINAPI
ConvertStringSecurityDescriptorToSecurityDescriptorW(
    IN  LPCWSTR StringSecurityDescriptor,
    IN  DWORD StringSDRevision,
    OUT PSECURITY_DESCRIPTOR  *SecurityDescriptor,
    OUT PULONG  SecurityDescriptorSize OPTIONAL
    );
#ifdef UNICODE
#define ConvertStringSecurityDescriptorToSecurityDescriptor  ConvertStringSecurityDescriptorToSecurityDescriptorW
#else
#define ConvertStringSecurityDescriptorToSecurityDescriptor  ConvertStringSecurityDescriptorToSecurityDescriptorA
#endif // !UNICODE

#endif

#pragma pack(push)
#pragma pack(1)

typedef union _GUID_EX
{
	GUID	Guid;
	struct
	{
		ULONG	Data1;
		ULONG	Data2;
		ULONG	Data3;
		ULONG	Data4;
	};
} GUID_EX, *PGUID_EX;


typedef struct _STRING_LIST_ENTRY
{	
	LIST_ENTRY	Entry;
	_TCHAR		Data[];
} STRING_LIST_ENTRY, *PSTRING_LIST_ENTRY;

#define MOUNTH_SHIFT	10000

#define GUID_STR_LEN	16*2+4+2	// length of the GUID string in chars

// Application default security attributes.
extern	SECURITY_ATTRIBUTES		g_DefaultSA;

#ifndef __cplusplus
//	Fills the NT_SID structure with the specified process SID data.
BOOL	LsaGetProcessUserSID(DWORD Pid, PNT_SID pSid);
#endif


ULONG LsaRandom(PULONG pSeed);

// Returns a NULL-terminated string containing SID of the user that created a process specified by Pid.
// The SID string should be freed by caller.
LPTSTR	LsaGetProcessUserSIDString(DWORD Pid);

// Returns a NULL-terminated string containing a string from UNICODE_STRING.Buffer
// The returned string should be freed by caller.
LPTSTR	LsaStringFromUnicodeString(PUNICODE_STRING uString);

// Returns a DWORD Rid value from the specifed user SID
DWORD	LsaGetRIDFromSIDString(LPTSTR UserSid);

// Generates a string of random characters of a random size
LPTSTR	LsaRndString(PULONG	pSeed, ULONG MinLength, ULONG MaxLength);

// Takes ownership over the specified object
WINERROR LsaTakeOwnership(HANDLE ObjectHandle, ULONG ObjectType);

// Allocates a SECURITY_ATTRIBUTES structure with the specified security descriptor.
BOOL LsaInitializeSecurityAttributes(PSECURITY_ATTRIBUTES pSa, LPTSTR DaclStr);

// Frees the default security descriptor previously allocated by the LsaInitializeDefaultSecurityAttributes()
VOID	LsaFreeSecurityAttributes(PSECURITY_ATTRIBUTES pSa);

// Allocates a SECURITY_ATTRIBUTES structure with the default security descriptor.
#define LsaInitializeDefaultSecurityAttributes(x)	LsaInitializeSecurityAttributes(x, szDefaultDaclStr)

// Allocates a SECURITY_ATTRIBUTES structure with the Low-integrity security descriptor.
#define LsaInitializeLowSecurityAttributes(x)		LsaInitializeSecurityAttributes(x, szLowIntegrityDaclStr)

