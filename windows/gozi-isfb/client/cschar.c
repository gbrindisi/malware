//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ISFB project. Version 2.13.24.1
//	
// module: cschar.c
// $Revision: 459 $
// $Date: 2015-01-26 22:53:34 +0300 (Пн, 26 янв 2015) $
// description:
//	Defines constant char sequences allocated within a separate PE-section

#include "..\common\common.h"
#include "..\crypto\crypto.h"
#include "..\config.h"

#ifdef _BC_GENERATE_ID
 CSTCHAR_DEF(szRequestFmtStr);
 CSTCHAR_DEF(szPostFmtStr);
#else
 CSTCHAR_DEF(szRequestFmt);
 CSTCHAR_DEF(szPostFmt);
#endif

CSTCHAR_DEF(szBrowserVersion);
CSTCHAR_DEF(szBrowserArch64);

CSTCHAR_DEF(szHttp);
CSTCHAR_DEF(szHttps);
CSTCHAR_DEF(szVolume);
CSTCHAR_DEF(szVfsUserId);
CSTCHAR_DEF(szLdrFmt);
CSTCHAR_DEF(szLdrUpdFmt);
CSTCHAR_DEF(szDataRegSubkey);
CSTCHAR_DEF(szDataRegDataValue);
CSTCHAR_DEF(szDataRegBlockValue);
CSTCHAR_DEF(szDataRegTemplate);
CSTCHAR_DEF(szDataRegClientId);
CSTCHAR_DEF(szDataRegIniValue);
CSTCHAR_DEF(szDataRegKeysValue);
CSTCHAR_DEF(szDataRegExeValue);
CSTCHAR_DEF(szDot);
CSTCHAR_DEF(szBkSlash);
CSTCHAR_DEF(szTemplateUrl);
CSTCHAR_DEF(szOpenIe);
CSTCHAR_DEF(szAutoPath);
CSTCHAR_DEF(szAppCertDlls);
CSTCHAR_DEF(szText);
CSTCHAR_DEF(szImage);
CSTCHAR_DEF(szJson);
CSTCHAR_DEF(szHtml);
CSTCHAR_DEF(szJavascript);
CSTCHAR_DEF(szBasicFmt);
CSTCHAR_DEF(szURLFmt);
CSTCHAR_DEF(szUserIdFmt);
CSTCHAR_DEF(szUserFmt);
CSTCHAR_DEF(szDeviceFmt);
CSTCHAR_DEF(szStoreVarFmt);
CSTCHAR_DEF(szGrabData);
CSTCHAR_DEF(szHidden);
CSTCHAR_DEF(szDwFmt);
CSTCHAR_DEF(szReplaceUserId);
CSTCHAR_DEF(szReplaceVersion);
CSTCHAR_DEF(szHttpEx);
CSTCHAR_DEF(szExtExe);
CSTCHAR_DEF(szExtBat);
CSTCHAR_DEF(sz64);
CSTCHAR_DEF(szLocal);
CSTCHAR_DEF(szEmptyString);
CSTCHAR_DEF(szPipe);
CSTCHAR_DEF(szMicrosoft);
CSTCHAR_DEF(szAppDataMicrosoft);
CSTCHAR_DEF(szAppData);
CSTCHAR_DEF(szForm);
CSTCHAR_DEF(szLog);
CSTCHAR_DEF(szKeyLog);
CSTCHAR_DEF(szPost);
CSTCHAR_DEF(szGet);
CSTCHAR_DEF(szSocksId);
CSTCHAR_DEF(szBoundary);
CSTCHAR_DEF(szContentTypeMulti);
CSTCHAR_DEF(szContDisp);
CSTCHAR_DEF(szContDispFile);
CSTCHAR_DEF(szContentTypeApp);
CSTCHAR_DEF(szOptional);
CSTCHAR_DEF(szContEnd);
CSTCHAR_DEF(szGuidStrTemp1);
CSTCHAR_DEF(szGuidStrTemp2);
CSTCHAR_DEF(szDefaultDaclStr);
CSTCHAR_DEF(szLowIntegrityDaclStr);
CSTCHAR_DEF(szOpen);
CSTCHAR_DEF(szBatFmt);
CSTCHAR_DEF(szBatchFile);
CSTCHAR_DEF(szVars);
CSTCHAR_DEF(szFiles);
CSTCHAR_DEF(szRun);
CSTCHAR_DEF(szDataUrl);
CSTCHAR_DEF(szUpd);
CSTCHAR_DEF(szSd);
CSTCHAR_DEF(szLdrSdFmt);
CSTCHAR_DEF(szClientDll);
CSTCHAR_DEF(szClientDll64);
CSTCHAR_DEF(szNtCurrentVersion);
CSTCHAR_DEF(szSystemRoot);

CSTCHAR_DEF(szCopyTmpl);

CSWCHAR_DEF(wczFfProfiles);
CSWCHAR_DEF(wczSolFiles);
CSWCHAR_DEF(wczFFCookie1);
CSWCHAR_DEF(wczFFCookie2);
CSWCHAR_DEF(wczSol);
CSWCHAR_DEF(wczTxt);
CSWCHAR_DEF(wczFfCookies);
CSWCHAR_DEF(wczIeCookies);
CSWCHAR_DEF(wczSols);
CSWCHAR_DEF(wczDosDevicePrefix);
CSWCHAR_DEF(wczMaskAll);
CSWCHAR_DEF(wczISFB);
CSWCHAR_DEF(wczSpdyOff);
CSWCHAR_DEF(wczImageGif);
CSWCHAR_DEF(wczReportFormat);
CSWCHAR_DEF(wczFormatClipbrd);
CSWCHAR_DEF(wczWinExplorer);
CSWCHAR_DEF(wczDelegateExecute);
CSWCHAR_DEF(wczClassesChrome);
CSWCHAR_DEF(wczCommand);
CSWCHAR_DEF(wczFindAll);

CSCHAR_DEF(szInternetSettings);
CSCHAR_DEF(szEnableSpdy);

CSCHAR_DEF(szWininet);
CSCHAR_DEF(szNspr4);
CSCHAR_DEF(szNss3);
CSCHAR_DEF(szChrome);
CSCHAR_DEF(szWS2_32);
CSCHAR_DEF(szOpera);
CSCHAR_DEF(szWsock32);
CSCHAR_DEF(szWininetDll);
CSCHAR_DEF(szKernel32);
CSCHAR_DEF(szAdvapi32);
CSCHAR_DEF(szNtdll);
CSCHAR_DEF(szKernelbase);
CSCHAR_DEF(szHost);
CSCHAR_DEF(szUserAgent);
CSCHAR_DEF(szConnection);
CSCHAR_DEF(szContentMd5);
CSCHAR_DEF(szContentType);
CSCHAR_DEF(szContentLength);
CSCHAR_DEF(szTransferEncoding);
CSCHAR_DEF(szAcceptEncoding);
CSCHAR_DEF(szReferer);
CSCHAR_DEF(szAcceptLanguage);
CSCHAR_DEF(szCookie);
CSCHAR_DEF(szSecPolicy);
CSCHAR_DEF(szSecPolicyReport);
CSCHAR_DEF(szXFrameOptions);
CSCHAR_DEF(szAccessCtrlOrigin);
CSCHAR_DEF(szChunkSize);
CSCHAR_DEF(szContentLengthTmp);
CSCHAR_DEF(szOCSP);
CSCHAR_DEF(szChunked);
CSCHAR_DEF(szIdentity);
CSCHAR_DEF(szEmptyStr);
CSCHAR_DEF(sz404);
CSCHAR_DEF(sz200);
CSCHAR_DEF(szTimeMask);
CSCHAR_DEF(szLogFailed);
CSCHAR_DEF(szLogCmdProcessed);
CSCHAR_DEF(szLogCmdComplete);
CSCHAR_DEF(szLogCmdParsing);
CSCHAR_DEF(szPR_Read);
CSCHAR_DEF(szPR_Write);
CSCHAR_DEF(szPR_Close);

#ifndef _USE_ZIP
 CSCHAR_DEF(szDiskDirectory);
 CSCHAR_DEF(szCabinetName);
 CSCHAR_DEF(szDestinationDir);
 CSCHAR_DEF(szQuotes);
 CSCHAR_DEF(szSetup1);
 CSCHAR_DEF(szSetup2);
 CSCHAR_DEF(szMakeCabParam);
#endif

#ifdef _ENABLE_SYSINFO
 CSCHAR_DEF(szCmdParam);
 CSCHAR_DEF(szSysinfoParam);
 CSCHAR_DEF(szTasklistParam);
 CSCHAR_DEF(szDriverParam);
 CSCHAR_DEF(szRegParam);
 CSCHAR_DEF(szTypeParam);
 CSCHAR_DEF(szInfoDelimiter);
#endif

CSCHAR_DEF(szUnknown);
CSCHAR_DEF(szDotPfx);
CSCHAR_DEF(szMy);
CSCHAR_DEF(szAddressBook);
CSCHAR_DEF(szAuthRoot);
CSCHAR_DEF(szCertificateAuthority);
CSCHAR_DEF(szDisallowed);
CSCHAR_DEF(szRoot);
CSCHAR_DEF(szTrustedPeople);
CSCHAR_DEF(szTrustedPublisher);
CSCHAR_DEF(szInternetSetStatusCallback);
CSCHAR_DEF(szHttpAddRequestHeadersW);
CSCHAR_DEF(szHttpAddRequestHeadersA);
CSCHAR_DEF(szHttpQueryInfoW);
CSCHAR_DEF(szHttpQueryInfoA);
CSCHAR_DEF(szInternetConnectW);
CSCHAR_DEF(szInternetConnectA);
CSCHAR_DEF(szInternetQueryDataAvailable);
CSCHAR_DEF(szHttpSendRequestW);
CSCHAR_DEF(szHttpSendRequestA);
CSCHAR_DEF(szInternetReadFileExW);
CSCHAR_DEF(szInternetReadFileExA);
CSCHAR_DEF(szInternetWriteFile);
CSCHAR_DEF(szInternetReadFile);
CSCHAR_DEF(szHttpOpenRequestW);

CSCHAR_DEF(szrecv);
CSCHAR_DEF(szclosesocket);
CSCHAR_DEF(szWSASend);
CSCHAR_DEF(szWSARecv);
CSCHAR_DEF(szLoadLibraryExW);
CSCHAR_DEF(szRegQueryValueExW);
CSCHAR_DEF(szRegGetValueW);
CSCHAR_DEF(szPR_Poll);
CSCHAR_DEF(szPR_GetError);
CSCHAR_DEF(szPR_SetError);
CSCHAR_DEF(szExitProcess);
CSCHAR_DEF(szIsWow64Process);
CSCHAR_DEF(szWow64EnableWow64FsRedirection);
CSCHAR_DEF(szCreateProcessA);
CSCHAR_DEF(szLdrRegisterDllNotification);
CSCHAR_DEF(szLdrUnregisterDllNotification);

#ifndef _WIN64
 CSCHAR_DEF(szZwWow64QueryInformationProcess64);
 CSCHAR_DEF(szZwWow64ReadVirtualMemory64);
#endif

CSCHAR_DEF(szZwGetContextThread);
CSCHAR_DEF(szZwSetContextThread);
CSCHAR_DEF(szZwProtectVirtualMemory);
CSCHAR_DEF(szZwWriteVirtualMemory);
CSCHAR_DEF(szLdrLoadDll);
CSCHAR_DEF(szLdrGetProcedureAddress);
CSCHAR_DEF(szRtlSetUnhandledExceptionFilter);

CSCHAR_DEF(szCryptGetUserKey);
CSCHAR_DEF(szLoadLibraryA);
CSCHAR_DEF(szExitThread);
CSCHAR_DEF(szDateTimeFmt);
CSCHAR_DEF(szPluginRegisterCallbacks);

CSCHAR_DEF(szRdataSec);
CSCHAR_DEF(szTextSec);
CSCHAR_DEF(szDataSec);

#if (defined(_ENABLE_VIDEO) && !defined(_AVI_VIDEO))
 CSCHAR_DEF(szGifSign);
 CSCHAR_DEF(szGif87a);
 CSCHAR_DEF(szGif89a);
 CSCHAR	cNetscapeExt[19] = {0x21, 0xff, 0x0b, 'N', 'E', 'T', 'S', 'C', 'A', 'P', 'E', '2', '.', '0', 0x3, 0x1, 0x0, 0x0, 0x0};
#endif
