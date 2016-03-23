//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// CRYPTO library project. Version 2.1
//	
// module: sign.c
// $Revision: 34 $
// $Date: 2013-03-12 16:00:51 +0300 (Вт, 12 мар 2013) $
// description: 
//	Cryptographic services provider library.
//	Digital signing.

#include "..\common\main.h"
#include "stdio.h"
#include "crypto.h"

//#define	_ENABLE_OUTPUT	TRUE

#define		RSA_BLOCK_LENGTH	(MAX_RSA_MODULUS_BITS / 8)

// File digital signature header structure.
typedef union	_DS_HEADER
{
	struct 
	{
		MD5		Md5;	// MD5 hash of the signed data buffer
		RC6_KEY	Key;	// RC6 key used to encrypt the buffer
		ULONG	Size;	// Size of the buffer in bytes
		ULONG	Salt;	// Random value
	};
	CHAR	Padding[RSA_BLOCK_LENGTH / 2];
} DS_HEADER, *PDS_HEADER;


//
//	Adds to the specified source buffer DS_HEADER structure containing buffer digital signature.
//	Returns the buffer with signed data and the size of this buffer.
//	The caller is responsible for freeing the buffer.
//
ULONG __stdcall DsSign(
	PCHAR	InBuffer,	// Source data buffer
	ULONG	InSize,		// Size of the source buffer in bytes
	PCHAR*	pOutBuffer,	// Variable that receives pointer to a signed buffer
	PCHAR	pRsaKey,	// RSA key used to sign the buffer
	BOOL	bEncrypt,	// Specify TRUE if the source buffer needs to be encrypted before signing
	BOOL	bResize		// Specify TRUE if the buffer size needs to be randomizes (by adding few non-significant bytes)
	)
{
	BOOL		CryptSize, OutSize = 0;
	PCHAR		CryptBuffer = NULL, OutBuffer = NULL;
	DS_HEADER	DsHeader;
	UCHAR		Ds[RSA_BLOCK_LENGTH] = {0};
	ULONG		ResSize = 0, DsSize = RSA_BLOCK_LENGTH;

	// Randomizing DsHeader
	RsaRandom(AppRand());
	RndSet((PUCHAR)&DsHeader, sizeof(DS_HEADER));

	// Calculating MD5 checksum of the data within InBuffer
	BufferToMd5(InBuffer, InSize, &DsHeader.Md5);
	DsHeader.Size = InSize;

	do	// not a loop
	{
		if (bEncrypt)
		{
			// Ecrypting the InBuffer data with random-generated RC6 key
			if (RC6EncryptDecryptBuffer(InBuffer, InSize, &CryptBuffer, &CryptSize, (PRC6_KEY)&DsHeader.Key, TRUE) != NO_ERROR)
				break;
			InBuffer = CryptBuffer;
			InSize = CryptSize;
		}
		else
			// Zeroing RC6 key value
			memset(&DsHeader.Key, 0, sizeof(RC6_KEY));

		if (!RsaEncryptWithPrivate((PUCHAR)&Ds, &DsSize, (PUCHAR)&DsHeader, sizeof(DS_HEADER), pRsaKey))
			break;
		
		ASSERT(DsSize == RSA_BLOCK_LENGTH);
		OutSize = InSize + DsSize;

		if (bResize)
			OutSize += (ResSize = RsaRandom(0) % RC6_BLOCK_SIZE);

		if (!(OutBuffer = AppAlloc(OutSize)))
		{
			OutSize = 0;
			break;
		}

		// Copying original (or encrypted) data
		memcpy(OutBuffer, InBuffer, InSize);
		// Randomizing data size (if needed)
		RndSet(OutBuffer + InSize, ResSize);
		// Adding digital signature
		memcpy(OutBuffer + InSize + ResSize, &Ds, DsSize);

		*pOutBuffer = OutBuffer;
		ASSERT(OutSize > 0);

#ifdef	_ENABLE_OUTPUT
		DbgPrint("CRYPTO: Signing: source file 0x%X of %u bytes, target file 0x%X of %u bytes\n", Crc32(InBuffer, InSize), InSize, Crc32(OutBuffer, OutSize), OutSize);
#endif
		
	} while(FALSE);

	if (CryptBuffer)
		AppFree(CryptBuffer);

	return(OutSize);
}

//
//	Verifies and removes digital signature from the data within the specified source buffer.
//	Decrypts the data if it was encrypted.
//	Returns the buffer with the unsigned data and the size of this buffer.
//	The caller is responsible for freeing the buffer.
//
ULONG __stdcall DsUnsign(
	PCHAR	InBuffer,	// Source buffer containing signed (and maybe encrypted) data
	ULONG	InSize,		// Size of the source buffer in bytes
	PCHAR*	pOutBuffer,	// Variable that receives pointer to unsigned data
	PCHAR	pRsaKey		// RSA key used for signing
	)
{
	ULONG		i, DsSize = 0, OutSize = 0;
	PCHAR		OutBuffer = NULL, pDs;
	DS_HEADER	DsHeader;
	BOOL		bEncrypt = FALSE;
	MD5			Md5;

#ifdef	_ENABLE_OUTPUT
		DbgPrint("CRYPTO: Unsigning: source file 0x%X of %u bytes\n", Crc32(InBuffer, InSize), InSize);
#endif


	do	// not a loop
	{
		if (InSize <= RSA_BLOCK_LENGTH)
			break;

		pDs = InBuffer + InSize - RSA_BLOCK_LENGTH;
		if (!RsaDecryptWithPublic((PUCHAR)&DsHeader, &DsSize, pDs, RSA_BLOCK_LENGTH, pRsaKey))
			break;

		ASSERT(DsSize == sizeof(DS_HEADER));

		if (DsHeader.Size > (InSize -= RSA_BLOCK_LENGTH))
			break;

		// Checking if the data within the buffer was encrypted (i.e. DsHeader.Key != 0)
		for (i=0; i<sizeof(RC6_KEY); i++)
		{
			if (((PCHAR)&DsHeader.Key)[i] != 0)
			{
				bEncrypt = TRUE;
				break;
			}
		}

		if (bEncrypt) 
		{
			// The data within the buffer is encrypted, decrypting
			if (RC6EncryptDecryptBuffer(InBuffer, InSize, &OutBuffer, &OutSize, (PRC6_KEY)&DsHeader.Key, FALSE) != NO_ERROR)
			{
				ASSERT(OutSize == 0);
				break;
			}

			if (OutSize != ((DsHeader.Size + (RC6_BLOCK_SIZE - 1)) & (~(RC6_BLOCK_SIZE - 1))))
			{
				OutSize = 0;
				break;
			}

			OutSize = DsHeader.Size;
		}
		else
		{
			// The data within the buffer was not encrypted
			OutSize = DsHeader.Size;
			if (!(OutBuffer = AppAlloc(OutSize)))
				memcpy(OutBuffer, InBuffer, OutSize);
			else
			{
				OutSize = 0;
				break;
			}
		}

		// Calculating MD5 hash of the data
		BufferToMd5(OutBuffer, OutSize, &Md5);

		// Comparing the hash with the DsHeader.Md5 field
		if (!CompareMd5(&Md5, &DsHeader.Md5))
		{
			// Hashes do not match
			OutSize = 0;
			break;
		}

		*pOutBuffer = OutBuffer;			
		ASSERT(OutSize > 0);

	} while(FALSE);

	if (OutSize == 0 && OutBuffer)
		AppFree(OutBuffer);

	return(OutSize);
}
