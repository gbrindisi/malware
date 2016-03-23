//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// CRYPTO library project. Version 2.1
//	
// module: crypto.c
// $Revision: 197 $
// $Date: 2014-02-10 14:46:47 +0300 (Пн, 10 фев 2014) $
// description: 
//	Cryptographic services provider library.
//	Defines RSA, RC6, MD5, SHA1, AES, Blowfish, CRC32, BASE64 algorithms.

#include "..\common\main.h"

#include "rsa.h"
#include "md5.h"
#include "md5lib.h"
#include "crypto.h"


#define RSA_BLOCK_SIZE 0x40	// bytes

static	ULONG	g_RndSeed = 0;

USHORT __stdcall RsaRandom(ULONG Seed)
{
	if (Seed)
		g_RndSeed = Seed;
	return((USHORT)(g_RndSeed = 1664525*(g_RndSeed)+1013904223));
}


LONG RsaEncryptWithPublic (PUCHAR output, PULONG outputLen, PUCHAR input, ULONG inputLen, PVOID publicKey)
{
	return(FALSE);
}


LONG RsaEncryptWithPrivate (PUCHAR output,	PULONG outputLen, PUCHAR input, ULONG inputLen, PVOID privateKey)
{
	ULONG Status = FALSE;
	R_RSA_PRIVATE_KEY* RsaPrivateKey = (R_RSA_PRIVATE_KEY*) privateKey;
	if (RSAPrivateEncrypt(output, (unsigned int*)outputLen, input, inputLen, RsaPrivateKey) == 0)
			Status = TRUE;

	return(Status);

}


LONG RsaDecryptWithPublic (PUCHAR output,	PULONG outputLen, PUCHAR input, ULONG inputLen, PVOID publicKey)
{
	ULONG Status = FALSE;
	R_RSA_PUBLIC_KEY* RsaPublicKey = (R_RSA_PUBLIC_KEY*) publicKey;
	if (RSAPublicDecrypt(output, (unsigned int*)outputLen, input, inputLen, RsaPublicKey) == 0)
			Status = TRUE;

	return(Status);	
}

//
//	Fills the specified buffer of the specified size with random bytes.
//
VOID RndSet(
	PUCHAR	Buffer,	// Pointer to a mamory buffer to fill with random bytes
	ULONG	Size	// Size of the buffer in bytes
	)
{
	ULONG i;
	g_RndSeed = AppRand();

	for (i=0; i<Size; i++)
	{
		Buffer[i] = (UCHAR)RsaRandom(0);
	}
}

LONG RsaGenerateKeysInternal(R_RSA_PUBLIC_KEY* pPublic, R_RSA_PRIVATE_KEY* pPrivate)
{
	ULONG Status = FALSE;
	UCHAR rndbuf[RSA_BLOCK_SIZE];
	R_RANDOM_STRUCT  rnd_struct;
	ULONG needed = 1;
	R_RSA_PROTO_KEY proto_key = {MIN_RSA_MODULUS_BITS, 1};
	
	R_RandomInit(&rnd_struct);

	while (needed) {
		RndSet(rndbuf, sizeof(rndbuf));
		R_RandomUpdate(&rnd_struct, rndbuf, sizeof(rndbuf));
		R_GetRandomBytesNeeded(&needed, &rnd_struct);
	}

	if (R_GeneratePEMKeys(pPublic, pPrivate, &proto_key, &rnd_struct) == 0) 
		Status = TRUE;
	
	R_RandomFinal(&rnd_struct);
	memset(rndbuf, 0, sizeof(rndbuf));

	return(Status);
}
	

LONG RsaGenerateKeys(PVOID* PublicKey, ULONG* PublicKeyLen, PVOID* PrivateKey, ULONG* PrivateKeyLen)
{
	R_RSA_PUBLIC_KEY* RsaPublicKey = NULL;
	R_RSA_PRIVATE_KEY* RsaPrivateKey = NULL;

	do 
	{
		if (!(RsaPublicKey = (R_RSA_PUBLIC_KEY*) AppAlloc(sizeof(R_RSA_PUBLIC_KEY))))
			// Out of memory while allocating RSA public key
			break;

		if (!(RsaPrivateKey = (R_RSA_PRIVATE_KEY*) AppAlloc(sizeof(R_RSA_PRIVATE_KEY))))
			// Out of memory while allocating RSA private key
			break;

		if (!RsaGenerateKeysInternal(RsaPublicKey, RsaPrivateKey))
			// Error generating keys
			break;

		*PublicKeyLen = sizeof(R_RSA_PUBLIC_KEY);
		*PrivateKeyLen = sizeof(R_RSA_PRIVATE_KEY);

		*PublicKey = (PVOID)RsaPublicKey;
		*PrivateKey = (PVOID)RsaPrivateKey;

		return(TRUE);
	}while(FALSE);

	if (RsaPublicKey)
		AppFree(RsaPublicKey);

	if (RsaPrivateKey)
		AppFree(RsaPrivateKey);

	return(FALSE);
}



///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


//
//	Calculates MD5 hash of the data within the specified buffer.
//
LONG BufferToMd5(PCHAR Buffer, ULONG Length, PMD5 md5)
{
	UCHAR digest[0x10];
	MD5_CTX ctx;

	MD5Init(&ctx);
	MD5Update(&ctx, Buffer, Length);
	MD5Final(digest, &ctx);
	memcpy(md5, digest, 0x10);

	return(TRUE);
}


//
//	Compares two MD5 hashes, returns TRUE if they are equal or FALSE if not.
//
BOOL CompareMd5(PMD5 Md5a, PMD5 Md5b)
{
	if (Md5a->dd0 == Md5b->dd0 && Md5a->dd1 == Md5b->dd1 && Md5a->dd2 == Md5b->dd2 && Md5a->dd3 == Md5b->dd3)
		return(TRUE);
	else
		return(FALSE);
}


//
//	Prforms light encryption over the specified buffer by xoring and rotaiting it DWORDs.
//
VOID XorRotateBuffer(
	PCHAR Buffer,	// pointer to a buffer with binary data
	ULONG Size,		// size of the buffer in bytes
	ULONG XorValue, // value to XOR with
	ULONG RotValue,	// value to rotate with
	BOOL bForward	// specifies encryption direction forward (encrypt) if TRUE or backword (decrypt) if FALSE
	)
{
	ULONG dSize = Size / sizeof(ULONG);
	ULONG bSize = Size % sizeof(ULONG);
	PULONG	dBuffer = (PULONG)Buffer;
	PUCHAR	bBuffer;

	while(dSize)
	{
		ULONG Value = *dBuffer;

		if (bForward)
			Value = _rotl(((Value + dSize) ^ XorValue), (UCHAR)(dSize + RotValue));
		else
			Value = (_rotr(Value, (UCHAR)(dSize + RotValue)) ^ XorValue) - dSize;

		*dBuffer = Value;
		dBuffer += 1;
		dSize -= 1;
	}

	bBuffer = (PUCHAR)dBuffer;
	while(bSize)
	{
		UCHAR Value = *bBuffer;

		Value ^= (UCHAR)XorValue;

		*bBuffer = Value;
		bBuffer += 1;
		bSize -= 1;
	}
}


//
//	Encrypts the specified memory buffer by XORing it's data with the specified key value in CBC manner.
//
VOID __stdcall XorEncryptBuffer(
	PCHAR	pBuffer,	// data buffer
	ULONG	Size,		// size of the buffer in bytes
	ULONG	Key,		// key value
	BOOL	bSkipZero	// TRUE to skip zero dwords
	)
{
	PULONG	pDwords = (PULONG)pBuffer;
	ULONG	uDword, uVector = 0, Count = 0;

	if (Size /= sizeof(ULONG))
	{
		do
		{
			uDword = *pDwords;

			if (bSkipZero && uDword == 0 && Size > 1 && pDwords[1] == 0)
				break;

			uDword = _rotl(uDword, Count += 1);
			uDword ^= uVector;
			uDword ^= Key;
			uVector = uDword;

			*pDwords = uDword;
			pDwords += 1;
		} while(Size -=1);
	}	// if (Size /= sizeof(ULONG))
}



//
//	Decrypts the specified memory buffer by XORing it's data with the specified key value in CBC manner.
//
VOID __stdcall XorDecryptBuffer(
	PCHAR	pBuffer,	// buffer containing encrypted data
	ULONG	Size,		// size of the buffer in bytes
	ULONG	Key,		// key value
	BOOL	bSkipZero	// TRUE to skip zero dwords
	)
{
	PULONG	pDwords = (PULONG)pBuffer;
	ULONG	uDword, uLast, uVector = 0, Count = 0;

	if (Size /= sizeof(ULONG))
	{
		do
		{
			uLast = uDword = *pDwords;
			if (bSkipZero && uDword == 0)
				break;

			uDword ^= Key;
			uDword ^= uVector;
			uDword = _rotr(uDword, Count += 1);
			uVector = uLast;

			*pDwords = uDword;
			pDwords += 1;
		} while(Size -= 1);
	}	// if (Size /= sizeof(ULONG))
}



//
//	Caclulates CRC32 hash of the data within the specified buffer
//
ULONG Crc32(
	PCHAR pMem,		// data buffer
	ULONG uLen		// length of the buffer in bytes
	)
{
  ULONG		i, c;
  ULONG		dwSeed =  -1;

  while( uLen-- )
  {
	  c = *pMem;
	  pMem = pMem + 1;
	  
	  for( i = 0; i < 8; i++ )
	  {
		  if ( (dwSeed ^ c) & 1 )
			  dwSeed = (dwSeed >> 1) ^ 0xEDB88320;
		  else
			  dwSeed = (dwSeed >> 1);
		  c >>= 1;
	  }
  }
  return(dwSeed);
}

