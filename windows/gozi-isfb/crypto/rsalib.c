#include "main.h"
#include "dbg.h"


#include "rsa.h"
#include "md5.h"
#include "md5lib.h"


#define RSA_BLOCK_SIZE 0x40	// bytes

static	ULONG	RndSeed = 0;

USHORT RsaRandom()
{
	return((USHORT)(RndSeed = 1664525*(RndSeed)+1013904223));
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

VOID RndSet(PUCHAR rndbuf, ULONG size)
{
	ULONG i;
	RndSeed = GetTickCount();

	for (i=0; i<size; i++)
	{
		rndbuf[i] = (UCHAR)RsaRandom();
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
	R_RSA_PUBLIC_KEY* RsaPublicKey;
	R_RSA_PRIVATE_KEY* RsaPrivateKey;

	do 
	{
		if (!(RsaPublicKey = (R_RSA_PUBLIC_KEY*) Alloc(sizeof(R_RSA_PUBLIC_KEY))))
		{
			DbgPrint("Out of memory while allocating RSA public key.\n");
			break;
		}

		if (!(RsaPrivateKey = (R_RSA_PRIVATE_KEY*) Alloc(sizeof(R_RSA_PRIVATE_KEY))))
		{
			DbgPrint("Out of memory while allocating RSA private key.\n");
			break;
		}

		if (!RsaGenerateKeysInternal(RsaPublicKey, RsaPrivateKey))
		{
			DbgPrint("Error generatin keys.\n")
			break;
		}

		*PublicKeyLen = sizeof(R_RSA_PUBLIC_KEY);
		*PrivateKeyLen = sizeof(R_RSA_PRIVATE_KEY);

		*PublicKey = (PVOID)RsaPublicKey;
		*PrivateKey = (PVOID)RsaPrivateKey;

		return(TRUE);
	}while(FALSE);

	if (RsaPublicKey)
		Free(RsaPublicKey);

	if (RsaPrivateKey)
		Free(RsaPrivateKey);

	return(FALSE);
}



///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


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
