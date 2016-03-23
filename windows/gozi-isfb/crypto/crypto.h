//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// CRYPTO library project. Version 2.1
//	
// module: crypto.h
// $Revision: 457 $
// $Date: 2015-01-26 18:40:30 +0300 (Пн, 26 янв 2015) $
// description: 
//	Cryptographic services provider library. Main include file.
//	Defines RSA, RC6, MD5, SHA1, AES, DES, Blowfish, CRC32, BASE64 and simple XOR algorithms.

#pragma once

#include "rsa.h"
#include "md5lib.h"
#include "rc6.h"
#include "des.h"
#include "serpent.h"
#include "rc4.h"


#ifdef	__cplusplus
extern "C" {
#endif

// Theese external functions used by CRYPTO library are application-specific:
//	they should be defined anywhere in a target project.
PVOID	__stdcall AppAlloc(ULONG Size);
VOID	__stdcall AppFree(PVOID pMem);
ULONG	__stdcall AppRand(VOID);


// ---- XOR --------------------------------------------------------------------------------------------------------------
VOID	XorRotateBuffer(PCHAR Buffer, ULONG Size, ULONG XorValue, ULONG RotValue, BOOL bForward);

VOID __stdcall XorEncryptBuffer(
	PCHAR	pBuffer,	// data buffer
	ULONG	Size,		// size of the buffer in bytes
	ULONG	Key,		// key value
	BOOL	bSkipZero	// TRUE to skip zero dwords
	);

VOID __stdcall XorDecryptBuffer(
	PCHAR	pBuffer,	// buffer containing encrypted data
	ULONG	Size,		// size of the buffer in bytes
	ULONG	Key,		// key value
	BOOL	bSkipZero	// TRUE to skip zero dwords
	);

// ---- MD5 --------------------------------------------------------------------------------------------------------------
LONG	BufferToMd5(PCHAR Buffer, ULONG Length, PMD5 md5);
BOOL	CompareMd5(PMD5 Md5a, PMD5 Md5b);

// ---- RSA --------------------------------------------------------------------------------------------------------------

USHORT __stdcall RsaRandom(ULONG Seed);

LONG RsaGenerateKeys(PVOID* PublicKey, PULONG PublicKeyLen, PVOID* PrivateKey, PULONG PrivateKeyLen);

LONG RsaEncryptWithPublic (
	PUCHAR	output,                             /* output block */
	PULONG	outputLen,                          /* length of output block */
	PUCHAR	input,                              /* input block */
	ULONG	inputLen,                           /* length of input block */
	PVOID	publicKey                           /* RSA public key */
	);


LONG RsaEncryptWithPrivate (
	PUCHAR	output,                             /* output block */
	PULONG	outputLen,                          /* length of output block */
	PUCHAR	input,                              /* input block */
	ULONG	inputLen,                           /* length of input block */
	PVOID	privateKey                          /* RSA private key */
	);


LONG RsaDecryptWithPublic (
	PUCHAR  output,                             /* output block */
	PULONG	outputLen,                          /* length of output block */
	PUCHAR	input,                              /* input block */
	ULONG	inputLen,                           /* length of input block */
	PVOID	publicKey                           /* RSA public key */
	);


// ---- CRC32 ------------------------------------------------------------------------------------------------------------

//
//	Caclulates CRC32 hash of the data within the specified buffer
//
ULONG Crc32(
	PCHAR pMem,		// data buffer
	ULONG uLen		// length of the buffer in bytes
	);


// ---- BASE64 -----------------------------------------------------------------------------------------------------------

#define B64_DEF_LINE_SIZE   255

/*
** base64 encode a stream adding padding and line breaks as per spec.
*/
void __stdcall b64encode(char* inbuf, char* outbuf, int linesize);

/*
** decode a base64 encoded stream discarding padding, line breaks and noise
*/
void __stdcall b64decode(char* inbuf, char* outbuf);


int __stdcall B64EncodeBuffer( char* inbuf, char* outbuf, int length, int linesize );
int __stdcall B64DecodeBuffer(char* inbuf, char* outbuf, long length);


// ---- Encrypt\Decrypt strings ---------------------------------------------------------------------------------------------

ULONG RC6EncryptDecryptBuffer(
	PCHAR		InBuf,
	ULONG		InSize,
	PCHAR*		pOutBuf,
	PULONG		pOutSize,
	PRC6_KEY	pRc6Key,
	BOOL		bEncrypt
	);

PCHAR __stdcall RC6EncryptStringToB64(
	PCHAR		SourceStr,
	PRC6_KEY	pKey
	);

PCHAR __stdcall RC6DecryptStringFromB64(
	PCHAR		SourceStr,
	PRC6_KEY	pKey
	);

PCHAR __stdcall GenScriptLine(
	PCHAR Template
	);

PCHAR __stdcall ObfuscateParamStr(
	PCHAR		SourceStr,	// the source string to obfuscate
	PRC6_KEY	pKey		// RC6 key
	);

VOID RC6EncryptDecrypt(
	HRC6		hRC6,
	PCHAR		InBuf,		// Source buffer to encrypt/decrypt, should be RC6_BLOCK_SIZE  aligned
	PCHAR		OutBuf,		// Destination buffer to encrypt/decrypt, should be RC6_BLOCK_SIZE  aligned
	ULONG		BufSize,	// Source and dest buffer size in bytes
	BOOL		bEncrypt	// Set TRUE to encrypt or FALSE to decrypt the data
	);
// ---- Digital signing ----------------------------------------------------------------------------------------------------


VOID RndSet(
	PUCHAR	Buffer,	// Pointer to a mamory buffer to fill with random bytes
	ULONG	Size	// Size of the buffer in bytes
	);

ULONG __stdcall DsSign(
	PCHAR	InBuffer,	// Source data buffer
	ULONG	InSize,		// Size of the source buffer in bytes
	PCHAR*	pOutBuffer,	// Variable that receives pointer to a signed buffer
	PCHAR	pRsaKey,	// RSA key used to sign the buffer
	BOOL	bEncrypt,	// Specify TRUE if the source buffer needs to be encrypted before signing
	BOOL	bResize		// Specify TRUE if the buffer size needs to be randomizes (by adding few non-significant bytes)
	);

ULONG __stdcall DsUnsign(
	PCHAR	InBuffer,	// Source buffer containing signed (and maybe encrypted) data
	ULONG	InSize,		// Size of the source buffer in bytes
	PCHAR*	pOutBuffer,	// Variable that receives pointer to unsigned data
	PCHAR	pRsaKey		// RSA key used for signing
	);


// ---- SHA1 ----------------------------------------------------------------------------------------------------------------

typedef struct {
    DWORD state[5];
    DWORD count[2];
    BYTE  buffer[64];
} SHA1_CTX;

#define SHA1_DIGEST_SIZE 20

void __stdcall SHA1_Init(SHA1_CTX* context);
void __stdcall SHA1_Update(SHA1_CTX* context, const BYTE* data, const size_t len);
void __stdcall SHA1_Final(SHA1_CTX* context, BYTE digest[SHA1_DIGEST_SIZE]);


// ---- Blowfish -------------------------------------------------------------------------------------------------------------

#define BLOWFISH_BLOCK_SIZE 16
  
typedef struct {
	unsigned long P[16 + 2];
	unsigned long S[4][256];
} BLOWFISH_CTX;

void __stdcall Blowfish_Init(BLOWFISH_CTX *ctx, unsigned char *key, int keyLen);
void __stdcall Blowfish_Encrypt(BLOWFISH_CTX *ctx, unsigned long *xl, unsigned long *xr);
void __stdcall Blowfish_Decrypt(BLOWFISH_CTX *ctx, unsigned long *xl, unsigned long *xr);


// ---- AES -------------------------------------------------------------------------------------------------------------------

#define AES_ENCRYPT	1
#define AES_DECRYPT	0

/* Because array size can't be a const in C, the following two are macros.
   Both sizes are in bytes. */
#define AES_MAXNR 14
#define AES_BLOCK_SIZE 16

/* This should be a hidden type, but EVP requires that the size be known */
struct aes_key_st {
	unsigned long rd_key[4 *(AES_MAXNR + 1)];
	int rounds;
};

typedef struct aes_key_st AES_KEY;

int __stdcall AES_set_encrypt_key(const unsigned char *userKey, const int bits, AES_KEY *key);
void __stdcall AES_encrypt(const unsigned char *in, unsigned char *out, const AES_KEY *key);

int __stdcall AES_set_decrypt_key(const unsigned char *userKey, const int bits, AES_KEY *key);
void __stdcall AES_decrypt(const unsigned char *in, unsigned char *out, const AES_KEY *key);


#ifdef	__cplusplus
}	// extern "C"
#endif