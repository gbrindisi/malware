//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// CRYPTO library project. Version 2.1
//	
// module: rc6.h
// $Revision: 156 $
// $Date: 2013-12-03 22:38:41 +0300 (Вт, 03 дек 2013) $
// description: 
//	Cryptographic services provider library.
//	Lightweight RC6 algorithm implementation.

#pragma once

#define	RC6_KEY_SIZE	128				// bits
#define RC6_KEY_CHARS	RC6_KEY_SIZE/8	// bytes
#define	RC6_BLOCK_SIZE	16				// bytes

// Use Cipher-block chaining (CBC) mode instead of Electronic codebook (ECB) mode by default
#define	_RC6_MODE_CBC

typedef unsigned long rc6_key[44];
typedef unsigned char RC6_KEY[RC6_KEY_CHARS], *PRC6_KEY;
typedef unsigned long RC6_CBC_VECTOR[RC6_BLOCK_SIZE/sizeof(long)];

typedef struct{
	rc6_key			skey;
#ifdef _RC6_MODE_CBC
	RC6_CBC_VECTOR	vector;
#endif
} RC6CONTEXT, *HRC6;

#ifdef	__cplusplus
extern "C" {
#endif

void __stdcall RC6KeySetup (HRC6 hAlgorithm, unsigned char* key);
void __stdcall MainRC6Decrypt (HRC6 hAlgorithm, unsigned long* In, unsigned long* Out);
void __stdcall MainRC6Encrypt (HRC6 hAlgorithm, unsigned long* In, unsigned long* Out);

#ifdef	__cplusplus
}
#endif