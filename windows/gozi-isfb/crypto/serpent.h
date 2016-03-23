//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// CRYPTO library project. Version 2.1
//	
// module: serpent.h
// $Revision: 216 $
// $Date: 2014-02-28 20:06:42 +0300 (Пт, 28 фев 2014) $
// description: 
//	Cryptographic services provider library.
//	Lightweight Serpent algorithm implementation


#pragma once

#define	_SERPENT

#define	SERPENT_KEY_SIZE	128					// bits
#define SERPENT_KEY_CHARS	SERPENT_KEY_SIZE/8	// bytes
#define	SERPENT_BLOCK_SIZE	16					// bytes

// Use Cipher-block chaining (CBC) mode instead of Electronic codebook (ECB) mode by default
#define	_SERPENT_MODE_CBC

typedef unsigned long SERPENT_CBC_VECTOR[SERPENT_BLOCK_SIZE/sizeof(long)];

typedef struct {
	unsigned long		key[140];
#ifdef _SERPENT_MODE_CBC
	SERPENT_CBC_VECTOR	vector;
#endif
} SERPENT_CTX, *HSERPENT;


#ifdef	__cplusplus
extern "C" {
#endif

void __stdcall SerpentKeySetup (HSERPENT hAlgorithm, unsigned char* key);
void __stdcall SerpentDecrypt (HSERPENT hAlgorithm, unsigned long* In, unsigned long* Out);
void __stdcall SerpentEncrypt (HSERPENT hAlgorithm, unsigned long* In, unsigned long* Out);

#ifdef	__cplusplus
}
#endif