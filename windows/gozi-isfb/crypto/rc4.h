//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// CRYPTO library project. Version 2.1
//	
// module: rc4.h
// $Revision: 75 $
// $Date: 2015-01-22 18:44:42 +0400 (Чт, 22 янв 2015) $
// description: 
//	Cryptographic services provider library.
//	Lightweight RC4 algorithm implementation.

#pragma once

#define	RC4_KEY_SIZE	32				// bits
#define RC4_KEY_CHARS	RC4_KEY_SIZE/8	// bytes
#define	RC4_BLOCK_SIZE	8				// bytes

typedef struct rc4_key_st
{
	int x,y;
	int data[256];
} RC4_KEY;
 
void RC4_set_key(RC4_KEY *key, int len, const unsigned char *data);
void RC4(RC4_KEY *key, size_t len, const unsigned char *indata, unsigned char *outdata);

