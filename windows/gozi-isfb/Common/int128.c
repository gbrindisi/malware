//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ISFB project. Version 2.13.24.1
//	
// module: int128.c
// $Revision: 354 $
// $Date: 2014-09-26 21:39:44 +0400 (Пт, 26 сен 2014) $
// description:
/* Primitives to manipulate 128-bit integers like, er, MD4 hashes...
   They are mapped over 16-byte arrays. The first byte (buf[0]) is
   the most significant, and its bit 0 (the one with weight 2**7)
   is the most significant bit. */

#include "common.h"

int int128eq(UINT128 i1, UINT128 i2) {
	return 	( (i1.u64_data[0] == i2.u64_data[0] ) && 
		(i1.u64_data[1] == i2.u64_data[1] ));
}

int int128cmp(UINT128 i1, UINT128 i2) {
	int i;
	for ( i = 3; i >= 0; i--) {
		if (i1.u32_data[i] < i2.u32_data[i])
			return -1;
		if (i1.u32_data[i] > i2.u32_data[i])
			return 1;
	}
	return 0;
}

int int128lt(UINT128 i1, UINT128 i2) {
	return int128cmp(i1,i2) < 0;
}

/* Determine whether id1 or id2 is closer to ref */
int int128xorcmp(UINT128 id1, UINT128 id2, UINT128 ref)
{
	int i;
	for(i = 0; i < 20; i++) {
		unsigned char xor1, xor2;
		if(id1.u8_data[i] == id2.u8_data[i])
			continue;
		xor1 = id1.u8_data[i] ^ ref.u8_data[i];
		xor2 = id2.u8_data[i] ^ ref.u8_data[i];
		if(xor1 < xor2)
			return -1;
		else
			return 1;
	}
	return 0;
}

const static char logtable[256] = {
   -1, 0, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3,
	4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
	5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
	5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
	6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
	6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
	6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
	6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
	7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
	7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
	7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
	7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
	7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
	7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
	7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
	7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
};

/* returns the position of the most significant bit of op
   (from 0 to 127) to be set to 1: in other words, the integer
   part of its log in base 2. If op is zero it returns -1
   meaning "error" (log(0) is undefined). */
int int128log(UINT128 op) {
	int i;
	int l = 120;
	for(i=0; i < 16; i++ ) {
		if(op.u8_data[i] != 0){
			return l + logtable[op.u8_data[i]];
		}
		l -= 8;
	}
	return -1; /* all bytes were zero */
}

int int128xorlog(UINT128 opn1, UINT128 opn2) {
	UINT128 buf = {0};
	int128xor(buf, opn1, opn2);
	return int128log(buf);
}

/* Bit at level 0 being most significant. */
unsigned int128getbit(UINT128 i128,int bit) {
	return (bit) <= 127 ? (i128.u32_data[(127 - bit) / 32] >> ((127 - bit) % 32)) & 1 : 0;
}

int int128commonbits(UINT128 opn1, UINT128 opn2) {
	int i, j;
	unsigned char xor;
	for(i = 0; i < 16; i++) {
		if(opn1.u8_data[i] != opn2.u8_data[i])
			break;
	}

	if(i == 16)
		return 120;

	xor = opn1.u8_data[i] ^ opn2.u8_data[i];

	j = 0;
	while((xor & 0x80) == 0) {
		xor <<= 1;
		j++;
	}

	return 8 * i + j;
}

BOOL string2int128(UINT128 i128, char *s) 
{
	int i, n;
	unsigned int u;
	if(s == NULL)				/* NULL string */
		return FALSE;	/* error */

	if(((n=strlen(s))&1) != 0 ) {	/* odd length string */
		n--;
	}

	int128zero(i128);

	for(i=0; i<16 && n > 0; i++, s += 2, n -= 2) {
		if(sscanf(s, "%2x", &u ) != 1)
			return FALSE;	/* invalid hex char */
		i128.u8_data[i] = u;
	}
	return TRUE;	/* OK */
}

UINT128 int128lshft(UINT128 i128, unsigned bits)
{
	union {
		UINT32 u32_data[4];
		UINT64 u64_data[2];
	} result = {{ 0, 0, 0, 0 }};
	int indexShift = (int)bits / 32;
	UINT64 shifted = 0;
	int i;

	if (bits == 0)
		return i128;

	if (bits > 127) {
		int128zero(i128);
		return i128;
	}

	for (i = 3; i >= indexShift; i--)
	{
		shifted += ((UINT64)i128.u32_data[3 - i]) << (bits % 32);
		result.u32_data[3 - i + indexShift] = (UINT32)shifted;
		shifted = shifted >> 32;
	}
	i128.u64_data[0] = result.u64_data[0];
	i128.u64_data[1] = result.u64_data[1];
	return i128;
}

UINT128 int128ladd(UINT128 opn1, UINT128 opn2)
{
	INT64 sum = 0;
	int i;
	for (i = 0; i < 4; i++) {
		sum += opn1.u32_data[i];
		sum += opn2.u32_data[i];
		opn1.u32_data[i] = (UINT32)sum;
		sum >>= 32;
	}
	return opn1;
}

UINT128 int128laddint(UINT128 opn1, int val)
{
	UINT128 opn2;
	opn2.u32_data[0] = val;
	opn2.u32_data[1] = 0;
	opn2.u32_data[2] = 0;
	opn2.u32_data[3] = 0;	
	return int128ladd(opn1,opn2);
}

int int128cmpint(UINT128 i128, UINT32 value)
{
	if ((i128.u64_data[1] > 0) || (i128.u32_data[1] > 0) || (i128.u32_data[0] > value))
		return 1;
	if (i128.u32_data[0] < value)
		return -1;
	return 0;
}


UINT128 int128rand(UINT128 value, unsigned numBits)
{
	// Copy the whole uint32s
	unsigned numULONGs = numBits / 32;
	unsigned i;
	UINT128 i128;

	// zero
	i128.u64_data[0] = i128.u64_data[1] = 0;

	for ( i = 0; i < numULONGs; i++) {
		i128.u32_data[3 - i] = int128bitchunk(value,i);
	}

	// Copy the remaining bits
	for ( i = numULONGs * 32; i < numBits; i++) {
		int128setbit(i128,i,int128getbit(value,i));
	}

	// Fill the remaining bits of the current 32-bit chunk with random bits
	// (Not seeding based on time to allow multiple different ones to be created in quick succession)
	numULONGs = (numBits + 31) / 32;
	for ( i = numBits; i < numULONGs * 32; i++) {
		int128setbit(i128,i, rand() % 2);
	}

	// Pad with random bytes
	for ( i = numULONGs; i < 3; i++) {
		i128.u32_data[3 - i] = rand();
	}
	return i128;
}

void int128setramdomBE(UINT128 *i128)
{
	UINT128 r;
	int i;
	int128setrandom(r);
	for ( i=0; i<16; i++)
		i128->u32_data[i/4] |= ((ULONG)r.u8_data[i]) << (8*(3-(i%4)));
}