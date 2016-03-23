//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ISFB project. Version 2.13.24.1
//	
// module: int128.h
// $Revision: 354 $
// $Date: 2014-09-26 21:39:44 +0400 (Пт, 26 сен 2014) $
// description:
/* Primitives to manipulate 128-bit integers like, er, MD4 hashes...
   They are mapped over 16-byte arrays. The first byte (buf[0]) is
   the most significant, and its bit 0 (the one with weight 2**7)
   is the most significant bit. */


#ifndef __INT128_H_
#define __INT128_H_

/* Primitives to manipulate 128-bit integers like, er, MD4 hashes...
   They are mapped over 16-byte arrays. The first byte (buf[0]) is
   the most significant, and its bit 0 (the one with weight 2**7)
   is the most significant bit. */

typedef union _UINT128
{
	UINT64 u64_data[2];
	UINT32 u32_data[4];
	UINT16 u16_data[8];
	UINT8  u8_data[16];
}UINT128;

// for printf
#define s_int128  "%02X-%02X-%02X-%02X-%02X-%02X-%02X-%02X-%02X-%02X-%02X-%02X-%02X-%02X-%02X-%02X"
// arg for printf
#define arg_int128(_int128) (_int128)->u8_data[0],(_int128)->u8_data[1],(_int128)->u8_data[2],(_int128)->u8_data[3],(_int128)->u8_data[4],(_int128)->u8_data[5],(_int128)->u8_data[6],(_int128)->u8_data[7],(_int128)->u8_data[8],(_int128)->u8_data[9],(_int128)->u8_data[10],(_int128)->u8_data[11],(_int128)->u8_data[12],(_int128)->u8_data[13],(_int128)->u8_data[14],(_int128)->u8_data[15]

#define int128_bitnum(n, bit) (((n).u8_data[(bit)/8] >> (7-((bit)%8))) & 1)

#define int128move(_dest, _src) {\
	(_dest).u64_data[0] = (_src).u64_data[0]; \
	(_dest).u64_data[1] = (_src).u64_data[1]; \
	}

#define int128iszero(_i128) (((_i128).u64_data[0]==0)&&((_i128).u64_data[1]==0))
#define int128zero(_i128)   (_i128).u64_data[0]=(_i128).u64_data[1]=0

int int128eq(UINT128 i1, UINT128 i2);
int int128cmp(UINT128 i1, UINT128 i2);
int int128commonbits(UINT128 opn1, UINT128 opn2);

int int128lt(UINT128 i1, UINT128 i2);
int int128xorcmp(UINT128 id1, UINT128 id2, UINT128 ref);

/* dest may also coincide with opn1 or opn2 */
#define int128xor(_dest, _opn1, _opn2) { \
	(_dest).u64_data[0]  = (_opn1).u64_data[0]  ^ (_opn2).u64_data[0]; \
	(_dest).u64_data[1]  = (_opn1).u64_data[1]  ^ (_opn2).u64_data[1]; \
	}

void int128setramdomBE(UINT128 *i128);

/* returns the position of the most significant bit of op
   (from 0 to 127) to be set to 1: in other words, the integer
   part of its log in base 2. If op is zero it returns -1
   meaning "error" (log(0) is undefined). */
int int128log(UINT128 op);

int int128xorlog(UINT128 opn1, UINT128 opn2);

#define int128setrandom(_i128) \
	(_i128).u16_data[0] = rand(); \
	(_i128).u16_data[1] = rand(); \
	(_i128).u16_data[2] = rand(); \
	(_i128).u16_data[3] = rand(); \
	(_i128).u16_data[4] = rand(); \
	(_i128).u16_data[5] = rand(); \
	(_i128).u16_data[6] = rand(); \
	(_i128).u16_data[7] = rand();

unsigned int128getbit(UINT128 i128,int bit);

/* Bit at level 0 being most significant. */
#define int128setbit(_i128,_bit,_value) { \
		if (_value) \
			(_i128).u32_data[(127 - (_bit)) / 32] |= 1 << ((127 - (_bit)) % 32); \
		else \
			(_i128).u32_data[(127 - (_bit)) / 32] &= ~(1 << ((127 - (_bit)) % 32)); \
	}


/* if s is NULL or points to an odd-length string, returns NULL
   else it truncates the string or pads it on its RIGHT side
   with zeroes, and converts it as hex string into a UINT128,
   returning the address of that UINT128 */
BOOL string2int128(UINT128 i128, char *s);

UINT128 int128lshft(UINT128 i128, unsigned bits);
UINT128	int128ladd(UINT128 opn1, UINT128 opn2);
UINT128 int128laddint(UINT128 opn1, int val);
int int128cmpint(UINT128 i128, UINT32 value);

#define int128bitchunk(_i128,_val) ((_val) < 4 ? (_i128).u32_data[3 - (_val)] : 0)
UINT128 int128rand(UINT128 value, unsigned numBits);

#endif //__INT128_H_