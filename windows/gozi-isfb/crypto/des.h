//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// CRYPTO library project. Version 2.1
//	
// module: des3.h
// $Revision: 25 $
// $Date: 2013-03-12 17:34:27 +0400 (Tue, 12 Mar 2013) $
// description: 
//	Cryptographic services provider library.
//	des implementation.

#pragma once

typedef unsigned char DES_cblock[8];
typedef /* const */ unsigned char const_DES_cblock[8];
/* With "const", gcc 2.8.1 on Solaris thinks that DES_cblock *
 * and const_DES_cblock * are incompatible pointer types. */

typedef struct DES_ks
    {
    union
	{
	DES_cblock cblock;
	/* make sure things are correct size on machines with
	 * 8 byte longs */
	unsigned long deslong[2];
	} ks[16];
    } DES_key_schedule;

#define DES_KEY_SZ 	(sizeof(DES_cblock))
#define DES_SCHEDULE_SZ (sizeof(DES_key_schedule))

#define DES_ENCRYPT	1
#define DES_DECRYPT	0

#define DES_CBC_MODE	0
#define DES_PCBC_MODE	1

#define DES_ecb2_encrypt(i,o,k1,k2,e) \
	DES_ecb3_encrypt((i),(o),(k1),(k2),(k1),(e))

#define DES_ede2_cbc_encrypt(i,o,l,k1,k2,iv,e) \
	DES_ede3_cbc_encrypt((i),(o),(l),(k1),(k2),(k1),(iv),(e))

#define DES_ede2_cfb64_encrypt(i,o,l,k1,k2,iv,n,e) \
	DES_ede3_cfb64_encrypt((i),(o),(l),(k1),(k2),(k1),(iv),(n),(e))

#define DES_ede2_ofb64_encrypt(i,o,l,k1,k2,iv,n) \
	DES_ede3_ofb64_encrypt((i),(o),(l),(k1),(k2),(k1),(iv),(n))

#ifdef	__cplusplus
extern "C" {
#endif

void __stdcall DES_ecb3_encrypt(const_DES_cblock *input, DES_cblock *output,
		      DES_key_schedule *ks1,DES_key_schedule *ks2,
		      DES_key_schedule *ks3, int enc);

/* DES_cbc_encrypt does not update the IV!  Use DES_ncbc_encrypt instead. */
void __stdcall DES_cbc_encrypt(const unsigned char *input,unsigned char *output,
		     long length,DES_key_schedule *schedule,DES_cblock *ivec,
		     int enc);
void __stdcall DES_ncbc_encrypt(const unsigned char *input,unsigned char *output,
		      long length,DES_key_schedule *schedule,DES_cblock *ivec,
		      int enc);

/* 	This is the DES encryption function that gets called by just about
	every other DES routine in the library.  You should not use this
	function except to implement 'modes' of DES.  I say this because the
	functions that call this routine do the conversion from 'char *' to
	long, and this needs to be done to make sure 'non-aligned' memory
	access do not occur.  The characters are loaded 'little endian'.
	Data is a pointer to 2 unsigned long's and ks is the
	DES_key_schedule to use.  enc, is non zero specifies encryption,
	zero if decryption. */
void __stdcall DES_encrypt1(unsigned long *data,DES_key_schedule *ks, int enc);

/* 	This functions is the same as DES_encrypt1() except that the DES
	initial permutation (IP) and final permutation (FP) have been left
	out.  As for DES_encrypt1(), you should not use this function.
	It is used by the routines in the library that implement triple DES.
	IP() DES_encrypt2() DES_encrypt2() DES_encrypt2() FP() is the same
	as DES_encrypt1() DES_encrypt1() DES_encrypt1() except faster :-). */
void __stdcall DES_encrypt2(unsigned long *data,DES_key_schedule *ks, int enc);

void __stdcall DES_encrypt3(unsigned long *data, DES_key_schedule *ks1,
		  DES_key_schedule *ks2, DES_key_schedule *ks3);
void __stdcall DES_decrypt3(unsigned long *data, DES_key_schedule *ks1,
		  DES_key_schedule *ks2, DES_key_schedule *ks3);
void __stdcall DES_ede3_cbc_encrypt(const unsigned char *input,unsigned char *output, 
			  long length,
			  DES_key_schedule *ks1,DES_key_schedule *ks2,
			  DES_key_schedule *ks3,DES_cblock *ivec,int enc);

void __stdcall DES_ede3_cfb64_encrypt(const unsigned char *in,unsigned char *out,
			    long length,DES_key_schedule *ks1,
			    DES_key_schedule *ks2,DES_key_schedule *ks3,
			    DES_cblock *ivec,int *num,int enc);

void __stdcall DES_ede3_ofb64_encrypt(const unsigned char *in,unsigned char *out,
			    long length,DES_key_schedule *ks1,
			    DES_key_schedule *ks2,DES_key_schedule *ks3,
			    DES_cblock *ivec,int *num);

void __stdcall DES_set_odd_parity(DES_cblock *key);
int __stdcall DES_check_key_parity(const_DES_cblock *key);
int __stdcall DES_is_weak_key(const_DES_cblock *key);
/* DES_set_key (= set_key = DES_key_sched = key_sched) calls
 * DES_set_key_checked if global variable DES_check_key is set,
 * DES_set_key_unchecked otherwise. */
int __stdcall DES_set_key(const_DES_cblock *key,DES_key_schedule *schedule);
int __stdcall DES_key_sched(const_DES_cblock *key,DES_key_schedule *schedule);
int __stdcall DES_set_key_checked(const_DES_cblock *key,DES_key_schedule *schedule);
void __stdcall DES_set_key_unchecked(const_DES_cblock *key,DES_key_schedule *schedule);


#ifdef	__cplusplus
}
#endif