//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// CRYPTO library project. Version 2.1
//	
// module: serpent.c
// $Revision: 132 $
// $Date: 2013-11-08 17:27:05 +0300 (Пт, 08 ноя 2013) $
// description: 
//	Cryptographic services provider library.
//	Lightweight Serpent algorithm implementation


#include "serpent.h"



/* 17 terms */

#define sb0(a,b,c,d,e,f,g,h)                                    \
{   unsigned long  t1,t2,t3,t4,t6,t7,t8,t9,t11,t12,t13,t15,t16;        \
    t1 = b ^ d;         \
    t2 = ~t1;           \
    t3 = a | d;         \
    t4 = b ^ c;         \
    h = t3 ^ t4;        \
    t6 = a ^ b;         \
    t7 = a | t4;        \
    t8 = c & t6;        \
    t9 = t2 | t8;       \
    e = t7 ^ t9;        \
    t11 = a ^ h;        \
    t12 = t1 & t6;      \
    t13 = e ^ t11;      \
    f = t12 ^ t13;      \
    t15 = e | f;        \
    t16 = t3 & t15;     \
    g = b ^ t16;        \
}

/* 17 terms */

#define ib0(a,b,c,d,e,f,g,h)                                    \
{   unsigned long  t1,t2,t3,t4,t6,t7,t8,t9,t11,t12,t13,t15,t16;        \
    t1 = a ^ d;         \
    t2 = c ^ d;         \
    t3 = ~t2;           \
    t4 = a | b;         \
    g = t3 ^ t4;        \
    t6 = b ^ t1;        \
    t7 = c | t6;        \
    t8 = a ^ t7;        \
    t9 = t2 & t8;       \
    f = t6 ^ t9;        \
    t11 = ~t8;          \
    t12 = b & d;        \
    t13 = f | t12;      \
    h = t11 ^ t13;      \
    t15 = t2 ^ t12;     \
    t16 = f | h;        \
    e = t15 ^ t16;      \
}

/* 18 terms */

#define sb1(a,b,c,d,e,f,g,h)                                    \
{   unsigned long  t1,t2,t3,t4,t5,t7,t8,t9,t10,t12,t13,t14,t16,t17;    \
    t1 = a ^ d;         \
    t2 = b ^ d;         \
    t3 = a & b;         \
    t4 = ~c;            \
    t5 = t2 ^ t3;       \
    g = t4 ^ t5;        \
    t7 = a ^ t2;        \
    t8 = b | t4;        \
    t9 = d | g;         \
    t10 = t7 & t9;      \
    f = t8 ^ t10;       \
    t12 = c ^ d;        \
    t13 = t1 | t2;      \
    t14 = f ^ t12;      \
    h = t13 ^ t14;      \
    t16 = t1 | g;       \
    t17 = t8 ^ t14;     \
    e = t16 ^ t17;      \
}

/* 17 terms */

#define ib1(a,b,c,d,e,f,g,h)                                \
{   unsigned long  t1,t2,t3,t4,t5,t7,t8,t9,t11,t12,t13,t15,t16;    \
    t1 = a ^ d;         \
    t2 = a & b;         \
    t3 = b ^ c;         \
    t4 = a ^ t3;        \
    t5 = b | d;         \
    h = t4 ^ t5;        \
    t7 = c | t1;        \
    t8 = b ^ t7;        \
    t9 = t4 & t8;       \
    f = t1 ^ t9;        \
    t11 = ~t2;          \
    t12 = h & f;        \
    t13 = t9 ^ t11;     \
    g = t12 ^ t13;      \
    t15 = a & d;        \
    t16 = c ^ t13;      \
    e = t15 ^ t16;      \
}

/* 16 terms */

#define sb2(a,b,c,d,e,f,g,h)                            \
{   unsigned long  t1,t2,t3,t5,t6,t7,t9,t10,t11,t13,t14,t15;   \
    t1 = ~a;            \
    t2 = b ^ d;         \
    t3 = c & t1;        \
    e = t2 ^ t3;        \
    t5 = c ^ t1;        \
    t6 = c ^ e;         \
    t7 = b & t6;        \
    h = t5 ^ t7;        \
    t9 = d | t7;        \
    t10 = e | t5;       \
    t11 = t9 & t10;     \
    g = a ^ t11;        \
    t13 = d | t1;       \
    t14 = t2 ^ h;       \
    t15 = g ^ t13;      \
    f = t14 ^ t15;      \
}

/* 16 terms */

#define ib2(a,b,c,d,e,f,g,h)                                    \
{   unsigned long  t1,t2,t3,t4,t5,t7,t8,t9,t11,t12,t14,t15;            \
    t1 = b ^ d;         \
    t2 = ~t1;           \
    t3 = a ^ c;         \
    t4 = c ^ t1;        \
    t5 = b & t4;        \
    e = t3 ^ t5;        \
    t7 = a | t2;        \
    t8 = d ^ t7;        \
    t9 = t3 | t8;       \
    h = t1 ^ t9;        \
    t11 = ~t4;          \
    t12 = e | h;        \
    f = t11 ^ t12;      \
    t14 = d & t11;      \
    t15 = t3 ^ t12;     \
    g = t14 ^ t15;      \
}

/* 18 terms */

#define sb3(a,b,c,d,e,f,g,h)                                    \
{   unsigned long  t1,t2,t3,t4,t5,t6,t8,t9,t10,t12,t13,t15,t16,t17;    \
    t1 = a ^ c;         \
    t2 = a | d;         \
    t3 = a & b;         \
    t4 = a & d;         \
    t5 = b | t4;        \
    t6 = t1 & t2;       \
    f = t5 ^ t6;        \
    t8 = b ^ d;         \
    t9 = c | t3;        \
    t10 = t6 ^ t8;      \
    h = t9 ^ t10;       \
    t12 = c ^ t3;       \
    t13 = t2 & h;       \
    g = t12 ^ t13;      \
    t15 = ~g;           \
    t16 = t2 ^ t3;      \
    t17 = f & t15;      \
    e = t16 ^ t17;      \
}

/* 17 terms */

#define ib3(a,b,c,d,e,f,g,h)                                    \
{   unsigned long  t1,t2,t3,t4,t5,t7,t8,t9,t11,t12,t14,t15,t16;        \
    t1 = b ^ c;         \
    t2 = b | c;         \
    t3 = a ^ c;         \
    t4 = t2 ^ t3;       \
    t5 = d | t4;        \
    e = t1 ^ t5;        \
    t7 = a ^ d;         \
    t8 = t1 | t5;       \
    t9 = t2 ^ t7;       \
    g = t8 ^ t9;        \
    t11 = a & t4;       \
    t12 = e | t9;       \
    f = t11 ^ t12;      \
    t14 = a & g;        \
    t15 = t2 ^ t14;     \
    t16 = e & t15;      \
    h = t4 ^ t16;       \
}

/* 17 terms */

#define sb4(a,b,c,d,e,f,g,h)                                    \
{   unsigned long  t1,t2,t3,t4,t5,t7,t8,t10,t11,t12,t14,t15,t16;       \
    t1 = ~a;            \
    t2 = a ^ d;         \
    t3 = a ^ b;         \
    t4 = c ^ t1;        \
    t5 = t2 | t3;       \
    e = t4 ^ t5;        \
    t7 = ~e;            \
    t8 = b | t7;        \
    h = t2 ^ t8;        \
    t10 = a & e;        \
    t11 = b ^ h;        \
    t12 = t8 & t11;     \
    g = t10 ^ t12;      \
    t14 = a | t7;       \
    t15 = t3 ^ t14;     \
    t16 = h & g;        \
    f = t15 ^ t16;      \
}

/* 17 terms */

#define ib4(a,b,c,d,e,f,g,h)                                    \
{   unsigned long  t1,t2,t3,t4,t6,t7,t8,t10,t11,t12,t14,t15,t16;       \
    t1 = c ^ d;         \
    t2 = c | d;         \
    t3 = b ^ t2;        \
    t4 = a & t3;        \
    f = t1 ^ t4;        \
    t6 = a ^ d;         \
    t7 = b | d;         \
    t8 = t6 & t7;       \
    h = t3 ^ t8;        \
    t10 = ~a;           \
    t11 = c ^ h;        \
    t12 = t10 | t11;    \
    e = t3 ^ t12;       \
    t14 = c | t4;       \
    t15 = t7 ^ t14;     \
    t16 = h | t10;      \
    g = t15 ^ t16;      \
}

/* 17 terms */

#define sb5(a,b,c,d,e,f,g,h)                                \
{   unsigned long  t1,t2,t3,t4,t5,t7,t8,t10,t11,t12,t14,t15,t16;   \
    t1 = ~a;            \
    t2 = a ^ b;         \
    t3 = a ^ d;         \
    t4 = c ^ t1;        \
    t5 = t2 | t3;       \
    e = t4 ^ t5;        \
    t7 = ~d;            \
    t8 = e & t7;        \
    f = t2 ^ t8;        \
    t10 = b | f;        \
    t11 = c | e;        \
    t12 = t7 ^ t10;     \
    h = t11 ^ t12;      \
    t14 = d | f;        \
    t15 = t1 ^ t14;     \
    t16 = e | h;        \
    g = t15 ^ t16;      \
}

/* 16 terms */

#define ib5(a,b,c,d,e,f,g,h)                                \
{   unsigned long  t1,t2,t3,t4,t5,t7,t8,t10,t11,t13,t14,t15;       \
    t1 = ~c;            \
    t2 = b & t1;        \
    t3 = d ^ t2;        \
    t4 = a & t3;        \
    t5 = b ^ t1;        \
    h = t4 ^ t5;        \
    t7 = b | h;         \
    t8 = a & t7;        \
    f = t3 ^ t8;        \
    t10 = a | d;        \
    t11 = t1 ^ t7;      \
    e = t10 ^ t11;      \
    t13 = a ^ c;        \
    t14 = b & t10;      \
    t15 = t4 | t13;     \
    g = t14 ^ t15;      \
} 

/* 17 terms */

#define sb6(a,b,c,d,e,f,g,h)                                \
{   unsigned long  t1,t2,t3,t4,t5,t7,t8,t9,t11,t12,t13,t15,t16;    \
    t1 = a ^ c;         \
    t2 = b | d;         \
    t3 = b ^ c;         \
    t4 = ~t3;           \
    t5 = a & d;         \
    f = t4 ^ t5;        \
    t7 = b | c;         \
    t8 = d ^ t1;        \
    t9 = t7 & t8;       \
    h = t2 ^ t9;        \
    t11 = t1 & t7;      \
    t12 = t4 ^ t8;      \
    t13 = h & t11;      \
    e = t12 ^ t13;      \
    t15 = t3 ^ t11;     \
    t16 = h | t15;      \
    g = t12 ^ t16;      \
}

/* 17 terms */

#define ib6(a,b,c,d,e,f,g,h)                                \
{   unsigned long  t1,t2,t3,t4,t6,t7,t8,t9,t11,t12,t13,t15,t16;    \
    t1 = ~c;            \
    t2 = a ^ c;         \
    t3 = b ^ d;         \
    t4 = a | t1;        \
    f = t3 ^ t4;        \
    t6 = a | b;         \
    t7 = b & t2;        \
    t8 = f ^ t6;        \
    t9 = t7 | t8;       \
    e = c ^ t9;         \
    t11 = ~f;           \
    t12 = d | t2;       \
    t13 = t9 ^ t11;     \
    h = t12 ^ t13;      \
    t15 = b ^ t11;      \
    t16 = e & h;        \
    g = t15 ^ t16;      \
}

/* 17 terms */

#define sb7(a,b,c,d,e,f,g,h)                                \
{   unsigned long  t1,t2,t3,t4,t5,t7,t8,t9,t11,t12,t13,t15,t16;    \
    t1 = ~c;            \
    t2 = b ^ c;         \
    t3 = b | t1;        \
    t4 = d ^ t3;        \
    t5 = a & t4;        \
    h = t2 ^ t5;        \
    t7 = a ^ d;         \
    t8 = b ^ t5;        \
    t9 = t2 | t8;       \
    f = t7 ^ t9;        \
    t11 = d & t3;       \
    t12 = t5 ^ f;       \
    t13 = h & t12;      \
    g = t11 ^ t13;      \
    t15 = t1 | t4;      \
    t16 = t12 ^ g;      \
    e = t15 ^ t16;      \
}

/* 17 terms */

#define ib7(a,b,c,d,e,f,g,h)                                \
{   unsigned long  t1,t2,t3,t4,t6,t7,t8,t9,t11,t12,t14,t15,t16;    \
    t1 = a & b;         \
    t2 = a | b;         \
    t3 = c | t1;        \
    t4 = d & t2;        \
    h = t3 ^ t4;        \
    t6 = ~d;            \
    t7 = b ^ t4;        \
    t8 = h ^ t6;        \
    t9 = t7 | t8;       \
    f = a ^ t9;         \
    t11 = c ^ t7;       \
    t12 = d | f;        \
    e = t11 ^ t12;      \
    t14 = a & h;        \
    t15 = t3 ^ f;       \
    t16 = e ^ t14;      \
    g = t15 ^ t16;      \
}

#ifndef _MSC_VER

#define rotr(x,n)   (((x) >> ((unsigned long)(n))) | ((x) << (32 - (unsigned long)(n))))
#define rotl(x,n)   (((x) << ((unsigned long)(n))) | ((x) >> (32 - (unsigned long)(n))))

#else

#include <stdlib.h>

#pragma intrinsic(_lrotr,_lrotl)
#define rotr(x,n)   _lrotr(x,n)
#define rotl(x,n)   _lrotl(x,n)

#endif

#define k_xor(r,a,b,c,d)        \
{   (a) ^= hCtx->key[4 * (r) +  8]; \
    (b) ^= hCtx->key[4 * (r) +  9]; \
    (c) ^= hCtx->key[4 * (r) + 10]; \
    (d) ^= hCtx->key[4 * (r) + 11]; \
}

#define k_set(r,a,b,c,d)        \
{   (a) = hCtx->key[4 * (r) +  8];  \
    (b) = hCtx->key[4 * (r) +  9];  \
    (c) = hCtx->key[4 * (r) + 10];  \
    (d) = hCtx->key[4 * (r) + 11];  \
}

#define k_get(r,a,b,c,d)        \
{   hCtx->key[4 * (r) +  8] = (a);  \
    hCtx->key[4 * (r) +  9] = (b);  \
    hCtx->key[4 * (r) + 10] = (c);  \
    hCtx->key[4 * (r) + 11] = (d);  \
}

/* the linear transformation and its inverse    */

#define rot(a,b,c,d)            \
{   (a) = rotl((a), 13);        \
    (c) = rotl((c), 3);         \
    (b) ^= (a) ^ (c);           \
    (d) ^= (c) ^ ((a) << 3);    \
    (b) = rotl((b), 1);         \
    (d) = rotl((d), 7);         \
    (a) ^= (b) ^ (d);           \
    (c) ^= (d) ^ ((b) << 7);    \
    (a) = rotl((a), 5);         \
    (c) = rotl((c), 22);        \
}

#define irot(a,b,c,d)           \
{   (c) = rotr((c), 22);        \
    (a) = rotr((a), 5);         \
    (c) ^= (d) ^ ((b) << 7);    \
    (a) ^= (b) ^ (d);           \
    (d) = rotr((d), 7);         \
    (b) = rotr((b), 1);         \
    (d) ^= (c) ^ ((a) << 3);    \
    (b) ^= (a) ^ (c);           \
    (c) = rotr((c), 3);         \
    (a) = rotr((a), 13);        \
}


/* initialise the key schedule from the user supplied key   */

void Serpentset_key(HSERPENT hCtx, unsigned long key_blk[], unsigned long key_len)
{
    unsigned long  i,lk,a,b,c,d,e,f,g,h;

    if(key_len > 256)

        return;

    i = 0; 
    
    while(i < (key_len + 31) / 32)
    {
        hCtx->key[i] = key_blk[i]; i++;
    }

    if(key_len < 256)
    {
        while(i < 8)

            hCtx->key[i++] = 0;

        i = key_len / 32; lk = 1 << key_len % 32; 

        hCtx->key[i] = hCtx->key[i] & (lk - 1) | lk;
    }

    for(i = 0; i < 132; ++i)
    {
        lk = hCtx->key[i] ^ hCtx->key[i + 3] ^ hCtx->key[i + 5] 
                                ^ hCtx->key[i + 7] ^ 0x9e3779b9 ^ i;

        hCtx->key[i + 8] = (lk << 11) | (lk >> 21); 
    }

    k_set( 0,a,b,c,d);sb3(a,b,c,d,e,f,g,h);k_get( 0,e,f,g,h);
    k_set( 1,a,b,c,d);sb2(a,b,c,d,e,f,g,h);k_get( 1,e,f,g,h);
    k_set( 2,a,b,c,d);sb1(a,b,c,d,e,f,g,h);k_get( 2,e,f,g,h);
    k_set( 3,a,b,c,d);sb0(a,b,c,d,e,f,g,h);k_get( 3,e,f,g,h);
    k_set( 4,a,b,c,d);sb7(a,b,c,d,e,f,g,h);k_get( 4,e,f,g,h);
    k_set( 5,a,b,c,d);sb6(a,b,c,d,e,f,g,h);k_get( 5,e,f,g,h);
    k_set( 6,a,b,c,d);sb5(a,b,c,d,e,f,g,h);k_get( 6,e,f,g,h);
    k_set( 7,a,b,c,d);sb4(a,b,c,d,e,f,g,h);k_get( 7,e,f,g,h);
    k_set( 8,a,b,c,d);sb3(a,b,c,d,e,f,g,h);k_get( 8,e,f,g,h);
    k_set( 9,a,b,c,d);sb2(a,b,c,d,e,f,g,h);k_get( 9,e,f,g,h);
    k_set(10,a,b,c,d);sb1(a,b,c,d,e,f,g,h);k_get(10,e,f,g,h);
    k_set(11,a,b,c,d);sb0(a,b,c,d,e,f,g,h);k_get(11,e,f,g,h);
    k_set(12,a,b,c,d);sb7(a,b,c,d,e,f,g,h);k_get(12,e,f,g,h);
    k_set(13,a,b,c,d);sb6(a,b,c,d,e,f,g,h);k_get(13,e,f,g,h);
    k_set(14,a,b,c,d);sb5(a,b,c,d,e,f,g,h);k_get(14,e,f,g,h);
    k_set(15,a,b,c,d);sb4(a,b,c,d,e,f,g,h);k_get(15,e,f,g,h);
    k_set(16,a,b,c,d);sb3(a,b,c,d,e,f,g,h);k_get(16,e,f,g,h);
    k_set(17,a,b,c,d);sb2(a,b,c,d,e,f,g,h);k_get(17,e,f,g,h);
    k_set(18,a,b,c,d);sb1(a,b,c,d,e,f,g,h);k_get(18,e,f,g,h);
    k_set(19,a,b,c,d);sb0(a,b,c,d,e,f,g,h);k_get(19,e,f,g,h);
    k_set(20,a,b,c,d);sb7(a,b,c,d,e,f,g,h);k_get(20,e,f,g,h);
    k_set(21,a,b,c,d);sb6(a,b,c,d,e,f,g,h);k_get(21,e,f,g,h);
    k_set(22,a,b,c,d);sb5(a,b,c,d,e,f,g,h);k_get(22,e,f,g,h);
    k_set(23,a,b,c,d);sb4(a,b,c,d,e,f,g,h);k_get(23,e,f,g,h);
    k_set(24,a,b,c,d);sb3(a,b,c,d,e,f,g,h);k_get(24,e,f,g,h);
    k_set(25,a,b,c,d);sb2(a,b,c,d,e,f,g,h);k_get(25,e,f,g,h);
    k_set(26,a,b,c,d);sb1(a,b,c,d,e,f,g,h);k_get(26,e,f,g,h);
    k_set(27,a,b,c,d);sb0(a,b,c,d,e,f,g,h);k_get(27,e,f,g,h);
    k_set(28,a,b,c,d);sb7(a,b,c,d,e,f,g,h);k_get(28,e,f,g,h);
    k_set(29,a,b,c,d);sb6(a,b,c,d,e,f,g,h);k_get(29,e,f,g,h);
    k_set(30,a,b,c,d);sb5(a,b,c,d,e,f,g,h);k_get(30,e,f,g,h);
    k_set(31,a,b,c,d);sb4(a,b,c,d,e,f,g,h);k_get(31,e,f,g,h);
    k_set(32,a,b,c,d);sb3(a,b,c,d,e,f,g,h);k_get(32,e,f,g,h);

};

/* encrypt a block of text  */

void __stdcall SerpentEncrypt(
	HSERPENT		hCtx, 
	unsigned long*	In, 
	unsigned long*	Out
	)

{
    unsigned long  a,b,c,d,e,f,g,h;
    
    a = In[0];b = In[1];c = In[2];d = In[3];

#ifdef _SERPENT_MODE_CBC
	a ^= hCtx->vector[0];
	b ^= hCtx->vector[1];
	c ^= hCtx->vector[2];
	d ^= hCtx->vector[3];
#endif
    
    k_xor( 0,a,b,c,d); sb0(a,b,c,d,e,f,g,h); rot(e,f,g,h); 
    k_xor( 1,e,f,g,h); sb1(e,f,g,h,a,b,c,d); rot(a,b,c,d); 
    k_xor( 2,a,b,c,d); sb2(a,b,c,d,e,f,g,h); rot(e,f,g,h); 
    k_xor( 3,e,f,g,h); sb3(e,f,g,h,a,b,c,d); rot(a,b,c,d); 
    k_xor( 4,a,b,c,d); sb4(a,b,c,d,e,f,g,h); rot(e,f,g,h); 
    k_xor( 5,e,f,g,h); sb5(e,f,g,h,a,b,c,d); rot(a,b,c,d); 
    k_xor( 6,a,b,c,d); sb6(a,b,c,d,e,f,g,h); rot(e,f,g,h); 
    k_xor( 7,e,f,g,h); sb7(e,f,g,h,a,b,c,d); rot(a,b,c,d); 
    k_xor( 8,a,b,c,d); sb0(a,b,c,d,e,f,g,h); rot(e,f,g,h); 
    k_xor( 9,e,f,g,h); sb1(e,f,g,h,a,b,c,d); rot(a,b,c,d); 
    k_xor(10,a,b,c,d); sb2(a,b,c,d,e,f,g,h); rot(e,f,g,h); 
    k_xor(11,e,f,g,h); sb3(e,f,g,h,a,b,c,d); rot(a,b,c,d); 
    k_xor(12,a,b,c,d); sb4(a,b,c,d,e,f,g,h); rot(e,f,g,h); 
    k_xor(13,e,f,g,h); sb5(e,f,g,h,a,b,c,d); rot(a,b,c,d); 
    k_xor(14,a,b,c,d); sb6(a,b,c,d,e,f,g,h); rot(e,f,g,h); 
    k_xor(15,e,f,g,h); sb7(e,f,g,h,a,b,c,d); rot(a,b,c,d); 
    k_xor(16,a,b,c,d); sb0(a,b,c,d,e,f,g,h); rot(e,f,g,h); 
    k_xor(17,e,f,g,h); sb1(e,f,g,h,a,b,c,d); rot(a,b,c,d); 
    k_xor(18,a,b,c,d); sb2(a,b,c,d,e,f,g,h); rot(e,f,g,h); 
    k_xor(19,e,f,g,h); sb3(e,f,g,h,a,b,c,d); rot(a,b,c,d); 
    k_xor(20,a,b,c,d); sb4(a,b,c,d,e,f,g,h); rot(e,f,g,h); 
    k_xor(21,e,f,g,h); sb5(e,f,g,h,a,b,c,d); rot(a,b,c,d); 
    k_xor(22,a,b,c,d); sb6(a,b,c,d,e,f,g,h); rot(e,f,g,h); 
    k_xor(23,e,f,g,h); sb7(e,f,g,h,a,b,c,d); rot(a,b,c,d); 
    k_xor(24,a,b,c,d); sb0(a,b,c,d,e,f,g,h); rot(e,f,g,h); 
    k_xor(25,e,f,g,h); sb1(e,f,g,h,a,b,c,d); rot(a,b,c,d); 
    k_xor(26,a,b,c,d); sb2(a,b,c,d,e,f,g,h); rot(e,f,g,h); 
    k_xor(27,e,f,g,h); sb3(e,f,g,h,a,b,c,d); rot(a,b,c,d); 
    k_xor(28,a,b,c,d); sb4(a,b,c,d,e,f,g,h); rot(e,f,g,h); 
    k_xor(29,e,f,g,h); sb5(e,f,g,h,a,b,c,d); rot(a,b,c,d); 
    k_xor(30,a,b,c,d); sb6(a,b,c,d,e,f,g,h); rot(e,f,g,h); 
    k_xor(31,e,f,g,h); sb7(e,f,g,h,a,b,c,d); k_xor(32,a,b,c,d); 

#ifdef _SERPENT_MODE_CBC
	hCtx->vector[0] = a;
	hCtx->vector[1] = b;
	hCtx->vector[2] = c;
	hCtx->vector[3] = d;
#endif
    
    Out[0] = a; Out[1] = b; Out[2] = c; Out[3] = d;
};

/* decrypt a block of text  */

void __stdcall SerpentDecrypt(
	HSERPENT		hCtx, 
	unsigned long*	In, 
	unsigned long*	Out
	)
{
    unsigned long  a,b,c,d,e,f,g,h;
#ifdef _SERPENT_MODE_CBC
	SERPENT_CBC_VECTOR	vector;
#endif
    
    a = In[0];b = In[1];c = In[2];d = In[3];

#ifdef _SERPENT_MODE_CBC
	vector[0] = a;
	vector[1] = b;
	vector[2] = c;
	vector[3] = d;
#endif

    k_xor(32,a,b,c,d); ib7(a,b,c,d,e,f,g,h); k_xor(31,e,f,g,h);
    irot(e,f,g,h); ib6(e,f,g,h,a,b,c,d); k_xor(30,a,b,c,d);
    irot(a,b,c,d); ib5(a,b,c,d,e,f,g,h); k_xor(29,e,f,g,h);
    irot(e,f,g,h); ib4(e,f,g,h,a,b,c,d); k_xor(28,a,b,c,d);
    irot(a,b,c,d); ib3(a,b,c,d,e,f,g,h); k_xor(27,e,f,g,h);
    irot(e,f,g,h); ib2(e,f,g,h,a,b,c,d); k_xor(26,a,b,c,d);
    irot(a,b,c,d); ib1(a,b,c,d,e,f,g,h); k_xor(25,e,f,g,h);
    irot(e,f,g,h); ib0(e,f,g,h,a,b,c,d); k_xor(24,a,b,c,d);
    irot(a,b,c,d); ib7(a,b,c,d,e,f,g,h); k_xor(23,e,f,g,h);
    irot(e,f,g,h); ib6(e,f,g,h,a,b,c,d); k_xor(22,a,b,c,d);
    irot(a,b,c,d); ib5(a,b,c,d,e,f,g,h); k_xor(21,e,f,g,h);
    irot(e,f,g,h); ib4(e,f,g,h,a,b,c,d); k_xor(20,a,b,c,d);
    irot(a,b,c,d); ib3(a,b,c,d,e,f,g,h); k_xor(19,e,f,g,h);
    irot(e,f,g,h); ib2(e,f,g,h,a,b,c,d); k_xor(18,a,b,c,d);
    irot(a,b,c,d); ib1(a,b,c,d,e,f,g,h); k_xor(17,e,f,g,h);
    irot(e,f,g,h); ib0(e,f,g,h,a,b,c,d); k_xor(16,a,b,c,d);
    irot(a,b,c,d); ib7(a,b,c,d,e,f,g,h); k_xor(15,e,f,g,h);
    irot(e,f,g,h); ib6(e,f,g,h,a,b,c,d); k_xor(14,a,b,c,d);
    irot(a,b,c,d); ib5(a,b,c,d,e,f,g,h); k_xor(13,e,f,g,h);
    irot(e,f,g,h); ib4(e,f,g,h,a,b,c,d); k_xor(12,a,b,c,d);
    irot(a,b,c,d); ib3(a,b,c,d,e,f,g,h); k_xor(11,e,f,g,h);
    irot(e,f,g,h); ib2(e,f,g,h,a,b,c,d); k_xor(10,a,b,c,d);
    irot(a,b,c,d); ib1(a,b,c,d,e,f,g,h); k_xor( 9,e,f,g,h);
    irot(e,f,g,h); ib0(e,f,g,h,a,b,c,d); k_xor( 8,a,b,c,d);
    irot(a,b,c,d); ib7(a,b,c,d,e,f,g,h); k_xor( 7,e,f,g,h);
    irot(e,f,g,h); ib6(e,f,g,h,a,b,c,d); k_xor( 6,a,b,c,d);
    irot(a,b,c,d); ib5(a,b,c,d,e,f,g,h); k_xor( 5,e,f,g,h);
    irot(e,f,g,h); ib4(e,f,g,h,a,b,c,d); k_xor( 4,a,b,c,d);
    irot(a,b,c,d); ib3(a,b,c,d,e,f,g,h); k_xor( 3,e,f,g,h);
    irot(e,f,g,h); ib2(e,f,g,h,a,b,c,d); k_xor( 2,a,b,c,d);
    irot(a,b,c,d); ib1(a,b,c,d,e,f,g,h); k_xor( 1,e,f,g,h);
    irot(e,f,g,h); ib0(e,f,g,h,a,b,c,d); k_xor( 0,a,b,c,d);

#ifdef _SERPENT_MODE_CBC
	a ^= hCtx->vector[0];
	b ^= hCtx->vector[1];
	c ^= hCtx->vector[2];
	d ^= hCtx->vector[3];

	hCtx->vector[0] = vector[0];
	hCtx->vector[1] = vector[1];
	hCtx->vector[2] = vector[2];
	hCtx->vector[3] = vector[3];
#endif
    
    Out[0] = a; Out[1] = b; Out[2] = c; Out[3] = d;
};


void __stdcall SerpentKeySetup(
	HSERPENT		hAlgorithm,
	unsigned char*	Key
	)
{
	Serpentset_key(hAlgorithm, (unsigned long*)Key, SERPENT_KEY_SIZE);

#ifdef _SERPENT_MODE_CBC
	hAlgorithm->vector[0] = 0;
	hAlgorithm->vector[1] = 0;
	hAlgorithm->vector[2] = 0;
	hAlgorithm->vector[3] = 0;
#endif
}
