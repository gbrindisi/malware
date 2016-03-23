//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// CRYPTO library project. Version 2.1
//	
// module: rc6.c
// $Revision: 132 $
// $Date: 2013-11-08 17:27:05 +0300 (Пт, 08 ноя 2013) $
// description: 
//	Cryptographic services provider library.
//	Lightweight RC6 algorithm implementation


#include "rc6.h"

#define ROUND			20
#define ROUNDKEYS		2*ROUND + 4


#define ROL(x, y) (((x) >> ((unsigned long)(y))) | ((x) << (32 - (unsigned long)(y))))
#define ROR(x, y) (((x) << ((unsigned long)(y))) | ((x) >> (32 - (unsigned long)(y))))
#define MAX(x, y) ( ((x)>(y))?(x):(y) )

//__inline unsigned long
//BSWAP (unsigned long x)
//{
//  __asm
//  {
//    mov eax, x;
//    bswap eax;
//  }
//  return x;
//}

#if BIG_ENDIAN == 1
#define BSWAP(x) (((ROR(x,8) & 0xFF00FF00) | (ROL(x,8) & 0x00FF00FF)))
#else
#define BSWAP(x) (x)
#endif


// #define ROL(x, y) _lrotl(x, y)
// #define ROR(x, y) _lrotr(x, y)

void __stdcall RC6KeySetup (
	HRC6 hAlgorithm, 
	unsigned char * key
	)
{
  unsigned long L[64], S[50], A, B, i, j, v, s, t, l;

  /* copy the key into the L array */
  for (A = i = j = 0; i < RC6_KEY_CHARS;)
  {
      A = (A << 8) | ((unsigned long) (key[i++] & 255));
      if (!(i & 3))
	  {
		  L[j++] = BSWAP (A);
		  A = 0;
	  }
  }

  /* setup the S array */
  t = ROUNDKEYS;			/* fixed at 20 rounds */
  S[0] = 0xB7E15163UL;
  for (i = 1; i < t; i++)
    S[i] = S[i - 1] + 0x9E3779B9UL;

  /* mix buffer */
  s = 3 * MAX (t, j);
  l = j;
  for (A = B = i = j = v = 0; v < s; v++)
    {
      A = S[i] = ROL (S[i] + A + B, 3);
      B = L[j] = ROL (L[j] + A + B, (A + B));
      i = (i + 1) % t;
      j = (j + 1) % l;
    }

  /* copy to key */
  for (i = 0; i < t; i++)
    {
      hAlgorithm->skey[i] = S[i];
    }

#ifdef _RC6_MODE_CBC
	hAlgorithm->vector[0] = 0;
	hAlgorithm->vector[1] = 0;
	hAlgorithm->vector[2] = 0;
	hAlgorithm->vector[3] = 0;
#endif

}


void __stdcall MainRC6Encrypt(
	HRC6 hAlgorithm, 
	unsigned long* In, 
	unsigned long* Out
	)
{
  unsigned long a, b, c, d, t, u;
  long r;

  a = In[0];
  b = In[1];
  c = In[2];
  d = In[3];

#ifdef _RC6_MODE_CBC
  a ^= hAlgorithm->vector[0];
  b ^= hAlgorithm->vector[1];
  c ^= hAlgorithm->vector[2];
  d ^= hAlgorithm->vector[3];
#endif

  b += hAlgorithm->skey[0];
  d += hAlgorithm->skey[1];
  for (r = 0; r < ROUND; r++)
    {
      t = (b * (b + b + 1));
      t = ROL (t, 5);
      u = (d * (d + d + 1));
      u = ROL (u, 5);
      a = ROL (a ^ t, u) + hAlgorithm->skey[r + r + 2];
      c = ROL (c ^ u, t) + hAlgorithm->skey[r + r + 3];
      t = a;
      a = b;
      b = c;
      c = d;
      d = t;
    }
  a += hAlgorithm->skey[42];
  c += hAlgorithm->skey[43];

  Out[0] = a;
  Out[1] = b;
  Out[2] = c;
  Out[3] = d;

#ifdef _RC6_MODE_CBC
  hAlgorithm->vector[0] = a;
  hAlgorithm->vector[1] = b;
  hAlgorithm->vector[2] = c;
  hAlgorithm->vector[3] = d;
#endif
}

void __stdcall MainRC6Decrypt(
	HRC6 hAlgorithm, 
	unsigned long* In, 
	unsigned long* Out
	)
{
  unsigned long a, b, c, d, t, u;
  long r;
#ifdef _RC6_MODE_CBC
  RC6_CBC_VECTOR vector;
#endif

  a = In[0];
  b = In[1];
  c = In[2];
  d = In[3];

#ifdef _RC6_MODE_CBC
  vector[0] = a;
  vector[1] = b;
  vector[2] = c;
  vector[3] = d;
#endif

  a -= hAlgorithm->skey[42];
  c -= hAlgorithm->skey[43];
  for (r = ROUND - 1; r >= 0; r--)
    {
      t = d;
      d = c;
      c = b;
      b = a;
      a = t;
      t = (b * (b + b + 1));
      t = ROL (t, 5);
      u = (d * (d + d + 1));
      u = ROL (u, 5);
      c = ROR (c - hAlgorithm->skey[r + r + 3], t) ^ u;
      a = ROR (a - hAlgorithm->skey[r + r + 2], u) ^ t;
    }
  b -= hAlgorithm->skey[0];
  d -= hAlgorithm->skey[1];

#ifdef _RC6_MODE_CBC
  a ^= hAlgorithm->vector[0];
  b ^= hAlgorithm->vector[1];
  c ^= hAlgorithm->vector[2];
  d ^= hAlgorithm->vector[3];

  hAlgorithm->vector[0] = vector[0];
  hAlgorithm->vector[1] = vector[1];
  hAlgorithm->vector[2] = vector[2];
  hAlgorithm->vector[3] = vector[3];
#endif

  Out[0] = a;
  Out[1] = b;
  Out[2] = c;
  Out[3] = d;
}
