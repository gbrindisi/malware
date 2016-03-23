//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// CRYPTO library project. Version 2.1
//	
// module: rc4.c
// $Revision: 75 $
// $Date: 2015-01-22 18:44:42 +0400 (Чт, 22 янв 2015) $
// description: 
//	Cryptographic services provider library.
//	Lightweight RC4 algorithm implementation.

#include "rc4.h"

/* if this is defined data[i] is used instead of *data, this is a %20 * speedup on x86 */
#define RC4_INDEX

/* RC4 as implemented from a posting from
 * Newsgroups: sci.crypt
 * From: sterndark@netcom.com (David Sterndark)
 * Subject: RC4 Algorithm revealed.
 * Message-ID: <sternCvKL4B.Hyy@netcom.com>
 * Date: Wed, 14 Sep 1994 06:35:31 GMT
 */

void RC4_set_key(RC4_KEY *key, int len, const unsigned char *data)
{
	register int tmp;
	register int id1,id2;
	register int *d;
	unsigned int i;

	d= &(key->data[0]);
	key->x = 0;
	key->y = 0;
	id1=id2=0;

#define SK_LOOP(d,n) { \
	tmp=d[(n)]; \
	id2 = (data[id1] + tmp + id2) & 0xff; \
	if (++id1 == len) id1=0; \
	d[(n)]=d[id2]; \
	d[id2]=tmp; }

	for (i=0; i < 256; i++) d[i]=i;
	for (i=0; i < 256; i+=4)
	{
		SK_LOOP(d,i+0);
		SK_LOOP(d,i+1);
		SK_LOOP(d,i+2);
		SK_LOOP(d,i+3);
	}
}

/* RC4 as implemented from a posting from
 * Newsgroups: sci.crypt
 * From: sterndark@netcom.com (David Sterndark)
 * Subject: RC4 Algorithm revealed.
 * Message-ID: <sternCvKL4B.Hyy@netcom.com>
 * Date: Wed, 14 Sep 1994 06:35:31 GMT
 */

void RC4(RC4_KEY *key, size_t len, const unsigned char *indata, unsigned char *outdata)
{
	register int *d;
	register int x,y,tx,ty;
	size_t i;

	x=key->x;
	y=key->y;
	d=key->data; 

#define LOOP(in,out) \
		x=((x+1)&0xff); \
		tx=d[x]; \
		y=(tx+y)&0xff; \
		d[x]=ty=d[y]; \
		d[y]=tx; \
		(out) = d[(tx+ty)&0xff]^ (in);

#ifndef RC4_INDEX
#define RC4_LOOP(a,b,i)	LOOP(*((a)++),*((b)++))
#else
#define RC4_LOOP(a,b,i)	LOOP(a[i],b[i])
#endif

	i=len>>3;
	if (i)
	{
		for (;;)
		{
			RC4_LOOP(indata,outdata,0);
			RC4_LOOP(indata,outdata,1);
			RC4_LOOP(indata,outdata,2);
			RC4_LOOP(indata,outdata,3);
			RC4_LOOP(indata,outdata,4);
			RC4_LOOP(indata,outdata,5);
			RC4_LOOP(indata,outdata,6);
			RC4_LOOP(indata,outdata,7);
#ifdef RC4_INDEX
			indata+=8;
			outdata+=8;
#endif
			if (--i == 0) break;
		}
	}
	i=len&0x07;
	if (i)
	{
		for (;;)
		{
			RC4_LOOP(indata,outdata,0); if (--i == 0) break;
			RC4_LOOP(indata,outdata,1); if (--i == 0) break;
			RC4_LOOP(indata,outdata,2); if (--i == 0) break;
			RC4_LOOP(indata,outdata,3); if (--i == 0) break;
			RC4_LOOP(indata,outdata,4); if (--i == 0) break;
			RC4_LOOP(indata,outdata,5); if (--i == 0) break;
			RC4_LOOP(indata,outdata,6); if (--i == 0) break;
		}
	}
	key->x=x;
	key->y=y;
}
