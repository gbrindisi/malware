//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ISFB project. Version 2.13.24.1
//	
// module: crtsup.c
// $Revision: 326 $
// $Date: 2014-09-12 22:18:31 +0400 (Пт, 12 сен 2014) $
// description:
//	CRT support routines.
//  Used to build the project without standard CRT.

#include "main.h"
#include "crtsup.h"

/***
*strcmp - compare two strings, returning less than, equal to, or greater than
*
*Purpose:
*       STRCMP compares two strings and returns an integer
*       to indicate whether the first is less than the second, the two are
*       equal, or whether the first is greater than the second.
*
*       Comparison is done byte by byte on an UNSIGNED basis, which is to
*       say that Null (0) is less than any other character (1-255).
*
*Entry:
*       const char * src - string for left-hand side of comparison
*       const char * dst - string for right-hand side of comparison
*
*Exit:
*       returns -1 if src <  dst
*       returns  0 if src == dst
*       returns +1 if src >  dst
*
*Exceptions:
*
*******************************************************************************/

int __cdecl __strcmp (
        const char * src,
        const char * dst
        )
{
        int ret = 0 ;

        while( ! (ret = *(unsigned char *)src - *(unsigned char *)dst) && *dst)
                ++src, ++dst;

        if ( ret < 0 )
                ret = -1 ;
        else if ( ret > 0 )
                ret = 1 ;

        return( ret );
}


/***
*wcscmp - compare two wchar_t strings,
*        returning less than, equal to, or greater than
*
*Purpose:
*       wcscmp compares two wide-character strings and returns an integer
*       to indicate whether the first is less than the second, the two are
*       equal, or whether the first is greater than the second.
*
*       Comparison is done wchar_t by wchar_t on an UNSIGNED basis, which is to
*       say that Null wchar_t(0) is less than any other character.
*
*Entry:
*       const wchar_t * src - string for left-hand side of comparison
*       const wchar_t * dst - string for right-hand side of comparison
*
*Exit:
*       returns -1 if src <  dst
*       returns  0 if src == dst
*       returns +1 if src >  dst
*
*Exceptions:
*
*******************************************************************************/

int __cdecl __wcscmp (
        const wchar_t * src,
        const wchar_t * dst
        )
{
        int ret = 0 ;

        while( ! (ret = (int)(*src - *dst)) && *dst)
                ++src, ++dst;

        if ( ret < 0 )
                ret = -1 ;
        else if ( ret > 0 )
                ret = 1 ;

        return( ret );
}



int __cdecl __stricmp (
        const char * dst,
        const char * src
        )
{
    int f, l;

    do
    {
        if ( ((f = (unsigned char)(*(dst++))) >= 'A') && (f <= 'Z') )
            f -= 'A' - 'a';
        if ( ((l = (unsigned char)(*(src++))) >= 'A') && (l <= 'Z') )
            l -= 'A' - 'a';
    }
    while ( f && (f == l) );

    return(f - l);
}

int __cdecl __wcsicmp (
        const wchar_t * dst,
        const wchar_t * src
        )
{
	wchar_t f,l;
	
	do  {
		f = __ascii_towlower(*dst);
		l = __ascii_towlower(*src);
		dst++;
		src++;
	} while ( (f) && (f == l) );
	
	return (int)(f - l);
}



//
//	Compare string with wildcast ignore case.
//
int __cdecl __wcswicmp(const WCHAR *wild, const WCHAR *string) 
{
	const WCHAR *cp = NULL, *mp = NULL;
	
	while ((*string) && (*wild != '*')) 
	{
		if ((__ascii_towlower(*wild) != __ascii_towlower(*string)) && (*wild != '?')) 
			return 0;
		wild++;
		string++;
	}
	
	while (*string) 
	{
		if (*wild == '*') 
		{
			if (!*++wild) 
				return 1;
			mp = wild;
			cp = string+1;
		} 
		else if ((__ascii_towlower(*wild) == __ascii_towlower(*string)) || (*wild == '?')) 
		{
			wild++;
//			cp = string+1;	// '*' requires any symbol (*a != a)
			cp = string;	// '*' doesn't require a symbol (*a == a)
		} 
		else 
		{
			wild = mp;
			string = cp++;
		}
	}	// while (*string) 
	
	while (*wild == '*')
		wild++;

  return !*wild;
}


//
//	Compare string with wildcast ignore case.
//
int __cdecl __strwicmp(const CHAR *wild, const CHAR *string) 
{
	const CHAR *cp = NULL, *mp = NULL;
	
	while ((*string) && (*wild != '*')) 
	{
		if ((__ascii_tolower(*wild) != __ascii_tolower(*string)) && (*wild != '?')) 
			return 0;
		wild++;
		string++;
	}
	
	while (*string) 
	{
		if (*wild == '*') 
		{
			if (!*++wild) 
				return 1;
			mp = wild;
//			cp = string+1;	// '*' requires any symbol (*a != a)
			cp = string;	// '*' doesn't require a symbol (*a == a)
		} 
		else if ((__ascii_tolower(*wild) == __ascii_tolower(*string)) || (*wild == '?')) 
		{
			wild++;
			string++;
		} 
		else 
		{
			wild = mp;
			string = cp++;
		}
	}	// while (*string) 
	
	while (*wild == '*')
		wild++;

  return !*wild;
}


//
//	Scans memory buffer for a substring containing a wildcast.
//	If found returns the pointer to the substring and it's size.
//
CHAR* __cdecl __memwiscan(
	const CHAR	*mem,
	int			size,
	const CHAR	*wild,
	int			*psize
	)
{
	const CHAR *wp = wild, *mp = NULL;
	char	c;
	int		s;

	while((size) && (*wp))
	{
		while((c = *wp) && (c != '*') && (c != '?') && (size) && (__ascii_tolower(c) != __ascii_tolower(*mem)))
		{
			size -= 1;
			mem += 1;
		}

		mp = mem;
		s = size;

		while((c = *wp) && (c != '*') && (size) && ((c == '?') || (__ascii_tolower(c) == __ascii_tolower(*mem))))
		{
			size -= 1;
			mem += 1;
			wp += 1;
		}

		if (c == '*')
		{
			while(*wp == '*')
				wp += 1;

			if (mem = __memwiscan(mem, size, wp, &size))
				*psize = ((int)(mem - mp) + size);
			else
				mp = NULL;

			break;
		}

		if (c == 0)
		{
			*psize = s - size;
			break;
		}
		
		mem = mp + 1;

		if (s)
			size = s - 1;

		wp = wild;
		mp = NULL;
	}	// while((size) && (*wp))

	return((CHAR*)mp);
}


CHAR* __cdecl __memchr(
	CHAR*	mem,
	int		size,
	CHAR	c
	)
{
	int		i;
	CHAR*	found = NULL;

	for (i=0; i<size; i++)
	{
		if (*mem == c)
		{
			found = mem;
			break;
		}
		mem += 1;
	}

	return(found);
}

CHAR* __cdecl __memstr(
	CHAR*	mem,
	int		size,
	CHAR*	s
	)
{
	int		i;
	CHAR*	found = NULL;

	while(size)
	{
		i = 0;

		while(s[i] && (i < size) && (mem[i] == s[i]))
			i += 1;

		if (s[i] == 0)
		{
			found = mem;
			break;
		}

		mem += 1;
		size -= 1;
	}

	return(found);
}


/***
*void srand(seed) - seed the random number generator
*
*Purpose:
*       Seeds the random number generator with the int given.  Adapted from the
*       BASIC random number generator.
*
*Entry:
*       unsigned seed - seed to seed rand # generator with
*
*Exit:
*       None.
*
*Exceptions:
*
*******************************************************************************/
static unsigned long g_seed = 0;

void __cdecl _srand (
        unsigned int seed
        )
{
	g_seed = (unsigned long)seed;
}

/***
*int rand() - returns a random number
*
*Purpose:
*       returns a pseudo-random number 0 through 32767.
*
*Entry:
*       None.
*
*Exit:
*       Returns a pseudo-random number 0 through 32767.
*
*Exceptions:
*
*******************************************************************************/
ULONG RtlRandomEx( PULONG Seed );

int __cdecl _rand (
	void
	)
{
	ULONG r = RtlRandomEx(&g_seed);
	return ((r * 214013L+ 2531011L) >> 16) & 0x7fff;
}

/*
 * Number of 100 nanosecond units from 1/1/1601 to 1/1/1970
 */
#define EPOCH_BIAS  116444736000000000i64

/*
 * Union to facilitate converting from FILETIME to unsigned __int64
 */
typedef union {
        unsigned __int64 ft_scalar;
        FILETIME ft_struct;
        } FT;


/***
*__time64_t _time64(timeptr) - Get current system time and convert to a
*       __time64_t value.
*
*Purpose:
*       Gets the current date and time and stores it in internal 64-bit format
*       (__time64_t). The time is returned and stored via the pointer passed in
*       timeptr. If timeptr == NULL, the time is only returned, not stored in
*       *timeptr. The internal (__time64_t) format is the number of seconds
*       since 00:00:00, Jan 1 1970 (UTC).
*
*Entry:
*       __time64_t *timeptr - pointer to long to store time in.
*
*Exit:
*       returns the current time.
*
*Exceptions:
*
*******************************************************************************/

__time64_t __cdecl __time64 (
        __time64_t *timeptr
        )
{
        __time64_t tim;
        FT nt_time;

        GetSystemTimeAsFileTime( &(nt_time.ft_struct) );

        tim = (__time64_t)((nt_time.ft_scalar - EPOCH_BIAS) / 10000000i64);


        if (timeptr)
                *timeptr = tim;         /* store time if requested */

        return tim;
}
