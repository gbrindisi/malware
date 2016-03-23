//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ISFB project. Version 2.13.24.1
//	
// module: crtsup.h
// $Revision: 326 $
// $Date: 2014-09-12 22:18:31 +0400 (Пт, 12 сен 2014) $
// description:
//	CRT support routines.
//  Used to build the project without standard CRT.



#define __ascii_tolower(c)      ( (((c) >= 'A') && ((c) <= 'Z')) ? ((c) - 'A' + 'a') : (c) )
#define __ascii_toupper(c)      ( (((c) >= 'a') && ((c) <= 'z')) ? ((c) - 'a' + 'A') : (c) )
#define __ascii_towlower(c)     ( (((c) >= L'A') && ((c) <= L'Z')) ? ((c) - L'A' + L'a') : (c) )
#define __ascii_towupper(c)     ( (((c) >= L'a') && ((c) <= L'z')) ? ((c) - L'a' + L'A') : (c) )

int __cdecl __strcmp (const char * src, const char * dst);
int __cdecl __wcscmp (const wchar_t * src, const wchar_t * dst);
int __cdecl __stricmp (const char * dst, const char * src);
int __cdecl __wcsicmp (const wchar_t * dst, const wchar_t * src);
int __cdecl __strwicmp(const CHAR *wild, const CHAR *string);
int __cdecl __wcswicmp(const WCHAR *wild, const WCHAR *string);
CHAR* __cdecl __memwiscan(const CHAR *mem, int size, const CHAR	*wild, int *psize);
CHAR* __cdecl __memchr(CHAR* mem, int size, CHAR c);
CHAR* __cdecl __memstr(CHAR* mem, int size, CHAR* s);


#ifdef _UNICODE
	#define	_lstrcmp	__wcscmp
	#define _lstrcmpi	__wcsicmp
#else
	#define _lstrcmp	__strcmp	
	#define _lstrcmpi	__stricmp
#endif

int __cdecl _rand (
	void
	);
void __cdecl _srand (
        unsigned int seed
        );

__time64_t __cdecl __time64 (
        __time64_t *timeptr
        );

#define time(x)  __time64(x)