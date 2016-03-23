//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ISFB project. Version 2.13.24.1
//	
// module: scrshot.h
// $Revision: 367 $
// $Date: 2014-10-07 17:26:07 +0400 (Вт, 07 окт 2014) $
// description:
//	Window screenshot generation routines

#pragma once

#ifdef __cplusplus
 extern "C" {
#endif

//
//	Obtains encoder class ID for the specified image format.
//
WINERROR ScrGetEncoderClsid(
	const WCHAR*	format, 
	CLSID*			pClsid
	);


//
//	Generates a screensot of the specified window and saves it into the specified file.
//
WINERROR ScrGenerateImage(
	HWND		hWnd,		// window to genereate a screenshot
	HBITMAP*	pBitmap,
	HBITMAP*	pSource
	);



//
//	Generates a screensot of the specified window and saves it into the specified file.
//
WINERROR ScrMakeScreenshot(
	HWND			hWnd,		// window to genereate a screenshot
	LPWSTR			pFilePath,	// file path to store the screenshot
	LPSTREAM		pStream,	// stream to store the screenshot
	const CLSID*	pClsId		// image encoder class ID
	);


#ifdef __cplusplus
 }
#endif
