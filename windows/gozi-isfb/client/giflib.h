#ifndef __GIFLIB_H__
#define __GIFLIB_H__

#define GIF_IMG_BEGIN	','
#define GIF_EXT_BEGIN	'!'
#define GIF_END			';'

#define GIF_GCE_LABEL		0xf9
#define GIF_APP_LABEL		0xff

typedef unsigned char UCHAR;
typedef unsigned short USHORT;

#define NETSCAPE_ID "NETSCAPE"

#define	GIF_FRAMES_PER_SECOND	4

#ifndef __PLATFORM_H__

#define	PL_BOOL					BOOL
#define PL_NULL					NULL
#define	PL_TRUE					TRUE
#define	PL_FALSE				FALSE
#define	PL_WCHAR				WCHAR
#define	PL_FILE					HANDLE

#define PL_E_OK					(WINERROR)NO_ERROR
#define PL_E_UNDEFINED			(WINERROR)ERROR_INVALID_FUNCTION
#define PL_E_UNSUPPORTED		(WINERROR)ERROR_NOT_SUPPORTED
#define PL_E_MALLOC				(WINERROR)ERROR_NOT_ENOUGH_MEMORY
#define PL_E_INVALID_PARAM		(WINERROR)ERROR_INVALID_PARAMETER
#define PL_E_LIMIT				(WINERROR)ERROR_BUFFER_OVERFLOW
#define PL_E_BUF_SMALL			(WINERROR)ERROR_INSUFFICIENT_BUFFER
#define PL_E_NOT_FOUND			(WINERROR)ERROR_NOT_FOUND
#define PL_E_GIF_DECODE			(WINERROR)ERROR_BAD_FORMAT
#define PL_E_EOF				(WINERROR)ERROR_HANDLE_EOF

#define PLPRINTF(x)   

#endif	// __PLATFORM_H__


#pragma pack(push, 1)

typedef struct _GIF_IMG_HEADER {
	UCHAR intro;
	unsigned short left;
	unsigned short top;
	unsigned short width;
	unsigned short height;
	union {
		struct {
			unsigned char	packedFields;
		};
		struct {
			unsigned char SizeOfLocalColorTable:3;
			unsigned char Reserved:2;
			unsigned char Sort:1;
			unsigned char Interlace:1;
			unsigned char LocalColorTable:1;
		};
	};
} GIF_IMG_HEADER, *PGIF_IMG_HEADER;


typedef struct _GIF_EXT {
	UCHAR	intro;
	UCHAR	label;
	UCHAR	blockSize;
} GIF_EXT, *PGIF_EXT;

typedef struct _GIF_GCE_EXT {
	GIF_EXT header;
	UCHAR	Flags;
	USHORT	Delay;
	UCHAR	TransparentColorIndex;
	UCHAR	BlockTerminator;
} GIF_GCE_EXT, *PGIF_GCE_EXT;

typedef struct _GIF_APP_EXT {
	GIF_EXT header;
	char appId[8];
} GIF_APP_EXT, *PGIF_APP_EXT;

typedef struct _GIF_HEADER {
	char	sign[3];
	char	ver[3];
	unsigned short	screenWidth;
	unsigned short	screenHeight;
	union {
		struct {
			unsigned char	packedFields;
		};
		struct {
			unsigned char SizeOfGlobalColorTable:3;
			unsigned char Sort:1;
			unsigned char ColorResolution:3;
			unsigned char GlobalColorTable:1;
		};
	};
	unsigned char	backgroundColorIndex;
	unsigned char	pixelAspectRatio;	
} GIF_HEADER, *PGIF_HEADER;
#pragma pack(pop)

//
//	Captures a video of the specified length from the current user desktop and stores it in animated GIF format.
//
WINERROR GifCaptureScreen(
	ULONG	Seconds,			// number of seconds of video to capture
	ULONG	FramesPerSecond,	// umber of frames per second, should be a power of 2
	PCHAR*	ppBuffer,			// receives a buffer containing screen capture in GIF
	PULONG	pSize				// receives size of the buffer
	);

#endif
