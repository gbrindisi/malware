//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// KeyLog project. Version 3.0
//	
// module: wnd.c
// $Revision: 58 $
// $Date: 2014-12-17 17:44:58 +0300 (Ср, 17 дек 2014) $
// description: 
//	Hidden window that receives system notifications.

#ifndef __WND_H_
#define __WND_H_

#define NOTIFY_MAX       5

typedef struct _NOTIFICATION_WINDOW NOTIFICATION_WINDOW,*PNOTIFICATION_WINDOW;

typedef WINERROR (*PNWND_REGISTER0)(PVOID Context);
typedef WINERROR (*PNWND_REGISTER)(HWND hWnd,PVOID Context);
typedef BOOL     (*PNWND_HANDLE)(PVOID Context,HWND hWnd,UINT uMsg,WPARAM wParam,LPARAM lParam, LRESULT *lResult);
typedef VOID     (*PNWND_UNREGISTER0)(PVOID Context);
typedef VOID     (*PNWND_UNREGISTER)(HWND hWnd,PVOID Context);

typedef struct _NOTIFICATION_CONSUMER
{
	PNWND_REGISTER0		Register0;		// called before window is been created
	PNWND_REGISTER		Register;		// called from WM_CREATE
	PNWND_HANDLE		Handle;			// handles window messages
	PNWND_UNREGISTER0	Unregister0;	// called before exiting thread
	PNWND_UNREGISTER	Unregister;		// called from WM_DESTROY
	BOOL volatile		bActive;		// specifies if the consumer is active	
}NOTIFICATION_CONSUMER,*PNOTIFICATION_CONSUMER;

WINERROR NWindowStart(VOID);
VOID NWindowStop(VOID);

LONG NWindowRegister( PNOTIFICATION_CONSUMER Consumer );
VOID NWindowUnregister( PNOTIFICATION_CONSUMER Consumer );

#endif //__WND_H_