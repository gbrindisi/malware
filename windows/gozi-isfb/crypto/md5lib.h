
#pragma once

// MD5 hash structure
typedef union _MD5
{
	struct 
	{
		DWORD dd0;
		DWORD dd1;
		DWORD dd2;
		DWORD dd3;
	};
	DWORD dd[4];
	UCHAR db[0x10];
} MD5, *PMD5;


typedef struct _CHAINED_BUFFER CHAINED_BUFFER, *PCHAINED_BUFFER;

typedef struct _CHAINED_BUFFER 
{
	PCHAINED_BUFFER Next;
	PVOID Buffer;
	ULONG Size;
} CHAINED_BUFFER, *PCHAINED_BUFFER;


