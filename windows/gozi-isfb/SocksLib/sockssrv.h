//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// SOCKS project. Version 1.3
//	
// module: sockssrv.h
// $Revision: 43 $
// $Date: 2014-03-15 21:03:17 +0300 (Сб, 15 мар 2014) $
// description:
//	Socks server main header file.


#define	SOCKS_CMD_CONNECT			1
#define	SOCKS_CMD_BIND				2
#define	SOCKS_CMD_UDP				3

#define	SOCKS_ADDR_IP4				1
#define	SOCKS_ADDR_IP6				4
#define	SOCKS_ADDR_DNAME			3

#define	SOCKS_RPL_GRANTED			0x5a
#define	SOCKS_RPL_FAILED			0x5b

#define	SOCKS_AUTH_NO				0
#define	SOCKS_AUTH_UP				2
#define	SOCKS_AUTH_UNKNOWN			0xff

#define	SOCKS5_OK					0
#define	SOCKS5_ERROR				1
#define	SOCKS5_FAILED				3
#define	SOCKS5_UNREACHABLE			4

#pragma pack(push)
#pragma pack(1)

typedef struct _SOCKS4_REQUEST
{
	UCHAR	Command;
	USHORT	Port;
	ULONG	Ip;
	UCHAR	User;
} SOCKS4_REQUEST, PSOCKS4_REQUEST;


typedef struct _SOCKS4_REPLY
{
	UCHAR	NullChar;
	UCHAR	Status;
	USHORT	Reserved0;
	ULONG	Reserved1;
} SOCKS4_REPLY, *PSOCKS4_REPLY;


typedef struct _SOCKS5_REPLY0
{
	UCHAR	Version;	// must be 05
	UCHAR	Method;
} SOCKS5_REPLY0, *PSOCKS5_REPLY0;

typedef struct _SOCKS5_HEADER
{
	UCHAR	Version;	// must be 05
	union
	{
		UCHAR	Status;
		UCHAR	Command;
	};
	UCHAR	Reserved;
	UCHAR	AddressType;
} SOCKS5_HEADER, *PSOCKS5_HEADER;

typedef struct _SOCKS5_IP4
{
	ULONG	Address;
	USHORT	Port;
} SOCKS5_IP4, *PSOCKS5_IP4;

typedef struct _SOCKS5_IP6
{
	UCHAR	Address[16];
	USHORT	Port;
} SOCKS5_IP6, *PSOCKS5_IP6;

typedef struct _SOCKS5_DNAME
{
	UCHAR	Length;
	UCHAR	Name[256];
} SOCKS5_DNAME, *PSOCKS5_DNAME;

typedef struct _SOCKS5_MESSAGE
{
	SOCKS5_HEADER	Header;
	union
	{
		SOCKS5_IP4		Ip4;
		SOCKS5_IP6		Ip6;
		SOCKS5_DNAME	DName;
	};
} SOCKS5_MESSAGE, *PSOCKS5_MESSAGE;


#pragma pack(pop)


// Usefull macros
#define IP4_ADDR(a,b,c,d)	htonl(((UCHAR)((a) & 0xff) << 24) | ((UCHAR)((b) & 0xff) << 16) | ((UCHAR)((c) & 0xff) << 8) | (UCHAR)((d) & 0xff))