//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ISFB project. Version 2.13.24.1
//	
// module: comsup.h
// $Revision: 39 $
// $Date: 2013-03-19 18:02:34 +0300 (Вт, 19 мар 2013) $
// description:
//	COM interfaces support routines.


BOOL	ComInit(HRESULT* phRes);
VOID	ComUninit(HRESULT hRes);
PVOID	ComCreateInterface(REFCLSID ClsId, REFIID RefId);