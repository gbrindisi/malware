//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ISFB project. Version 2.13.24.1
//	
// module: dll.h
// $Revision: 265 $
// $Date: 2014-07-09 18:33:23 +0400 (Ср, 09 июл 2014) $
// description:
//	ISFB installer DLL include file.

// This define is mandatory, it marks DLL-specific code sections.
#define _DLL_INSTALLER		TRUE

// Allows installing software right on the DLL load. 
// Otherwise you have to call DllRegisterServer() function.
//#define	_START_ON_DLL_LOAD	TRUE
