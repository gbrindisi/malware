//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ZipLib project. Version 1.0
//	
// module: ziplib.h
// $Revision: 16 $
// $Date: 2014-10-03 09:55:21 +0400 (Пт, 03 окт 2014) $
// description:
//	ZipLib main definition file.

#ifndef __ZIPLIB_H__
#define __ZIPLIB_H__

#include "platform.h"

PL_ERROR
ZipDir(PL_WCHAR *Dir, PL_WCHAR *ZipFile);

PL_ERROR
ZipFileToHandle(PL_WCHAR *Root, PL_WCHAR *Path, PL_WCHAR *FileName, PL_WCHAR *ZipFile);

#endif
