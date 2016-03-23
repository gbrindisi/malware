//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// KeyLog project. Version 3.0
//	
// module: llhook.h
// $Revision: 58 $
// $Date: 2014-12-17 17:44:58 +0300 (Ср, 17 дек 2014) $
// description: 
//	Low-level keyboard hook

#ifndef __LLHOOK_H_
#define __LLHOOK_H_

VOID LLHookInitialize(VOID);
VOID LLHookRelease(VOID);
VOID LLHookEnable(BOOL bEnable);

#endif //__LLHOOK_H_