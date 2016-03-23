#ifndef __PRIV_H_
#define __PRIV_H_

#ifndef SE_RESTORE_NAME
#define SE_RESTORE_NAME                   TEXT("SeRestorePrivilege")
#endif

BOOL 
	SetPrivilege(
		IN HANDLE hToken,
		IN LPCTSTR lpszPrivilege,
		IN BOOL bEnablePrivilege
		); 

BOOL 
	SetProcessPrivilege(
		IN LPCTSTR PrivilegeName, 
		IN BOOL bSet
		);

#endif //__PRIV_H_