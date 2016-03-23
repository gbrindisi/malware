#include	"..\common\common.h"

//***********************************************************************************
// Name: SetPrivilege
//
// Routine Description:
// 
//   Enables or disables token privilege
//
// Return Value:
// 
//     If the function handles the control signal, it should return TRUE. 
//     If it returns FALSE, the next handler function in the list of handlers for 
//     this process is used.
//	
// Parameters:
//
//  hToken       - A handle to the access token that contains the privileges 
//                 to be modified.
// lpszPrivilege - A pointer to a null-terminated string that specifies the name 
//                 of the privilege
// bEnablePrivilege - enable or disable privilege
//  
//***********************************************************************************
BOOL 
	SetPrivilege(
		IN HANDLE hToken,
		IN LPCTSTR lpszPrivilege,
		IN BOOL bEnablePrivilege
		) 
{
	BOOL fbResult;
	TOKEN_PRIVILEGES Privileges;
	LUID luid;

	fbResult = 
		LookupPrivilegeValue( 
			NULL,            // lookup privilege on local system
			lpszPrivilege,   // privilege to lookup 
			&luid );         // receives LUID of privilege
	
	if ( fbResult ){

		Privileges.PrivilegeCount = 1;
		Privileges.Privileges[0].Luid = luid;
		if (bEnablePrivilege) {
			Privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		}
		else {
			Privileges.Privileges[0].Attributes = 0;
		}
		// Enable the privilege or disable all privileges.

		fbResult = 
			AdjustTokenPrivileges(
				hToken, 
				FALSE, 
				&Privileges, 
				sizeof(TOKEN_PRIVILEGES), 
				(PTOKEN_PRIVILEGES) NULL, 
				(PDWORD) NULL
				);
		
		if( fbResult ){
			fbResult = (GetLastError() == ERROR_SUCCESS);
		}
	}

	return fbResult;
}
//***********************************************************************************
// Name: SetProcessPrivilege
//
// Routine Description:
// 
//   Enables or disables privilege for the current process.
//
// Return Value:
// 
//     If the function handles the control signal, it should return TRUE. 
//     If it returns FALSE, the next handler function in the list of handlers for 
//     this process is used.
//	
// Parameters:
//
// lpszPrivilege - A pointer to a null-terminated string that specifies the name 
//                 of the privilege
// bSet - enable or disable privilege
//  
//***********************************************************************************
BOOL 
	SetProcessPrivilege(
		IN LPCTSTR PrivilegeName, 
		IN BOOL bSet
		)
{
	HANDLE hToken;
	BOOL fbResult;

	//
	// Open process access token
	//
	fbResult = 
		OpenProcessToken( 
			GetCurrentProcess(),
			TOKEN_ADJUST_PRIVILEGES,
			&hToken
			);

	if( fbResult ) {
		//
		// set token privilege
		//
		fbResult = 
			SetPrivilege( 
				hToken, 
				PrivilegeName, 
				bSet
				);
		CloseHandle( hToken);
	}
	return fbResult;
}