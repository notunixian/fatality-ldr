#include <windows.h>
#include <iostream>
#include <tlhelp32.h>
#include "fagality.h"
#include "steam_module.h"
#include "fatality_loader.h"
#include "legacy.h"
#include "legacy_steam.h"
#include <winbase.h>
#include "crash_fix.h"

DWORD FindProcessId( const std::wstring &processName )
{
	PROCESSENTRY32 processInfo;
	processInfo.dwSize = sizeof( processInfo );

	HANDLE processesSnapshot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, NULL );
	if( processesSnapshot == INVALID_HANDLE_VALUE )
		return 0;

	Process32First( processesSnapshot, &processInfo );
	if( !processName.compare( processInfo.szExeFile ) )
	{
		CloseHandle( processesSnapshot );
		return processInfo.th32ProcessID;
	}

	while( Process32Next( processesSnapshot, &processInfo ) )
	{
		if( !processName.compare( processInfo.szExeFile ) )
		{
			CloseHandle( processesSnapshot );
			return processInfo.th32ProcessID;
		}
	}

	CloseHandle( processesSnapshot );
	return 0;
}

HANDLE get_csgo_handle( int perms = PROCESS_ALL_ACCESS ) {
	DWORD pid = FindProcessId( L"csgo.exe" );

	if( !pid )
		return INVALID_HANDLE_VALUE;

	return OpenProcess( perms, FALSE, pid );
}

HANDLE get_steam_handle( ) {
	DWORD pid = FindProcessId( L"steam.exe" );

	if( !pid )
		return INVALID_HANDLE_VALUE;

	return OpenProcess( PROCESS_ALL_ACCESS, FALSE, pid );
}

bool write_memory_to_file( HANDLE hFile, LONG offset, DWORD size, LPCVOID dataBuffer )
{
	DWORD lpNumberOfBytesWritten = 0;
	DWORD retValue = 0;
	DWORD dwError = 0;

	if( ( hFile != INVALID_HANDLE_VALUE ) && dataBuffer )
	{
		retValue = SetFilePointer( hFile, offset, NULL, FILE_BEGIN );
		dwError = GetLastError( );

		if( ( retValue == INVALID_SET_FILE_POINTER ) && ( dwError != NO_ERROR ) )
		{
			return false;
		}
		else
		{
			if( WriteFile( hFile, dataBuffer, size, &lpNumberOfBytesWritten, 0 ) )
			{
				return true;
			}
			else
			{
				return false;
			}
		}
	}
	else
	{
		return false;
	}
}

bool write_memory_to_new_file( const CHAR *file, DWORD size, LPCVOID dataBuffer )
{
	HANDLE hFile = CreateFileA( file, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, 0, 0 );

	if( hFile != INVALID_HANDLE_VALUE )
	{
		bool resultValue = write_memory_to_file( hFile, 0, size, dataBuffer );
		CloseHandle( hFile );
		return resultValue;
	}
	else
	{
		return false;
	}
}

// TODO: add error checks for this, will remain commented until i do so.

//void open_csgo()
//{
//	printf("[+] opening csgo\n");
//	printf("[!] if you do not see csgo open within 5 seconds, open csgo manually.\n");
//	WinExec("C:\\Program FIles (x86)\\Steam\\steam.exe -applaunch 730", 0);
//}

void inject_desync()
{
	HANDLE csgo_handle = get_csgo_handle();
	if (csgo_handle != INVALID_HANDLE_VALUE) {
		TerminateProcess(csgo_handle, 0);
		MessageBoxA(0, "Please open loader before CS:GO", "", 0);
		exit(0);
	}

	HANDLE steam_handle = get_steam_handle();
	if (steam_handle == INVALID_HANDLE_VALUE) {
		MessageBoxA(0, "Please open Steam before loading", "", 0);
		exit(0);
	}

	printf("[*] waiting for steam\n");
	while ((steam_handle = get_steam_handle(), steam_handle == INVALID_HANDLE_VALUE))
		Sleep(1000);

	printf("[+] found steam\n");

	char steam_mod_path[] = "C:/Windows/SysWOW64/ftc_steam_module.dll";
	void* steam_module = VirtualAllocEx(steam_handle, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	WriteProcessMemory(steam_handle, steam_module, steam_mod_path, sizeof(steam_mod_path), nullptr);
	HANDLE steam_thread = CreateRemoteThread(steam_handle, nullptr, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, steam_module, 0, 0);

	printf("[*] waiting for steam thread to finish\n");
	WaitForSingleObject(steam_thread, INFINITE);

	// open_csgo()
	printf("[+] waiting for csgo\n");
	while ((csgo_handle = get_csgo_handle(), csgo_handle == INVALID_HANDLE_VALUE))
		Sleep(1000);

	printf("[+] found csgo\n");

	Sleep(1000);

	printf("[+] injecting ftc loader");

	char csgo1_mod_path[] = "C:/Windows/SysWOW64/ftc_loader.dll";
	void* csgo1_module = VirtualAllocEx(csgo_handle, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	WriteProcessMemory(csgo_handle, csgo1_module, csgo1_mod_path, sizeof(csgo1_mod_path), nullptr);
	HANDLE csgo1_legacy_thread = CreateRemoteThread(csgo_handle, nullptr, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, csgo1_module, 0, 0);

	printf("[*] waiting for loader thread to finish\n");
	WaitForSingleObject(csgo1_legacy_thread, INFINITE);

	printf("[+] injecting ftc dependency\n");

	char csgo_mod_path[] = "C:/Windows/SysWOW64/ftc_dependency.dll";
	void* csgo_module = VirtualAllocEx(csgo_handle, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	WriteProcessMemory(csgo_handle, csgo_module, csgo_mod_path, sizeof(csgo_mod_path), nullptr);
	HANDLE csgo_thread = CreateRemoteThread(csgo_handle, nullptr, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, csgo_module, 0, 0);

	printf("[+] injecting ftc clantag crash fix\n");

	// another ghetto thing coming in, too lazy to make the crash fix dll wait for tier0.dll so we just wait 8 seconds

	Sleep(8000);

	char csgo2_mod_path[] = "C:/Windows/SysWOW64/ftc_crash_fix.dll";
	void* csgo2_module = VirtualAllocEx(csgo_handle, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	WriteProcessMemory(csgo_handle, csgo2_module, csgo2_mod_path, sizeof(csgo2_mod_path), nullptr);
	HANDLE csgo2_thread = CreateRemoteThread(csgo_handle, nullptr, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, csgo2_module, 0, 0);

	printf("[+] Injected ftc desync\n");

	printf("[+] done\n");
	Sleep(4000);
}

void inject_legacy()
{
	HANDLE csgo_handle = get_csgo_handle();
	if (csgo_handle != INVALID_HANDLE_VALUE) {
		TerminateProcess(csgo_handle, 0);
		MessageBoxA(0, "Please re-open CS:GO", "", 0);
		exit(0);
	}

	HANDLE steam_handle = get_steam_handle();
	if (steam_handle == INVALID_HANDLE_VALUE) {
		MessageBoxA(0, "Please open Steam before loading", "", 0);
		
	}

	printf("[*] waiting for steam.exe\n");
	while ((steam_handle = get_steam_handle(), steam_handle == INVALID_HANDLE_VALUE))
		Sleep(1000);

	printf("[+] found steam.exe\n");

	char steam_module_path[] = "C:/Windows/SysWOW64/fatal_legacy_steam_module.dll";
	void* steam_module = VirtualAllocEx(steam_handle, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	WriteProcessMemory(steam_handle, steam_module, steam_module_path, sizeof(steam_module_path), nullptr);
	HANDLE steam_thread = CreateRemoteThread(steam_handle, nullptr, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, steam_module, 0, 0);

	printf("[*] waiting for steam thread to finish\n");
	WaitForSingleObject(steam_thread, INFINITE);

	printf("[*] waiting for csgo.exe\n");
	while ((csgo_handle = get_csgo_handle(), csgo_handle == INVALID_HANDLE_VALUE))
		Sleep(1000);

	printf("[+] found csgo.exe\n");

	Sleep(1000);

	char csgo1_mod_path[] = "C:/Windows/SysWOW64/fatal_legacy.dll";
	void* csgo1_module = VirtualAllocEx(csgo_handle, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	WriteProcessMemory(csgo_handle, csgo1_module, csgo1_mod_path, sizeof(csgo1_mod_path), nullptr);
	HANDLE csgo1_thread = CreateRemoteThread(csgo_handle, nullptr, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, csgo1_module, 0, 0);

	printf("[*] waiting for loader thread to finish\n");
	WaitForSingleObject(csgo1_thread, INFINITE);

	printf("[+] injected ftc legacy\n");

	printf("[+] done\n");
	Sleep(4000);
}

int main( ) {
	SetConsoleTitleA("discord.gg/stayfatal");
	HANDLE csgo_handle = get_csgo_handle( );
	if( csgo_handle != INVALID_HANDLE_VALUE ) {
		TerminateProcess( csgo_handle, 0 );
		MessageBoxA( 0, "Please open loader before CS:GO", "", 0 );
	}

	HANDLE steam_handle = get_steam_handle( );
	if( steam_handle == INVALID_HANDLE_VALUE ) {
		MessageBoxA( 0, "Please open Steam before loading", "", 0 );
		return 1;
	}

	if( !write_memory_to_new_file( "C:/Windows/SysWOW64/ftc_dependency.dll", sizeof( fagality_dll ), fagality_dll ) ) {
		printf( "[-] failed to write to C:/Windows/SysWOW64/ftc_dependency.dll. (missing admin perms?)\n" );
		return 1;
	}


	if( !write_memory_to_new_file( "C:/Windows/SysWOW64/ftc_steam_module.dll", sizeof( steam_module ), steam_module ) ) {
		printf( "[-] failed to write to C:/Windows/SysWOW64/ftc_steam_module.dll. (missing admin perms?)\n" );
		return 1;
	}

	if( !write_memory_to_new_file( "C:/Windows/SysWOW64/ftc_loader.dll", sizeof( rawData ), rawData ) ) {
		printf( "[-] failed to write to C:/Windows/SysWOW64/ftc_loader.dll. (missing admin perms?)\n" );
		return 1;
	}
	if (!write_memory_to_new_file("C:/Windows/SysWOW64/fatal_legacy_steam_module.dll", sizeof(legacy_steam_module), legacy_steam_module))
	{
		printf("[-] failed to write to C:/Windows/SysWOW64/fatal_legacy_steam_module.dll. (missing admin perms?)\n");
		return 1;
	}

	if (!write_memory_to_new_file("C:/Windows/SysWOW64/fatal_legacy.dll", sizeof(legacy_dll), legacy_dll))
	{
		printf("[-] failed to write to C:/Windows/SysWOW64/fatal_legacy.dll. (missing admin perms?)\n");
		return 1;
	}
	if (!write_memory_to_new_file("C:/Windows/SysWOW64/ftc_crash_fix.dll", sizeof(crash_fix), crash_fix))
	{
		printf("[-] failed to write to C:/Windows/SysWOW64/ftc_crash_fix.dll. (missing admin perms?)\n");
		return 1;
	}

	printf("[1] Inject Desync\n");
	printf("[2] Inject Legacy\n");
	printf("[!] Choose option: ");
	
	int option;
	std::cin >> option;
	
	system("cls");


	switch (option)
	{
	case 1:
		inject_desync();
		break;
	case 2:
		inject_legacy();
		break;
	default:
		printf("[-] Status: Failure: Invalid Selection\n");
		Sleep(3000);
	}
	return 0;
}
