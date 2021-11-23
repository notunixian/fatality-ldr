#include <windows.h>
#include <iostream>
#include <tlhelp32.h>

/* required */
#include "steam_module.h"
#include "legacy_steam.h"

#include "fatality_loader.h"

#include "legacy.h"
#include "fagality.h"
#include <random>

/* required */

HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

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

HANDLE csgo_handle = get_csgo_handle();
HANDLE steam_handle = get_steam_handle();

void inject_desync()
{
	std::cout << R"(
  _____  ______  _______     ___   _  _____ 
 |  __ \|  ____|/ ____\ \   / / \ | |/ ____|
 | |  | | |__  | (___  \ \_/ /|  \| | |     
 | |  | |  __|  \___ \  \   / | . ` | |     
 | |__| | |____ ____) |  | |  | |\  | |____ 
 |_____/|______|_____/   |_|  |_| \_|\_____|
                                            
                                                                                                            																			                                                                                   
        )";
	std::cout << "\n";

	SetConsoleTextAttribute(hConsole, 3);

	while ((steam_handle = get_steam_handle(), steam_handle == INVALID_HANDLE_VALUE))
		Sleep(1000);

	printf("[+] found steam.exe\n");

	char steam_mod_path[] = "C:/Windows/SysWOW64/ftc_steam_module.dll";
	void* steam_module = VirtualAllocEx(steam_handle, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	WriteProcessMemory(steam_handle, steam_module, steam_mod_path, sizeof(steam_mod_path), nullptr);
	HANDLE steam_thread = CreateRemoteThread(steam_handle, nullptr, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, steam_module, 0, 0);

	while ((csgo_handle = get_csgo_handle(), csgo_handle == INVALID_HANDLE_VALUE))
		Sleep(1000);

	printf("[+] found csgo.exe\n");

	char csgo1_mod_path[] = "C:/Windows/SysWOW64/ftc_loader.dll";
	void* csgo1_module = VirtualAllocEx(csgo_handle, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	WriteProcessMemory(csgo_handle, csgo1_module, csgo1_mod_path, sizeof(csgo1_mod_path), nullptr);
	HANDLE csgo1_legacy_thread = CreateRemoteThread(csgo_handle, nullptr, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, csgo1_module, 0, 0);

	char csgo_mod_path[] = "C:/Windows/SysWOW64/ftc_dependency.dll";
	void* csgo_module = VirtualAllocEx(csgo_handle, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	WriteProcessMemory(csgo_handle, csgo_module, csgo_mod_path, sizeof(csgo_mod_path), nullptr);
	HANDLE csgo_thread = CreateRemoteThread(csgo_handle, nullptr, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, csgo_module, 0, 0);

	printf("[+] wait few minutes to it load completely (console will close itself in 5 minutes)\n");

	Sleep(300000);
}

void inject_legacy()
{
	std::cout << R"(
  _      ______ _____          _______     __
 | |    |  ____/ ____|   /\   / ____\ \   / /
 | |    | |__ | |  __   /  \ | |     \ \_/ / 
 | |    |  __|| | |_ | / /\ \| |      \   /  
 | |____| |___| |__| |/ ____ \ |____   | |   
 |______|______\_____/_/    \_\_____|  |_|   
                                                                                                               																			                                                                                   
        )";
	std::cout << "\n";

	SetConsoleTextAttribute(hConsole, 3);

	while ((steam_handle = get_steam_handle(), steam_handle == INVALID_HANDLE_VALUE))
		Sleep(1000);

	printf("[+] found steam.exe\n");

	char steam_module_path[] = "C:/Windows/SysWOW64/legacy_steam_module.dll";
	void* steam_module = VirtualAllocEx(steam_handle, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	WriteProcessMemory(steam_handle, steam_module, steam_module_path, sizeof(steam_module_path), nullptr);
	HANDLE steam_thread = CreateRemoteThread(steam_handle, nullptr, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, steam_module, 0, 0);

	while ((csgo_handle = get_csgo_handle(), csgo_handle == INVALID_HANDLE_VALUE))
		Sleep(1000);
	printf("[+] found csgo.exe\n");

	char csgo1_mod_path[] = "C:/Windows/SysWOW64/ftc_legacy.dll";
	void* csgo1_module = VirtualAllocEx(csgo_handle, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	WriteProcessMemory(csgo_handle, csgo1_module, csgo1_mod_path, sizeof(csgo1_mod_path), nullptr);
	HANDLE csgo1_thread = CreateRemoteThread(csgo_handle, nullptr, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, csgo1_module, 0, 0);

	printf("[+] wait few minutes to it load completely (console will close itself in 5 minutes)\n");

	Sleep(300000);
}

void randomizetitle()
{
	std::random_device rd;
	std::mt19937 mt(rd());
	std::uniform_int_distribution<> distr(0, 51);
	std::string name = "";
	char alphabet[] = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z' };
	for (int i = 0; i < 15; ++i)
	{
		name = name + alphabet[distr(mt)];
		SetConsoleTitleA(name.c_str());
	}
}

int main( ) {

	randomizetitle();

	SetConsoleTextAttribute(hConsole, 4);

	if (csgo_handle != INVALID_HANDLE_VALUE) {
		TerminateProcess(csgo_handle, 0);
		printf("Please open loader before CS:GO\n");
	}

	if (steam_handle == INVALID_HANDLE_VALUE) {
		printf("Please open Steam before loading");
		exit(0);
	}

	if( !write_memory_to_new_file( "C:/Windows/SysWOW64/ftc_dependency.dll", sizeof( fagality_dll ), fagality_dll ) ) {
		printf( "[-] failed to write to C:/Windows/SysWOW64/ftc_dependency.dll. (missing admin perms?)\n" );
		return 1;
	}

	if( !write_memory_to_new_file( "C:/Windows/SysWOW64/ftc_steam_module.dll", sizeof( steam_module ), steam_module ) ) {
		printf( "[-] failed to write to C:/Windows/SysWOW64/ftc_steam_module.dll. (missing admin perms?)\n" );
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

	SetConsoleTextAttribute(hConsole, 7);
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