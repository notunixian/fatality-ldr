#include <Windows.h>
//#include <detours.h>

//#pragma comment(lib, "detours.lib")

using ofunc = BOOL(WINAPI*)(_In_opt_ LPCWSTR lpApplicationName,
    _Inout_opt_ LPWSTR lpCommandLine,
    _In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes,
    _In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
    _In_ BOOL bInheritHandles,
    _In_ DWORD dwCreationFlags,
    _In_opt_ LPVOID lpEnvironment,
    _In_opt_ LPCWSTR lpCurrentDirectory,
    _In_ LPSTARTUPINFOW lpStartupInfo,
    _Out_ LPPROCESS_INFORMATION lpProcessInformation);
ofunc original;
HMODULE _self;
bool queue_unload = false;

BOOL
WINAPI
_CreateProcessW(
    _In_opt_ LPCWSTR lpApplicationName,
    _Inout_opt_ LPWSTR lpCommandLine,
    _In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes,
    _In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
    _In_ BOOL bInheritHandles,
    _In_ DWORD dwCreationFlags,
    _In_opt_ LPVOID lpEnvironment,
    _In_opt_ LPCWSTR lpCurrentDirectory,
    _In_ LPSTARTUPINFOW lpStartupInfo,
    _Out_ LPPROCESS_INFORMATION lpProcessInformation
) {
    if (wcsstr(lpApplicationName, L"csgo.exe"))
        dwCreationFlags |= CREATE_SUSPENDED;

    auto result = original(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);

    if (wcsstr(lpApplicationName, L"csgo.exe")) {
        VirtualAllocEx(lpProcessInformation->hProcess, (void*)0x1BFF0000, 0xA59000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        queue_unload = true;
    }

    return result;
}

unsigned long __stdcall thr(void*) {
   // original = (ofunc)DetourFunction((PBYTE)CreateProcessW, (PBYTE)_CreateProcessW);

    while (!queue_unload)
        Sleep(500);

    //DetourRemove((PBYTE)original, (PBYTE)_CreateProcessW);
    FreeLibraryAndExitThread(_self, 0);

    return 0;
}

bool __stdcall DllMain(HMODULE self, unsigned long reason, void* reserved) {
    if (reason == 1) {
        _self = self;
        CreateThread(0, 0, thr, 0, 0, 0);
    }
    return true;
}