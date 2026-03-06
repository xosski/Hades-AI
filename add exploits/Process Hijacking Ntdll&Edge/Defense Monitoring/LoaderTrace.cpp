// LoaderTrace.cpp
// Safe, observational harness: logs loader (DLL) notifications and exceptions in the current process.
// No code injection, no patching, no registry changes.

#define NOMINMAX
#include <windows.h>
#include <dbghelp.h>
#include <psapi.h>
#include <cstdio>
#include <string>
#include <vector>
#pragma comment(lib, "dbghelp.lib")

// Minimal UNICODE_STRING for Ldr notifications
typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

// Notification data structures (documented-by-practice)
typedef struct _LDR_DLL_LOADED_NOTIFICATION_DATA
{
    ULONG Flags;                 // Reserved
    PUNICODE_STRING FullDllName; // e.g., \Device\HarddiskVolume...\ntdll.dll
    PUNICODE_STRING BaseDllName; // e.g., ntdll.dll
    PVOID DllBase;               // Base address
    ULONG SizeOfImage;
} LDR_DLL_LOADED_NOTIFICATION_DATA, *PLDR_DLL_LOADED_NOTIFICATION_DATA;

typedef struct _LDR_DLL_UNLOADED_NOTIFICATION_DATA
{
    ULONG Flags; // Reserved
    PUNICODE_STRING FullDllName;
    PUNICODE_STRING BaseDllName;
    PVOID DllBase;
    ULONG SizeOfImage;
} LDR_DLL_UNLOADED_NOTIFICATION_DATA, *PLDR_DLL_UNLOADED_NOTIFICATION_DATA;

typedef struct _LDR_DLL_NOTIFICATION_DATA
{
    ULONG NotificationReason; // 1 = Loaded, 2 = Unloaded
    union
    {
        LDR_DLL_LOADED_NOTIFICATION_DATA Loaded;
        LDR_DLL_UNLOADED_NOTIFICATION_DATA Unloaded;
    };
} LDR_DLL_NOTIFICATION_DATA, *PLDR_DLL_NOTIFICATION_DATA;

typedef VOID(NTAPI *PLDR_DLL_NOTIFICATION_FUNCTION)(ULONG NotificationReason,
                                                    const LDR_DLL_NOTIFICATION_DATA *NotificationData,
                                                    PVOID Context);

typedef LONG NTSTATUS;
typedef NTSTATUS(NTAPI *pLdrRegisterDllNotification)(ULONG Flags,
                                                     PLDR_DLL_NOTIFICATION_FUNCTION Callback,
                                                     PVOID Context,
                                                     PVOID *Cookie);

typedef NTSTATUS(NTAPI *pLdrUnregisterDllNotification)(PVOID Cookie);

// Utility to print a UNICODE_STRING safely
static const wchar_t *SafeStr(PUNICODE_STRING us)
{
    return (us && us->Buffer) ? us->Buffer : L"(null)";
}

static void PrintModules()
{
    HMODULE hMods[1024];
    DWORD cbNeeded = 0;
    if (EnumProcessModules(GetCurrentProcess(), hMods, sizeof(hMods), &cbNeeded))
    {
        const int count = static_cast<int>(cbNeeded / sizeof(HMODULE));
        wprintf(L"[Modules] Count=%d\n", count);
        for (int i = 0; i < count; ++i)
        {
            wchar_t name[MAX_PATH] = L"";
            if (GetModuleFileNameExW(GetCurrentProcess(), hMods[i], name, MAX_PATH))
            {
                wprintf(L"  - 0x%p %ls\n", hMods[i], name);
            }
        }
    }
    else
    {
        wprintf(L"[Modules] EnumProcessModules failed (err=%lu)\n", GetLastError());
    }
}

// Vectored exception handler: logs exception code and where it occurred
static LONG CALLBACK VehHandler(EXCEPTION_POINTERS *ep)
{
    if (!ep || !ep->ExceptionRecord)
        return EXCEPTION_CONTINUE_SEARCH;
    const DWORD code = ep->ExceptionRecord->ExceptionCode;
    const PVOID addr = ep->ExceptionRecord->ExceptionAddress;
    wprintf(L"[VEH] Exception code=0x%08X at %p\n", code, addr);

    // Optional: capture a small backtrace (best-effort)
    void *frames[32] = {};
    USHORT n = RtlCaptureStackBackTrace(0, 32, frames, nullptr);
    for (USHORT i = 0; i < n; ++i)
    {
        wprintf(L"      #%02u %p\n", i, frames[i]);
    }

    // Let normal SEH proceed
    return EXCEPTION_CONTINUE_SEARCH;
}

// Loader notification callback
static VOID NTAPI LoaderCallback(ULONG reason, const LDR_DLL_NOTIFICATION_DATA *data, PVOID /*ctx*/)
{
    if (!data)
        return;
    switch (reason)
    {
    case 1: // Loaded
        wprintf(L"[Ldr] Loaded:  Base=%p  Size=0x%lx  Name=%ls  Full=%ls\n",
                data->Loaded.DllBase,
                data->Loaded.SizeOfImage,
                SafeStr(data->Loaded.BaseDllName),
                SafeStr(data->Loaded.FullDllName));
        break;
    case 2: // Unloaded
        wprintf(L"[Ldr] Unloaded: Base=%p  Size=0x%lx  Name=%ls  Full=%ls\n",
                data->Unloaded.DllBase,
                data->Unloaded.SizeOfImage,
                SafeStr(data->Unloaded.BaseDllName),
                SafeStr(data->Unloaded.FullDllName));
        break;
    default:
        wprintf(L"[Ldr] Reason=%lu (unknown)\n", reason);
        break;
    }
}

int wmain()
{
    SetConsoleOutputCP(CP_UTF8);
    wprintf(L"== Loader/Exception Analysis Harness ==\n");

    // Install a Vectored Exception Handler (first-chance)
    PVOID veh = AddVectoredExceptionHandler(1 /*call first*/, &VehHandler);
    if (!veh)
    {
        wprintf(L"[Init] AddVectoredExceptionHandler failed (err=%lu)\n", GetLastError());
    }
    else
    {
        wprintf(L"[Init] Vectored Exception Handler registered.\n");
    }

    // Dynamically resolve LdrRegisterDllNotification (no hard linking to ntdll)
    HMODULE hNt = GetModuleHandleW(L"ntdll.dll");
    pLdrRegisterDllNotification LdrRegisterDllNotification =
        reinterpret_cast<pLdrRegisterDllNotification>(
            GetProcAddress(hNt, "LdrRegisterDllNotification"));
    pLdrUnregisterDllNotification LdrUnregisterDllNotification =
        reinterpret_cast<pLdrUnregisterDllNotification>(
            GetProcAddress(hNt, "LdrUnregisterDllNotification"));

    PVOID cookie = nullptr;
    if (LdrRegisterDllNotification && LdrUnregisterDllNotification)
    {
        NTSTATUS st = LdrRegisterDllNotification(0, &LoaderCallback, nullptr, &cookie);
        if (st == 0)
        {
            wprintf(L"[Init] Loader notification registered.\n");
        }
        else
        {
            wprintf(L"[Init] LdrRegisterDllNotification failed (NTSTATUS=0x%08X)\n", st);
        }
    }
    else
    {
        wprintf(L"[Init] LdrRegisterDllNotification unavailable on this platform.\n");
    }

    wprintf(L"\n[Step] Enumerating current modules...\n");
    PrintModules();

    wprintf(L"\n[Step] Triggering benign module loads via LoadLibraryW...\n");
    std::vector<std::wstring> libs = {
        L"user32.dll",
        L"gdi32.dll",
        L"advapi32.dll",
        L"shell32.dll"};
    for (const auto &lib : libs)
    {
        HMODULE h = LoadLibraryW(lib.c_str());
        wprintf(L"  LoadLibrary(%ls) => 0x%p (err=%lu)\n", lib.c_str(), h, GetLastError());
    }

    wprintf(L"\n[Step] Raising a controlled exception (STATUS_ACCESS_VIOLATION: 0xC0000005)...\n");
    __try
    {
        // Use RaiseException to avoid unsafe memory writes
        RaiseException(0xC0000005 /*STATUS_ACCESS_VIOLATION*/, 0, 0, nullptr);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        wprintf(L"[SEH] Caught exception in local handler. Code=0x%08X\n", GetExceptionCode());
    }

    wprintf(L"\n[Step] Raising a second-chance exception to observe VEH (custom code 0xE0000001)...\n");
    // No SEH handler: expect VEH log then default handler termination (we'll catch to continue)
    __try
    {
        RaiseException(0xE0000001, 0, 0, nullptr);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        wprintf(L"[SEH] Custom exception observed and handled.\n");
    }

    // Cleanup loader notification if registered
    if (cookie && LdrUnregisterDllNotification)
    {
        LdrUnregisterDllNotification(cookie);
        wprintf(L"[Exit] Loader notification unregistered.\n");
    }

    if (veh)
    {
        RemoveVectoredExceptionHandler(veh);
        wprintf(L"[Exit] Vectored Exception Handler removed.\n");
    }

    wprintf(L"\nDone.\n");
    return 0;
}