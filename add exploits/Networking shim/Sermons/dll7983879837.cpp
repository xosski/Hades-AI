#include <Windows.h>
#include <iostream>
#include <string>
#include <filesystem>
#include <string_view>

auto main(int argc, char** argv) -> int {
    if (argc != 3) {
        std::cerr << "Usage: <injector> PID DLL\n";
        return EXIT_FAILURE;
    }
    auto process_id = std::stoul(argv[1]);
    auto path = (std::filesystem::current_path() / argv[2]).string();
    auto process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_id);
    auto buffer = VirtualAllocEx(process_handle, nullptr, path.size() + 1, MEM_COMMIT, PAGE_READWRITE);
    WriteProcessMemory(process_handle, buffer, path.data(), path.size() + 1, nullptr);
    auto loadlib_address = reinterpret_cast<LPVOID>(GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA"));
    auto thread = CreateRemoteThread(process_handle, nullptr, 0, static_cast<LPTHREAD_START_ROUTINE>(loadlib_address), buffer, 0, nullptr);
    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);
    VirtualFreeEx(process_handle, buffer, 0, MEM_RELEASE);
    CloseHandle(process_handle);
    std::cout << "injected";
    return EXIT_SUCCESS;
}