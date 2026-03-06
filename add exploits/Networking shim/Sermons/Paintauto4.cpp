#include <Windows.h>
#include <vector>
#include <string>
#include <TlHelp32.h>
#include <iostream>
#include <sddl.h>

bool IspaintRunning()
{
    bool isRunning = false;
    PROCESSENTRY32 processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return false;

    if (Process32First(snapshot, &processEntry)) {
        do {
            if (_wcsicmp(processEntry.szExeFile, L"mspaint.exe") == 0) {
                isRunning = true;
                break;
            }
        } while (Process32Next(snapshot, &processEntry));
    }

    CloseHandle(snapshot);
    return isRunning;
}

std::vector<int> Get_PixelColor(int X, int Y) noexcept
{
    static HDC Screen_HDC = GetWindowDC(NULL);
    const COLORREF Pixel = GetPixel(Screen_HDC, X, Y);
    return { GetGValue(Pixel), GetRValue(Pixel), GetBValue(Pixel) };
}

void CleanTraces() noexcept
{

    HANDLE hToken;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        DWORD dwSize = 0;
        GetTokenInformation(hToken, TokenUser, nullptr, 0, &dwSize);
        PTOKEN_USER pTokenUser = (PTOKEN_USER)malloc(dwSize);
        if (GetTokenInformation(hToken, TokenUser, pTokenUser, dwSize, &dwSize)) {
            LPWSTR sidString;
            if (ConvertSidToStringSid(pTokenUser->User.Sid, &sidString)) {

                // Define registry paths
                std::wstring baseKey = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage\\AppSwitched\\Project2.exe";
                std::wstring appCompatKey = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Compatibility Assistant\\Store\\Project2.exe";
                std::wstring userSettingsKey = L"SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings\\" + std::wstring(sidString) + L"\\Project2.exe";

                // Attempt to delete each registry key
                RegDeleteTree(HKEY_CURRENT_USER, baseKey.c_str());
                RegDeleteTree(HKEY_CURRENT_USER, appCompatKey.c_str());
                RegDeleteTree(HKEY_LOCAL_MACHINE, userSettingsKey.c_str());

                LocalFree(sidString);


                std::wstring prefetchPath = L"C:\\Windows\\Prefetch\\Project2*.pf";
                std::wstring command = L"del /f /q \"" + prefetchPath + L"\" > nul";
                _wsystem(command.c_str());

                LocalFree(sidString);
            }
        }
        free(pTokenUser);
        CloseHandle(hToken);
    }
}

int main() noexcept
{
    HWND consoleWindow = GetConsoleWindow();
    ShowWindow(consoleWindow, SW_HIDE);

    system("start mspaint");

    while (true)
    {
        if (!IspaintRunning()) {
            CleanTraces();
            ExitProcess(0);
            const std::vector<int> ScreenResolution = { GetSystemMetrics(SM_CXSCREEN) ,GetSystemMetrics(SM_CYSCREEN) };
            const auto New_PixelColor = Get_PixelColor(ScreenResolution[0] / 2 + 1, ScreenResolution[1] / 2 + 1);
            static auto Old_PixelColor = New_PixelColor;
            if (GetAsyncKeyState(VK_XBUTTON2) & 0x8000)
            {
                const auto ColorGap = 4;
                if (abs(New_PixelColor[0] - Old_PixelColor[0]) >= ColorGap || abs(New_PixelColor[1] - Old_PixelColor[1]) >= ColorGap || abs(New_PixelColor[2] - Old_PixelColor[2]) >= ColorGap)
                {
                    mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 1, 0, 0);
                    Sleep(1);
                    mouse_event(MOUSEEVENTF_LEFTUP, 0, 2, 0, 0);
                    Old_PixelColor = New_PixelColor;
                }
            }
            else Old_PixelColor = New_PixelColor;
            Sleep(1);
            Beep(100, 50);
        }
    }
}