#define DEBUG

#if !defined(DEBUG)

#include <iostream>
#include <windows.h>

int main() {
	POINT cursorPos;

	while (true) {
		// Получаем текущие координаты курсора
		if (GetCursorPos(&cursorPos)) {
			std::cout << "Координаты мыши: X = " << cursorPos.x << ", Y = " << cursorPos.y << std::endl;
		}
		else {
			std::cerr << "Не удалось получить координаты мыши." << std::endl;
		}

		// Задержка на 1 секунду
		Sleep(1000);
	}

	return 0;
}

#endif





#if defined(DEBUG)

#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <windows.h>
#include <tlhelp32.h>

#define X_PAST_PASSWORD     437
#define Y_PAST_PASSWORD     429

#define X_LOG_IN            598
#define Y_LOG_IN            521

#define X_SETCUR_LIBRARY    329
#define Y_SETCUR_LIBRARY    83

#define X_LIBRARY           336
#define Y_LIBRARY           125

#define X_SELECT_DOTA       180
#define Y_SELECT_DOTA       389

#define X_START_DOTA        471
#define Y_START_DOTA        468

#define X_CHOISE_VHS        616
#define Y_CHOISE_VHS        490

#define X_TAKE_REWARDS      827
#define Y_TAKE_REWARDS      681

#define X_ICO               241
#define Y_ICO               30

#define X_BUTTON_PLAY       1257
#define Y_BUTTON_PLAY       859

#define X_DEFUALT_GAME      1229
#define Y_DEFUALT_GAME      484

#define X_PICK_ALLPICK      1134
#define Y_PICK_ALLPICK      613

#define X_CANCEL_GAME       1379
#define Y_CANCEL_GAME       859

#define X_SETTINGS          66
#define Y_SETTINGS          25

#define X_SETTINGS_ACC      896
#define Y_SETTINGS_ACC      85

#define X_START_CALIBRATION 211
#define Y_START_CALIBRATION 271

#define X_END_CALIBRATION   719
#define Y_END_CALIBRATION   616

#define X_END1_CALIBRATION  721
#define Y_END1_CALIBRATION  485

#define X_SETCUR_PROFILE    1191
#define Y_SETCUR_PROFILE    58

#define X_EXIT_PROFILE      1216
#define Y_EXIT_PROFILE      249

#define X_CONFIRM_EXIT      835
#define Y_CONFIRM_EXIT      516

#define KEYEVENTF_KEYDOWN   0x0000
#define KEYEVENTF_KEYUP     0x0002

void SendKeysViaClipboard(const std::string& text) {
	// Открыть буфер обмена
	if (OpenClipboard(NULL)) {
		// Очистить буфер обмена
		EmptyClipboard();

		// Создать строку, которую хотим вставить в буфер обмена
		HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, text.size() + 1);
		if (hMem) {
			// Копируем строку в буфер обмена
			memcpy(GlobalLock(hMem), text.c_str(), text.size() + 1);
			GlobalUnlock(hMem);

			// Помещаем строку в буфер обмена
			SetClipboardData(CF_TEXT, hMem);

			// Закрыть буфер обмена
			CloseClipboard();

			// Эмулируем нажатие Ctrl+V (вставка из буфера обмена)
			keybd_event(0x11, 0, KEYEVENTF_KEYDOWN, 0);  // Нажимаем Ctrl (0x11 - виртуальный код для Ctrl)
			keybd_event(0x56, 0, KEYEVENTF_KEYDOWN, 0);  // Нажимаем V (0x56 - виртуальный код для V)
			keybd_event(0x56, 0, KEYEVENTF_KEYUP, 0);    // Отпускаем V
			keybd_event(0x11, 0, KEYEVENTF_KEYUP, 0);    // Отпускаем Ctrl
		}
	}
}

bool TerminateProcessByName(const std::wstring& processName) {
	// Снимем список всех процессов
	PROCESSENTRY32 pe32;
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE) {
		std::cerr << "Failed to create snapshot of processes" << std::endl;
		return false;
	}

	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(hProcessSnap, &pe32)) {
		std::cerr << "Failed to get the first process" << std::endl;
		CloseHandle(hProcessSnap);
		return false;
	}

	// Перебираем все процессы и ищем нужный
	do {
		if (processName == pe32.szExeFile) {  // Если имя процесса совпадает с Dota 2
			HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pe32.th32ProcessID);
			if (hProcess == NULL) {
				std::cerr << "Failed to open process for termination" << std::endl;
				CloseHandle(hProcessSnap);
				return false;
			}

			// Завершаем процесс
			if (TerminateProcess(hProcess, 0)) {
				std::cout << "Successfully terminated Dota 2!" << std::endl;
				CloseHandle(hProcess);
				CloseHandle(hProcessSnap);
				return true;
			}
			else {
				std::cerr << "Failed to terminate process" << std::endl;
				CloseHandle(hProcess);
				CloseHandle(hProcessSnap);
				return false;
			}
		}
	} while (Process32Next(hProcessSnap, &pe32));

	std::cerr << "Dota 2 not found!" << std::endl;
	CloseHandle(hProcessSnap);
	return false;
}

void SetCursor(int x, int y) {
	SetCursorPos(x, y);
	Sleep(5000);
	mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
	Sleep(50);
	mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);
}

int main() {
	std::ios::sync_with_stdio(false);
	std::cin.tie(nullptr);

	std::ifstream file("data.txt");
	
	if (!file.is_open()) {
		std::cerr << "Open file error!"; return 1;
	}



	std::string line;

	while (std::getline(file, line)) {
		std::istringstream stream(line);
		std::string login, password;
		
		std::getline(stream, login, ':');
		std::getline(stream, password, ':');

		STARTUPINFO si = { sizeof(STARTUPINFO) };
		PROCESS_INFORMATION pi;

		if (!CreateProcess(
			L"E:\\Steam\\Steam.exe",
			NULL,
			NULL,
			NULL,
			FALSE,
			0,
			NULL,
			NULL,
			&si,
			&pi
		)) {
			std::cerr << "Failed to start Steam!";
			return 1;
		}
		std::clog << "Steam started!" << std::endl;
		Sleep(20000);

		SendKeysViaClipboard(login);
		Sleep(1500);

		SetCursor(X_PAST_PASSWORD, Y_PAST_PASSWORD);

		SendKeysViaClipboard(password);
		Sleep(1500);

		SetCursor(X_LOG_IN, Y_LOG_IN);
		Sleep(10000);

		SetCursorPos(X_SETCUR_LIBRARY, Y_SETCUR_LIBRARY);
		Sleep(1500);

		SetCursor(X_LIBRARY, Y_LIBRARY);
		Sleep(1500);

		SetCursor(X_SELECT_DOTA, Y_SELECT_DOTA);
		Sleep(1500);

		SetCursor(X_START_DOTA, Y_START_DOTA);

		std::clog << "Dota 2 started!" << std::endl;
		Sleep(180000);

		SetCursor(X_CHOISE_VHS, Y_CHOISE_VHS);
		Sleep(1500);

		SetCursor(X_TAKE_REWARDS, Y_TAKE_REWARDS);
		Sleep(1500);

		SetCursor(X_ICO, Y_ICO);
		Sleep(1500);

		SetCursor(X_BUTTON_PLAY, Y_BUTTON_PLAY);
		Sleep(1500);

		SetCursor(X_DEFUALT_GAME, Y_DEFUALT_GAME);
		Sleep(1500);

		SetCursor(X_PICK_ALLPICK, Y_PICK_ALLPICK);
		Sleep(1500);

		SetCursor(X_DEFUALT_GAME, Y_DEFUALT_GAME);
		Sleep(1500);

		SetCursor(X_CANCEL_GAME, Y_CANCEL_GAME);
		Sleep(1500);

		SetCursor(X_SETTINGS, Y_SETTINGS);
		Sleep(1500);

		SetCursor(X_SETTINGS_ACC, Y_SETTINGS_ACC);
		Sleep(1500);

		SetCursor(X_START_CALIBRATION, Y_START_CALIBRATION);
		Sleep(1500);

		SetCursor(X_END_CALIBRATION, Y_END_CALIBRATION);
		Sleep(1500);

		SetCursor(X_END1_CALIBRATION, Y_END1_CALIBRATION);
		Sleep(1500);

		if (!TerminateProcessByName(L"dota2.exe")) {
			std::cerr << "Dota 2 do not exit!" << std::endl; return 1;
		}
		std::clog << "Dota 2 exit!" << std::endl;

		SetCursor(X_SETCUR_PROFILE, Y_SETCUR_PROFILE);
		Sleep(1500);

		SetCursor(X_EXIT_PROFILE, Y_EXIT_PROFILE);
		Sleep(1500);

		SetCursor(X_CONFIRM_EXIT, Y_CONFIRM_EXIT);
		Sleep(60000);

		if (!TerminateProcessByName(L"steam.exe")) {
			std::cerr << "Steam do not exit!" << std::endl; return 1;
		}
		std::clog << "Steam exit!" << std::endl;
	}

	file.close();
	return 0;
}

#endif