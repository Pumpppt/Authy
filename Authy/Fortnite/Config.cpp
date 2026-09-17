// Config.cpp - Configuration, Console, and Settings
#include "pch.h"
#include "Config.h"
#include <stdarg.h>

// ============================================================================
// Minimal JSON helpers - no external dependencies
// ============================================================================
namespace {
    static std::string JsonGetRaw(const std::string& json, const std::string& key) {
        std::string needle = "\"" + key + "\"";
        auto kpos = json.find(needle);
        if (kpos == std::string::npos) return "";
        auto colon = json.find(':', kpos + needle.size());
        if (colon == std::string::npos) return "";
        auto vstart = colon + 1;
        while (vstart < json.size() && (json[vstart] == ' ' || json[vstart] == '\t' ||
               json[vstart] == '\r' || json[vstart] == '\n')) ++vstart;
        if (vstart >= json.size()) return "";

        if (json[vstart] == '"') {
            auto vend = json.find('"', vstart + 1);
            if (vend == std::string::npos) return "";
            return json.substr(vstart + 1, vend - vstart - 1);
        } else {
            auto vend = vstart;
            while (vend < json.size() && json[vend] != ',' && json[vend] != '}' &&
                   json[vend] != ']' && json[vend] != '\r' && json[vend] != '\n') ++vend;
            std::string raw = json.substr(vstart, vend - vstart);
            while (!raw.empty() && (raw.back() == ' ' || raw.back() == '\t')) raw.pop_back();
            return raw;
        }
    }

    static bool JsonGetBool(const std::string& json, const std::string& key, bool fallback) {
        auto raw = JsonGetRaw(json, key);
        if (raw == "true")  return true;
        if (raw == "false") return false;
        return fallback;
    }

    static std::string JsonGetString(const std::string& json, const std::string& key,
                                     const std::string& fallback) {
        auto raw = JsonGetRaw(json, key);
        return raw.empty() ? fallback : raw;
    }

    static std::string ReadFileText(const wchar_t* path) {
        HANDLE hFile = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ,
                                   nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) return "";
        DWORD size = GetFileSize(hFile, nullptr);
        if (size == INVALID_FILE_SIZE || size == 0) { CloseHandle(hFile); return ""; }
        std::string buf(size, '\0');
        DWORD read = 0;
        ReadFile(hFile, buf.data(), size, &read, nullptr);
        CloseHandle(hFile);
        buf.resize(read);
        return buf;
    }

    // Returns the directory where this DLL lives (no trailing slash).
    static std::wstring GetDllDir() {
        wchar_t path[MAX_PATH] = {};
        HMODULE hSelf = nullptr;
        GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                           GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           (LPCWSTR)&GetDllDir, &hSelf);
        GetModuleFileNameW(hSelf, path, MAX_PATH);
        wchar_t* last = wcsrchr(path, L'\\');
        if (last) *last = L'\0';
        return path;
    }
}

namespace Authy {
    namespace Globals {
        void* MainImageBase = nullptr;
        void* EOSModuleBase = nullptr;

        void* MainTextBuf = nullptr;
        size_t MainTextSize = 0;
        void* MainRDataBuf = nullptr;
        size_t MainRDataSize = 0;

        void* EOSTextBuf = nullptr;
        size_t EOSTextSize = 0;
        void* EOSRDataBuf = nullptr;
        size_t EOSRDataSize = 0;
    }

    namespace PE {
        IMAGE_SECTION_HEADER* GetSection(uint64_t imageBase, const char* name) {
            if (!imageBase) return nullptr;
            auto dos = (IMAGE_DOS_HEADER*)imageBase;
            if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
            auto nt = (IMAGE_NT_HEADERS64*)(imageBase + dos->e_lfanew);
            if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;
            auto section = IMAGE_FIRST_SECTION(nt);
            for (uint16_t i = 0; i < nt->FileHeader.NumberOfSections; i++) {
                if (strncmp((const char*)section[i].Name, name, 8) == 0)
                    return &section[i];
            }
            return nullptr;
        }
    }

    namespace Config {
        std::wstring BackendW = L"http://127.0.0.1:5595";
        std::string  BackendA = "http://127.0.0.1:5595";
        URLMode      Mode = URLMode::Default;
        bool         EnableConsole = true;
        bool         FixMemLeak = true;
        bool         AntiExit = true;
        bool         ManualMapping = false;

        bool         UseFortniteredirect = true;
        bool         UseUEFNredirect = false;

        bool         ShowFortniteLogs = true;
        bool         ShowUEFNLogs = false;

        static FILE* g_ConsoleFile = nullptr;

        static void PrintBanner() {
            SetConsoleTitleA("Authy");
            printf("\n"
                   "    ___         __  __            \n"
                   "   /   | __  __/ /_/ /_  __  __   \n"
                   "  / /| |/ / / / __/ __ \\/ / / /   \n"
                   " / ___ / /_/ / /_/ / / / /_/ /    \n"
                   "/_/  |_\\__,_/\\__/_/ /_/\\__, /     \n"
                   "                      /____/      \n\n");

            const char* modeStr = "Default";
            if      (Mode == URLMode::Hybrid) modeStr = "Hybrid";
            else if (Mode == URLMode::Dev)    modeStr = "Dev";
            else if (Mode == URLMode::All)    modeStr = "All";

            printf("[Authy] Target Backend  : %ls\n",  BackendW.c_str());
            printf("[Authy] URL Mode        : %s\n",   modeStr);
            printf("[Authy] Redirect Mode   : %s\n",
                   UseFortniteredirect ? "Fortnite" : (UseUEFNredirect ? "UEFN" : "None"));
            printf("[Authy] Fortnite Logs   : %s\n",   ShowFortniteLogs ? "ON" : "OFF");
            printf("[Authy] UEFN Logs       : %s\n\n", ShowUEFNLogs     ? "ON" : "OFF");
        }

        static void LoadJson() {
            std::wstring dir = GetDllDir();
            std::wstring cfgPath = dir + L"\\config.json";

            std::string json = ReadFileText(cfgPath.c_str());
            if (json.empty())
                json = ReadFileText(L".\\config.json");
            if (json.empty()) return; // keep compiled defaults

            // --- Fortnite block ---
            UseFortniteredirect = JsonGetBool(json, "bUseFortniteredirect", true);
            ShowFortniteLogs    = JsonGetBool(json, "bShowFortniteLogs",    ShowFortniteLogs);

            // --- UEFN block ---
            UseUEFNredirect = JsonGetBool(json, "bUseUEFNredirect", false);
            ShowUEFNLogs    = JsonGetBool(json, "bShowUEFNLogs",    ShowUEFNLogs);

            // --- Backend URL ---
            std::string backendUrl = JsonGetString(json, "BackendURL", "http://127.0.0.1:5595");
            if (!backendUrl.empty()) {
                int wlen = MultiByteToWideChar(CP_UTF8, 0, backendUrl.c_str(), -1, nullptr, 0);
                if (wlen > 0) {
                    BackendW.resize(wlen - 1);
                    MultiByteToWideChar(CP_UTF8, 0, backendUrl.c_str(), -1, &BackendW[0], wlen);
                }
                BackendA = backendUrl;
            }

            // --- Settings block ---
            EnableConsole = JsonGetBool(json,   "EnableConsole", EnableConsole);
            FixMemLeak    = JsonGetBool(json,   "FixMemLeak",    FixMemLeak);
            AntiExit      = JsonGetBool(json,   "AntiExit",      AntiExit);
            ManualMapping = JsonGetBool(json,   "ManualMapping", ManualMapping);

            std::string urlMode = JsonGetString(json, "URLMode", "");
            if      (urlMode == "Hybrid")  Mode = URLMode::Hybrid;
            else if (urlMode == "Dev")     Mode = URLMode::Dev;
            else if (urlMode == "All")     Mode = URLMode::All;
            else if (urlMode == "Default") Mode = URLMode::Default;
        }

        void Init() {
            // 1. Resolve image bases & section buffers
            Globals::MainImageBase = *(void**)(__readgsqword(0x60) + 0x10);
            Globals::EOSModuleBase = GetModuleHandleA("EOSSDK-Win64-Shipping");
            if (!Globals::EOSModuleBase) Globals::EOSModuleBase = LoadLibraryA("EOSSDK-Win64-Shipping");

            if (Globals::MainImageBase) {
                auto textSec  = PE::GetSection((uint64_t)Globals::MainImageBase, ".text");
                auto rdataSec = PE::GetSection((uint64_t)Globals::MainImageBase, ".rdata");
                if (textSec) {
                    Globals::MainTextBuf  = (void*)((uint64_t)Globals::MainImageBase + textSec->VirtualAddress);
                    Globals::MainTextSize = textSec->Misc.VirtualSize;
                }
                if (rdataSec) {
                    Globals::MainRDataBuf  = (void*)((uint64_t)Globals::MainImageBase + rdataSec->VirtualAddress);
                    Globals::MainRDataSize = rdataSec->Misc.VirtualSize;
                }
            }

            if (Globals::EOSModuleBase) {
                auto textSec  = PE::GetSection((uint64_t)Globals::EOSModuleBase, ".text");
                auto rdataSec = PE::GetSection((uint64_t)Globals::EOSModuleBase, ".rdata");
                if (textSec) {
                    Globals::EOSTextBuf  = (void*)((uint64_t)Globals::EOSModuleBase + textSec->VirtualAddress);
                    Globals::EOSTextSize = textSec->Misc.VirtualSize;
                }
                if (rdataSec) {
                    Globals::EOSRDataBuf  = (void*)((uint64_t)Globals::EOSModuleBase + rdataSec->VirtualAddress);
                    Globals::EOSRDataSize = rdataSec->Misc.VirtualSize;
                }
            }

            // 2. Load all settings from config.json (next to the DLL)
            LoadJson();

            // 3. Open Console if requested
            if (EnableConsole) {
                AllocConsole();
                freopen_s(&g_ConsoleFile, "CONOUT$", "w+", stdout);
                freopen_s(&g_ConsoleFile, "CONOUT$", "w+", stderr);
                PrintBanner();
            }
        }

        void Shutdown() {
            if (g_ConsoleFile) {
                fclose(g_ConsoleFile);
                g_ConsoleFile = nullptr;
            }
            FreeConsole();
        }

        void Log(const char* tag, const char* fmt, ...) {
            if (!EnableConsole) return;
            printf("[%s] ", tag);
            va_list args;
            va_start(args, fmt);
            vprintf(fmt, args);
            va_end(args);
            fflush(stdout);
        }

        void LogW(const char* tag, const wchar_t* fmt, ...) {
            if (!EnableConsole) return;
            wprintf(L"[%hs] ", tag);
            va_list args;
            va_start(args, fmt);
            vwprintf(fmt, args);
            va_end(args);
            fflush(stdout);
        }

        // Only prints when bShowFortniteLogs is true in config.json
        void LogFortnite(const char* fmt, ...) {
            if (!EnableConsole || !ShowFortniteLogs) return;
            printf("[Fortnite] ");
            va_list args;
            va_start(args, fmt);
            vprintf(fmt, args);
            va_end(args);
        }

        // Only prints when bShowUEFNLogs is true in config.json
        void LogUEFN(const char* fmt, ...) {
            if (!EnableConsole || !ShowUEFNLogs) return;
            printf("[UEFN] ");
            va_list args;
            va_start(args, fmt);
            vprintf(fmt, args);
            va_end(args);
        }
    }
}
