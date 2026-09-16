// Config.cpp - Configuration, Console, and Settings
#include "pch.h"
#include "Config.h"
#include <stdarg.h>

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

        static FILE* g_ConsoleFile = nullptr;

        static void PrintBanner() {
            SetConsoleTitleA("Authy - Universal Fortnite Redirect");
            printf("\n"
                   "    ___         __  __            \n"
                   "   /   | __  __/ /_/ /_  __  __   \n"
                   "  / /| |/ / / / __/ __ \\/ / / /   \n"
                   " / ___ / /_/ / /_/ / / / /_/ /    \n"
                   "/_/  |_\\__,_/\\__/_/ /_/\\__, /     \n"
                   "                      /____/      \n\n");

            printf("[Authy] Target Backend: %ls\n\n", BackendW.c_str());
        }

        void Init() {
            // 1. Resolve image bases & section buffers using standard Windows PE headers
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

            // 2. Parse command line for -backend=
            const wchar_t* cmd = GetCommandLineW();
            if (cmd) {
                const wchar_t* pos = wcsstr(cmd, L"-backend=");
                if (pos) {
                    pos += 9;
                    const wchar_t* end = wcschr(pos, L' ');
                    if (end) BackendW = std::wstring(pos, end - pos);
                    else BackendW = std::wstring(pos);
                } else {
                    // Fallback to authy.ini
                    wchar_t iniBuf[256] = { 0 };
                    GetPrivateProfileStringW(L"Authy", L"Backend", L"http://127.0.0.1:5595", iniBuf, 256, L".\\authy.ini");
                    if (iniBuf[0] != L'\0') BackendW = iniBuf;
                }
            }

            // Sync narrow backend string
            char backendBuf[256] = { 0 };
            WideCharToMultiByte(CP_UTF8, 0, BackendW.c_str(), -1, backendBuf, sizeof(backendBuf), nullptr, nullptr);
            BackendA = backendBuf;

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
        }

        void LogW(const char* tag, const wchar_t* fmt, ...) {
            if (!EnableConsole) return;
            wprintf(L"[%hs] ", tag);
            va_list args;
            va_start(args, fmt);
            vwprintf(fmt, args);
            va_end(args);
        }
    }
}
