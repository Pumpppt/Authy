// DllMain.cpp - Entry Point and Initialization
#include "pch.h"
#include "Config.h"
#include "Hooks.h"
#include "Patches.h"

namespace Authy {
    static DWORD WINAPI MainThread(LPVOID) {
        // 1. Initialize Configuration, Image/Sections, Console & Version Detection
        //    (reads config.json from DLL directory)
        Config::Init();

        // Only proceed if a redirect mode is actually enabled
        if (!Config::UseFortniteredirect && !Config::UseUEFNredirect) {
            Config::Log("Authy", "No redirect enabled in config.json - standing by.\n");
            return 0;
        }

        // 2. Install Anti-Crash, Anti-Exit, and Signature Patches
        if (Config::AntiExit) {
            Patches::Install();
        }

        // 3. Install Universal & 32.11 Hooks (Engine, EOS, Libcurl)
        Hooks::Install();

        return 0;
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        if (Authy::Config::ManualMapping) {
            Authy::MainThread(nullptr);
        } else {
            CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)Authy::MainThread, nullptr, 0, nullptr);
        }
        break;
    case DLL_PROCESS_DETACH:
        Authy::Hooks::Remove();
        Authy::Config::Shutdown();
        break;
    }
    return TRUE;
}
