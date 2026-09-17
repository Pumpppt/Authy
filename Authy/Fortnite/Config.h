// Config.h - Configuration, Console, and Settings
#pragma once
#include "Authy.h"

namespace Authy {
    namespace Config {
        extern std::wstring BackendW;
        extern std::string  BackendA;
        extern URLMode      Mode;
        extern bool         EnableConsole;
        extern bool         FixMemLeak;
        extern bool         AntiExit;
        extern bool         ManualMapping;

        // Set by config.json; true = use Fortnite redirect, false = check UseUEFNredirect
        extern bool         UseFortniteredirect;
        extern bool         UseUEFNredirect;

        // Game-log passthrough - if true, raw game logs are printed to the Authy console
        extern bool         ShowFortniteLogs;
        extern bool         ShowUEFNLogs;

        void Init();
        void Shutdown();
        void Log(const char* tag, const char* fmt, ...);
        void LogW(const char* tag, const wchar_t* fmt, ...);

        // Game-log helpers - only print when the matching flag is enabled
        void LogFortnite(const char* fmt, ...);
        void LogUEFN(const char* fmt, ...);
    }
}
