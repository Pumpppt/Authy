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

        void Init();
        void Shutdown();
        void Log(const char* tag, const char* fmt, ...);
        void LogW(const char* tag, const wchar_t* fmt, ...);
    }
}
