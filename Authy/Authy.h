// Authy.h - Master Header and Common Types
#pragma once

#undef UNICODE
#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN

#include <winsock2.h>
#include <ws2tcpip.h>
#include <Windows.h>
#include <string>
#include <string_view>
#include <vector>
#include <array>
#include <algorithm>
#include <stdio.h>
#include <psapi.h>
#include <winternl.h>
#include <DbgHelp.h>

#include "MinHook.h"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "minhook.lib")

namespace Authy {
    enum class URLMode {
        Default, // Standard private server redirection
        Hybrid,  // Profile, version check, content pages only
        Dev,     // Profile & content pages only
        All      // Redirect every request
    };

    namespace Globals {
        extern void* MainImageBase;
        extern void* EOSModuleBase;

        extern void* MainTextBuf;
        extern size_t MainTextSize;
        extern void* MainRDataBuf;
        extern size_t MainRDataSize;

        extern void* EOSTextBuf;
        extern size_t EOSTextSize;
        extern void* EOSRDataBuf;
        extern size_t EOSRDataSize;
    }
}
