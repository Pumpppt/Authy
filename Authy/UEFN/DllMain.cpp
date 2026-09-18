// DllMain.cpp - UEFN Entry, Libcurl, EOS & ProcessRequest Interception
#include "pch.h"
#include "UEFN.h"
#include "Config.h"
#include "MinHook.h"
#include "Redirection.h"
#include <string>
#include <string_view>
#include <vector>
#include <sstream>
#include <algorithm>
#include <psapi.h>
#include <shlobj.h>
#include <emmintrin.h>

namespace Authy {
    namespace UEFN {
        // ============================================================================
        // Forward Declarations & Types
        // ============================================================================
        typedef int (*PFN_curl_easy_setopt)(void* handle, int option, ...);

        static PFN_curl_easy_setopt g_Original_EngineCurl = nullptr;
        static PFN_curl_easy_setopt g_Original_EOSCurl    = nullptr;

        static bool (*g_ProcessRequestOG)(void* Request)    = nullptr;
        static bool (*g_EOSProcessRequestOG)(void* Request) = nullptr;

        static uint32_t g_URLFieldOffset   = 0;
        static bool     g_EngineCurlHooked = false;
        static bool     g_EOSCurlHooked    = false;
        static bool     g_ProcessReqHooked = false;
        static bool     g_ExitHooked       = false;
        static bool     g_MemLeakFixed     = false;

        static void ReturnNone() {}

        // ============================================================================
        // Memory & Pattern Scanning Helpers
        // ============================================================================
        static bool IsReadableMemory(const void* p, size_t len = 8) {
            if (!p || reinterpret_cast<uintptr_t>(p) < 0x10000) return false;
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQuery(p, &mbi, sizeof(mbi))) return false;
            constexpr DWORD readable = PAGE_READONLY | PAGE_READWRITE |
                                       PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                                       PAGE_EXECUTE_WRITECOPY | PAGE_WRITECOPY;
            return (mbi.Protect & readable) && !(mbi.Protect & PAGE_GUARD) && mbi.RegionSize >= len;
        }

        static uintptr_t SigScan(HMODULE hModule, const char* signature) {
            if (!hModule) return 0;

            MODULEINFO modInfo{};
            if (!GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(modInfo)))
                return 0;

            uint8_t* base = reinterpret_cast<uint8_t*>(modInfo.lpBaseOfDll);
            size_t size   = modInfo.SizeOfImage;

            std::vector<int> bytes;
            const char* current = signature;
            while (*current) {
                while (*current == ' ') current++;
                if (!*current) break;

                if (*current == '?') {
                    bytes.push_back(-1);
                    current++;
                    if (*current == '?') current++;
                } else {
                    bytes.push_back(static_cast<int>(strtoul(current, const_cast<char**>(&current), 16)));
                }
            }

            if (bytes.empty() || size < bytes.size()) return 0;

            size_t patternLen = bytes.size();
            for (size_t i = 0; i <= size - patternLen; ++i) {
                bool match = true;
                for (size_t j = 0; j < patternLen; ++j) {
                    if (bytes[j] != -1 && base[i + j] != static_cast<uint8_t>(bytes[j])) {
                        match = false;
                        break;
                    }
                }
                if (match) {
                    return reinterpret_cast<uintptr_t>(base + i);
                }
            }

            return 0;
        }

        static uintptr_t ScanModuleSignatures(HMODULE hModule, const std::vector<const char*>& signatures) {
            if (!hModule) return 0;
            for (const auto& sig : signatures) {
                uintptr_t addr = SigScan(hModule, sig);
                if (addr) return addr;
            }
            return 0;
        }

        // ============================================================================
        // Auto-Configuration: bEnableCURLInEditor for UEFN & Projects
        // ============================================================================
        static void SetIniKey(const std::wstring& filePath, const wchar_t* section, const wchar_t* key, const wchar_t* value) {
            if (filePath.empty()) return;

            size_t slashPos = filePath.find_last_of(L"\\/");
            if (slashPos != std::wstring::npos) {
                std::wstring dir = filePath.substr(0, slashPos);
                CreateDirectoryW(dir.c_str(), nullptr);
            }

            WritePrivateProfileStringW(section, key, value, filePath.c_str());
        }

        static void AutoEnableCurlInIniFiles() {
            wchar_t localAppData[MAX_PATH] = {};
            if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, localAppData))) {
                std::wstring uefnConfigDir = std::wstring(localAppData) + L"\\UnrealEditorFortnite\\Saved\\Config";
                SetIniKey(uefnConfigDir + L"\\WindowsEditor\\Engine.ini", L"HTTP", L"bEnableCURLInEditor", L"True");
                SetIniKey(uefnConfigDir + L"\\WindowsEditor\\Engine.ini", L"HTTP.Curl", L"bEnableCURLInEditor", L"True");

                SetIniKey(uefnConfigDir + L"\\Windows\\Engine.ini", L"HTTP", L"bEnableCURLInEditor", L"True");
                SetIniKey(uefnConfigDir + L"\\Windows\\Engine.ini", L"HTTP.Curl", L"bEnableCURLInEditor", L"True");
            }

            wchar_t currentDir[MAX_PATH] = {};
            GetCurrentDirectoryW(MAX_PATH, currentDir);
            std::wstring localEngineIni = std::wstring(currentDir) + L"\\Config\\DefaultEngine.ini";
            SetIniKey(localEngineIni, L"HTTP", L"bEnableCURLInEditor", L"True");
            SetIniKey(localEngineIni, L"HTTP.Curl", L"bEnableCURLInEditor", L"True");

            LPWSTR cmdLine = GetCommandLineW();
            if (cmdLine) {
                std::wstring cmd(cmdLine);
                size_t projPos = cmd.find(L".uproject");
                if (projPos != std::wstring::npos) {
                    size_t startQuote = cmd.rfind(L"\"", projPos);
                    size_t startSpace = cmd.rfind(L" ", projPos);
                    size_t start = (startQuote != std::wstring::npos) ? (startQuote + 1) :
                                   ((startSpace != std::wstring::npos) ? (startSpace + 1) : 0);
                    std::wstring uprojectPath = cmd.substr(start, projPos + 9 - start);
                    size_t lastSlash = uprojectPath.find_last_of(L"\\/");
                    if (lastSlash != std::wstring::npos) {
                        std::wstring projDir = uprojectPath.substr(0, lastSlash);
                        std::wstring projEngineIni = projDir + L"\\Config\\DefaultEngine.ini";
                        SetIniKey(projEngineIni, L"HTTP", L"bEnableCURLInEditor", L"True");
                        SetIniKey(projEngineIni, L"HTTP.Curl", L"bEnableCURLInEditor", L"True");
                    }
                }
            }

            Config::Log("UEFN", "Auto-configured bEnableCURLInEditor=True in project and editor INI files.\n");
        }

        // ============================================================================
        // URL Parser & Builder (Fiddler-Style PathAndQuery Extraction)
        // ============================================================================
        struct ParsedUri {
            std::string Protocol;
            std::string Host;
            std::string Port;
            std::string Path;
            std::string Query;

            static ParsedUri Parse(std::string_view url) {
                ParsedUri result;
                if (url.empty()) return result;

                size_t protoEnd = url.find("://");
                size_t hostStart = 0;
                if (protoEnd != std::string_view::npos) {
                    result.Protocol = std::string(url.substr(0, protoEnd));
                    hostStart = protoEnd + 3;
                }

                size_t pathStart = url.find('/', hostStart);
                size_t queryStart = url.find('?', hostStart);

                size_t hostEnd = (pathStart != std::string_view::npos) ? pathStart :
                                 (queryStart != std::string_view::npos ? queryStart : url.size());

                std::string_view hostPort = url.substr(hostStart, hostEnd - hostStart);
                size_t colonPos = hostPort.find(':');
                if (colonPos != std::string_view::npos) {
                    result.Host = std::string(hostPort.substr(0, colonPos));
                    result.Port = std::string(hostPort.substr(colonPos + 1));
                } else {
                    result.Host = std::string(hostPort);
                }

                if (pathStart != std::string_view::npos) {
                    if (queryStart != std::string_view::npos && queryStart > pathStart) {
                        result.Path = std::string(url.substr(pathStart, queryStart - pathStart));
                    } else {
                        result.Path = std::string(url.substr(pathStart));
                    }
                }

                if (queryStart != std::string_view::npos) {
                    result.Query = std::string(url.substr(queryStart));
                }

                return result;
            }
        };

        static bool Contains(const std::string& str, const std::string& substr) {
            return str.find(substr) != std::string::npos;
        }

        static bool ShouldRedirectHost(const std::string& host) {
            // Never redirect localhost or local backend
            if (Contains(host, "127.0.0.1") || Contains(host, "localhost")) {
                return false;
            }

            // Fiddler-style rule: redirect all epicgames.com, epicgames.net, epicgames.dev, and akamaized.net
            if (Contains(host, "epicgames.com") ||
                Contains(host, "epicgames.net") ||
                Contains(host, "epicgames.dev") ||
                Contains(host, "akamaized.net"))
            {
                return true;
            }

            return false;
        }

        static std::string ProcessUrlRedirection(const char* originalUrl, const char* sourceTag) {
            if (!originalUrl) return "";

            ParsedUri uri = ParsedUri::Parse(originalUrl);

            Config::LogUEFN("[%s] Raw URL: %s\n", sourceTag, originalUrl);

            if (!ShouldRedirectHost(uri.Host)) {
                return originalUrl;
            }

            // Fiddler-equivalent: BackendURL + PathAndQuery
            std::string pathAndQuery = uri.Path;
            if (pathAndQuery.empty() || pathAndQuery.front() != '/') {
                pathAndQuery = "/" + pathAndQuery;
            }
            if (!uri.Query.empty()) {
                pathAndQuery += uri.Query;
            }

            std::string finalUrl = Config::BackendA + pathAndQuery;

            printf("[LogsCURLLive] %s\n", originalUrl);
            fflush(stdout);

            return finalUrl;
        }

        // ============================================================================
        // Hook Handlers
        // ============================================================================
        static int Hooked_EngineCurlSetOpt(void* handle, int option, void* param) {
            if (option == 64 || option == 81) { // CURLOPT_SSL_VERIFYPEER / CURLOPT_SSL_VERIFYHOST
                return g_Original_EngineCurl(handle, option, reinterpret_cast<void*>(0));
            }

            if (option == 10002 && param != nullptr) { // CURLOPT_URL
                const char* urlStr = reinterpret_cast<const char*>(param);
                std::string redirected = ProcessUrlRedirection(urlStr, "UEFN-Engine");
                return g_Original_EngineCurl(handle, option, reinterpret_cast<void*>(const_cast<char*>(redirected.c_str())));
            }

            return g_Original_EngineCurl(handle, option, param);
        }

        static int Hooked_EOSCurlSetOpt(void* handle, int option, void* param) {
            if (option == 64 || option == 81) { // CURLOPT_SSL_VERIFYPEER / CURLOPT_SSL_VERIFYHOST
                return g_Original_EOSCurl(handle, option, reinterpret_cast<void*>(0));
            }

            if (option == 10002 && param != nullptr) { // CURLOPT_URL
                const char* urlStr = reinterpret_cast<const char*>(param);
                std::string redirected = ProcessUrlRedirection(urlStr, "UEFN-EOS");
                return g_Original_EOSCurl(handle, option, reinterpret_cast<void*>(const_cast<char*>(redirected.c_str())));
            }

            return g_Original_EOSCurl(handle, option, param);
        }

        // ============================================================================
        // ProcessRequest Engine VTable Hooking
        // ============================================================================
        static bool CheckBytes(uint8_t* base, int ind, const uint8_t* bytes, size_t sz) {
            for (size_t i = 0; i < sz; i++) {
                if (*(base + ind + i) != bytes[i]) return false;
            }
            return true;
        }

        static uint32_t DiscoverURLFieldOffset(void** vtable, void* requestObj) {
            if (vtable && vtable[0] && IsReadableMemory(vtable[0], 64)) {
                auto* fn = reinterpret_cast<uint8_t*>(vtable[0]);
                static const uint8_t patterns[][3] = {
                    {0x48, 0x8D, 0x81}, {0x48, 0x8D, 0x91},
                    {0x48, 0x8B, 0x81}, {0x48, 0x8B, 0x91},
                    {0x48, 0x8D, 0x82}, {0x48, 0x8D, 0x92},
                    {0x48, 0x8B, 0x82}, {0x48, 0x8B, 0x92},
                };

                for (int i = 0; i < 192; i++) {
                    for (auto& p : patterns) {
                        if (CheckBytes(fn, i, p, 3)) {
                            uint32_t off = *(uint32_t*)(fn + i + 3);
                            if (off >= 8 && off < 0x800) {
                                return off;
                            }
                        }
                    }
                }
            }

            if (requestObj && IsReadableMemory(requestObj, 0x600)) {
                auto* base = reinterpret_cast<uint8_t*>(requestObj);
                for (uint32_t off = 8; off < 0x500; off += 8) {
                    if (!IsReadableMemory(base + off, sizeof(FString))) continue;
                    auto* candidate = reinterpret_cast<FString*>(base + off);
                    if (candidate->Length == 0 || candidate->Length > 2048) continue;
                    if (candidate->MaxSize < candidate->Length) continue;
                    if (!IsReadableMemory(candidate->String, candidate->Length * sizeof(wchar_t))) continue;

                    __try {
                        const wchar_t* s = candidate->String;
                        if (s[0] == L'h' && s[1] == L't' && s[2] == L't' && s[3] == L'p') {
                            return off;
                        }
                    } __except(EXCEPTION_EXECUTE_HANDLER) {}
                }
            }

            return 0;
        }

        static bool ModifyURLInPlace(FString* urlField, const FString& newUrl) {
            if (!urlField || !newUrl.String || newUrl.Length == 0) return false;

            if (urlField->MaxSize >= newUrl.Length && urlField->String != nullptr) {
                memcpy(urlField->String, newUrl.String, newUrl.Length * sizeof(wchar_t));
                urlField->Length = newUrl.Length;
                return true;
            }

            if (Unreal::Memory::FMemory__Realloc && IsReadableMemory((void*)Unreal::Memory::FMemory__Realloc, 16)) {
                __try {
                    wchar_t* newBuf = reinterpret_cast<wchar_t*>(
                        Unreal::Memory::Realloc(
                            urlField->String,
                            static_cast<int64_t>(newUrl.Length * sizeof(wchar_t)),
                            static_cast<uint32_t>(alignof(wchar_t))
                        )
                    );
                    if (newBuf) {
                        memcpy(newBuf, newUrl.String, newUrl.Length * sizeof(wchar_t));
                        urlField->String  = newBuf;
                        urlField->Length  = newUrl.Length;
                        urlField->MaxSize = newUrl.Length;
                        return true;
                    }
                } __except(EXCEPTION_EXECUTE_HANDLER) {}
            }

            return false;
        }

        static void RedirectProcessRequest(void* request) {
            if (!request) return;
            struct CurlReq { void** VTable; };
            auto* curlRequest = reinterpret_cast<CurlReq*>(request);
            if (!curlRequest || !curlRequest->VTable) return;

            if (g_URLFieldOffset == 0) {
                g_URLFieldOffset = DiscoverURLFieldOffset(curlRequest->VTable, request);
            }
            if (g_URLFieldOffset == 0) return;

            if (!IsReadableMemory((uint8_t*)request + g_URLFieldOffset, sizeof(FString))) return;
            FString* urlField = (FString*)((uint8_t*)request + g_URLFieldOffset);

            if (!urlField->String || urlField->Length == 0) return;
            if (!IsReadableMemory(urlField->String, urlField->Length * sizeof(wchar_t))) return;

            int len = WideCharToMultiByte(CP_UTF8, 0, urlField->String, -1, nullptr, 0, nullptr, nullptr);
            if (len > 0) {
                std::string sUrl(len - 1, '\0');
                WideCharToMultiByte(CP_UTF8, 0, urlField->String, -1, &sUrl[0], len, nullptr, nullptr);

                std::string rewritten = ProcessUrlRedirection(sUrl.c_str(), "UEFN-ProcessRequest");
                if (rewritten != sUrl) {
                    int wLen = MultiByteToWideChar(CP_UTF8, 0, rewritten.c_str(), -1, nullptr, 0);
                    if (wLen > 0) {
                        std::wstring wRewritten(wLen - 1, L'\0');
                        MultiByteToWideChar(CP_UTF8, 0, rewritten.c_str(), -1, &wRewritten[0], wLen);

                        FString newUrl(wRewritten.c_str());
                        ModifyURLInPlace(urlField, newUrl);
                        newUrl.Dealloc();
                    }
                }
            }
        }

        static bool ProcessRequestHook(void* request) {
            RedirectProcessRequest(request);
            return g_ProcessRequestOG ? g_ProcessRequestOG(request) : true;
        }

        static bool EOSProcessRequestHook(void* request) {
            RedirectProcessRequest(request);
            return g_EOSProcessRequestOG ? g_EOSProcessRequestOG(request) : true;
        }

        static void FindFMemoryRealloc(HMODULE hModule) {
            if (Unreal::Memory::FMemory__Realloc) return;
            if (!hModule) return;

            MODULEINFO modInfo{};
            if (!GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(modInfo)))
                return;

            static const uint8_t sig1[] = { 0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x74, 0x24, 0x10, 0x57, 0x48, 0x83, 0xEC };
            uint8_t* scanBytes = reinterpret_cast<uint8_t*>(modInfo.lpBaseOfDll);
            size_t sz          = modInfo.SizeOfImage;

            for (size_t i = 0; i < sz - sizeof(sig1); i++) {
                if (memcmp(scanBytes + i, sig1, sizeof(sig1)) == 0) {
                    Unreal::Memory::FMemory__Realloc = (uint64_t)(scanBytes + i);
                    return;
                }
            }
        }

        // ============================================================================
        // Hook Initializers
        // ============================================================================
        static bool HookEngineCurl() {
            if (g_EngineCurlHooked) return true;

            HMODULE hEngine = GetModuleHandleA("UnrealEditorFortnite-Engine-Win64-Shipping.dll");
            if (!hEngine) hEngine = GetModuleHandleA("UnrealEditorFortnite-Win64-Shipping.exe");
            if (!hEngine) hEngine = GetModuleHandleA(nullptr);

            if (!hEngine) return false;

            FindFMemoryRealloc(hEngine);

            std::vector<const char*> engineSigs = {
                "89 54 24 10 4C 89 44 24 18 4C 89 4C 24 20 53 48 83 EC 30 48 8B D9 48 85 C9 75 0B B8 2B 00 00 00",
                "89 54 24 10 4C 89 44 24 18 4C 89 4C 24 20 48 83 EC 28 48 85 C9 75 08 8D 41 2B 48 83 C4 28 C3 4C",
                "48 89 5C 24 10 56 48 83 EC 20 49 8B F0 48 8B D9 81 FA 10 27 00 00 7D 12 45 8B 00 48",
                "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 48 83 EC 30 33 ED 49 8B F0 48 8B D9",
                "48 89 5C 24 08 48 89 6C 24 10 56 57 41 56 48 83 EC 50 33 ED 49 8B F0 8B DA 48 8B F9",
                "48 89 5C 24 ? 55 56 57 41 56 41 57 48 83 EC 50 33 DB 49 8B F0 48 8B F9 8B EB 81 FA"
            };

            uintptr_t targetAddr = ScanModuleSignatures(hEngine, engineSigs);

            if (!targetAddr) {
                targetAddr = reinterpret_cast<uintptr_t>(GetProcAddress(hEngine, "curl_easy_setopt"));
            }

            if (!targetAddr) {
                HMODULE hLibCurl = GetModuleHandleA("libcurl.dll");
                if (!hLibCurl) hLibCurl = GetModuleHandleA("libcurl-x64.dll");
                if (hLibCurl) {
                    targetAddr = reinterpret_cast<uintptr_t>(GetProcAddress(hLibCurl, "curl_easy_setopt"));
                }
            }

            if (targetAddr) {
                if (MH_CreateHook(reinterpret_cast<void*>(targetAddr),
                                  reinterpret_cast<void*>(Hooked_EngineCurlSetOpt),
                                  reinterpret_cast<void**>(&g_Original_EngineCurl)) == MH_OK)
                {
                    MH_EnableHook(reinterpret_cast<void*>(targetAddr));
                    g_EngineCurlHooked = true;
                    Config::Log("UEFN", "Successfully hooked Engine curl_easy_setopt at 0x%p\n", (void*)targetAddr);
                    return true;
                }
            }

            return false;
        }

        static bool HookEOSCurl() {
            if (g_EOSCurlHooked) return true;

            HMODULE hEOS = GetModuleHandleA("EOSSDK-Win64-Shipping.dll");
            if (!hEOS) hEOS = GetModuleHandleA("EOSSDK-Win64-Shipping");
            if (!hEOS) hEOS = LoadLibraryA("EOSSDK-Win64-Shipping.dll");
            if (!hEOS) return false;

            std::vector<const char*> eosSigs = {
                "89 54 24 10 4C 89 44 24 18 4C 89 4C 24 20 48 83 EC 28 48 85 C9 75 0A B8 2B 00 00 00 48 83 C4 28",
                "89 54 24 10 4C 89 44 24 18 4C 89 4C 24 20 48 83 EC 28 48 85 C9 75 08 8D 41 2B 48 83 C4 28 C3 4C",
                "48 89 5C 24 18 55 56 57 41 56 41 57 48 83 EC 50 33 FF 49 8B F0 48 8B D9 8B EF 81 FA",
                "48 89 5C 24 ? 55 56 57 41 56 41 57 48 83 EC 50 33 DB 49 8B F0 48 8B F9 8B EB 81 FA"
            };

            uintptr_t targetAddr = ScanModuleSignatures(hEOS, eosSigs);

            if (!targetAddr) {
                targetAddr = reinterpret_cast<uintptr_t>(GetProcAddress(hEOS, "curl_easy_setopt"));
            }

            if (targetAddr) {
                if (MH_CreateHook(reinterpret_cast<void*>(targetAddr),
                                  reinterpret_cast<void*>(Hooked_EOSCurlSetOpt),
                                  reinterpret_cast<void**>(&g_Original_EOSCurl)) == MH_OK)
                {
                    MH_EnableHook(reinterpret_cast<void*>(targetAddr));
                    g_EOSCurlHooked = true;
                    Config::Log("UEFN", "Successfully hooked EOSSDK curl_easy_setopt at 0x%p\n", (void*)targetAddr);
                    return true;
                }
            }

            return false;
        }

        static void ApplyMemoryFixes() {
            if (!Config::FixMemLeak || g_MemLeakFixed) return;

            HMODULE hEngine = GetModuleHandleA("UnrealEditorFortnite-Engine-Win64-Shipping.dll");
            if (!hEngine) hEngine = GetModuleHandleA(nullptr);
            if (!hEngine) return;

            uintptr_t leakAddr = SigScan(hEngine, "4C 8B DC 55 57 41 56 49 8D AB ? ? ? ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? 48 8B 01 41 B6");
            if (leakAddr) {
                void* og = nullptr;
                if (MH_CreateHook(reinterpret_cast<void*>(leakAddr), reinterpret_cast<void*>(ReturnNone), &og) == MH_OK) {
                    MH_EnableHook(reinterpret_cast<void*>(leakAddr));
                    g_MemLeakFixed = true;
                    Config::Log("UEFN", "Applied Memory Leak Fix at 0x%p\n", (void*)leakAddr);
                }
            }
        }

        static void ApplyExitHooks() {
            if (!Config::AntiExit || g_ExitHooked) return;

            HMODULE hEngine = GetModuleHandleA("UnrealEditorFortnite-Engine-Win64-Shipping.dll");
            if (!hEngine) hEngine = GetModuleHandleA(nullptr);
            if (!hEngine) return;

            std::vector<const char*> unsafePopupSigs = {
                "4C 8B DC 55 49 8D AB ? ? ? ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? 49 89 73 F0 49 89 7B E8 48 8B F9 4D 89 63 E0 4D 8B E0 4D 89 6B D8",
                "4C 8B DC 55 49 8D AB ? ? ? ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ?",
                "48 89 5C 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 8D AC 24 ? ? ? ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? 80 B9 ? ? ? ? ? 48 8B DA 48 8B F1"
            };

            uintptr_t unsafePopup = ScanModuleSignatures(hEngine, unsafePopupSigs);
            if (unsafePopup) {
                void* og = nullptr;
                if (MH_CreateHook(reinterpret_cast<void*>(unsafePopup), reinterpret_cast<void*>(ReturnNone), &og) == MH_OK) {
                    MH_EnableHook(reinterpret_cast<void*>(unsafePopup));
                    Config::Log("UEFN", "Hooked UnsafeEnvironmentPopup at 0x%p\n", (void*)unsafePopup);
                }
            }

            std::vector<const char*> exitSigs = {
                "48 89 5C 24 ? 57 48 83 EC 40 41 B9 ? ? ? ? 0F B6 F9 44 38 0D ? ? ? ? 0F B6 DA 72 24 89 5C 24 30 48 8D 05 ? ? ? ? 89 7C 24 28 4C 8D 05 ? ? ? ? 33 D2 48 89 44 24 ? 33 C9 E8 ? ? ? ?",
                "48 8B C4 48 89 58 18 88 50 10 88 48 08 57 48 83 EC 30",
                "4C 8B DC 49 89 5B 08 49 89 6B 10 49 89 73 18 49 89 7B 20 41 56 48 83 EC 30 80 3D ? ? ? ? ? 49 8B"
            };

            uintptr_t reqExit = ScanModuleSignatures(hEngine, exitSigs);
            if (reqExit) {
                void* og = nullptr;
                if (MH_CreateHook(reinterpret_cast<void*>(reqExit), reinterpret_cast<void*>(ReturnNone), &og) == MH_OK) {
                    MH_EnableHook(reinterpret_cast<void*>(reqExit));
                    Config::Log("UEFN", "Hooked RequestExitWithStatus at 0x%p\n", (void*)reqExit);
                }
            }

            g_ExitHooked = true;
        }

        // ============================================================================
        // Background Polling Thread
        // ============================================================================
        static DWORD WINAPI BackgroundPollThread(LPVOID) {
            for (int i = 0; i < 600; ++i) { // Poll for up to 60 seconds
                if (!g_EngineCurlHooked) HookEngineCurl();
                if (!g_EOSCurlHooked)    HookEOSCurl();

                ApplyMemoryFixes();
                ApplyExitHooks();

                if (g_EngineCurlHooked && g_EOSCurlHooked) {
                    Config::Log("UEFN", "All UEFN hooks successfully active.\n");
                    break;
                }

                Sleep(100);
            }
            return 0;
        }

        // ============================================================================
        // Public API
        // ============================================================================
        void Init() {
            MH_Initialize();

            Config::Log("UEFN", "Initializing UEFN redirection engine...\n");
            Config::Log("UEFN", "Target Backend: %s\n", Config::BackendA.c_str());

            // 1. Auto-configure bEnableCURLInEditor in all relevant INI files
            AutoEnableCurlInIniFiles();

            // 2. Hook Curl functions
            bool engineHooked = HookEngineCurl();
            bool eosHooked    = HookEOSCurl();

            // 3. Apply memory and anti-exit patches
            ApplyMemoryFixes();
            ApplyExitHooks();

            if (engineHooked || eosHooked) {
                Config::Log("UEFN", "UEFN Redirection initialized successfully (Engine: %s, EOS: %s).\n",
                            engineHooked ? "YES" : "PENDING", eosHooked ? "YES" : "PENDING");
            } else {
                Config::Log("UEFN", "Waiting for UEFN modules to load in background...\n");
            }

            // Spawn background poller to ensure late-loaded modules are hooked
            CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)BackgroundPollThread, nullptr, 0, nullptr);
        }

        void Shutdown() {
            MH_DisableHook(MH_ALL_HOOKS);
            g_EngineCurlHooked = false;
            g_EOSCurlHooked    = false;
            g_ProcessReqHooked = false;
            g_ExitHooked       = false;
            g_MemLeakFixed     = false;
            Config::Log("UEFN", "UEFN Redirection engine stopped.\n");
        }
    }
}
