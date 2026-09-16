// Hooks.cpp - Universal Engine, EOS, and Libcurl Interception (1.7.2 through 32.11)
#include "pch.h"
#include "Hooks.h"
#include "Config.h"
#include "Redirection.h"
#include <emmintrin.h>

namespace Authy {
    namespace PE {
        IMAGE_SECTION_HEADER* GetSection(uint64_t imageBase, const char* name);
    }

    namespace Hooks {
        static bool (*g_ProcessRequestOG)(void* Request) = nullptr;
        static bool (*g_EOSProcessRequestOG)(void* Request) = nullptr;

        static uint32_t g_URLFieldOffset = 0;
        static bool     g_CurlHookInstalled = false;

        static bool IsReadablePtr(const void* p, SIZE_T len = 8) {
            if (!p || reinterpret_cast<uintptr_t>(p) < 0x10000) return false;
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQuery(p, &mbi, sizeof(mbi))) return false;
            constexpr DWORD readable = PAGE_READONLY | PAGE_READWRITE |
                                       PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                                       PAGE_EXECUTE_WRITECOPY | PAGE_WRITECOPY;
            return (mbi.Protect & readable) && !(mbi.Protect & PAGE_GUARD) && mbi.RegionSize >= len;
        }

        static bool CheckBytes(uint8_t* base, int ind, const uint8_t* bytes, size_t sz, bool upwards = false) {
            auto* offBase = upwards ? (base - ind) : (base + ind);
            for (size_t i = 0; i < sz; i++) {
                if (*(offBase + i) != bytes[i]) return false;
            }
            return true;
        }

        static bool CheckBytes3(uint8_t* base, int ind, uint8_t b0, uint8_t b1, uint8_t b2, bool upwards = false) {
            auto* offBase = upwards ? (base - ind) : (base + ind);
            return *(offBase + 0) == b0 && *(offBase + 1) == b1 && *(offBase + 2) == b2;
        }

        static bool CheckBytes1(uint8_t* base, int ind, uint8_t b0, bool upwards = false) {
            auto* offBase = upwards ? (base - ind) : (base + ind);
            return *(offBase) == b0;
        }

        // ============================================================================
        // Fast SIMD String Reference Finder
        // ============================================================================
        static uint8_t* InternalFindStringRef(uint64_t imageBase, const void* string, size_t sLen) {
            auto textSec = PE::GetSection(imageBase, ".text");
            if (!textSec) return nullptr;

            auto dos = (IMAGE_DOS_HEADER*)imageBase;
            if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
            auto nt = (IMAGE_NT_HEADERS64*)(imageBase + dos->e_lfanew);
            uint64_t imageSize = nt->OptionalHeader.SizeOfImage;

            uint8_t* scanBytes = (uint8_t*)(imageBase + textSec->VirtualAddress);
            size_t sizeOfImage = textSec->Misc.VirtualSize;

            __m128i t = _mm_set1_epi8((char)0x8D); // LEA opcode

            for (size_t i = 0; i < sizeOfImage - (sizeOfImage % 16); i += 16) {
                auto bytes = _mm_loadu_si128((const __m128i*)(scanBytes + i));
                int offset = _mm_movemask_epi8(_mm_cmpeq_epi8(bytes, t));
                if (offset == 0) continue;

                for (int q = 0; q < 16; q++) {
                    if (offset & (1 << q)) {
                        bool hasRex = (i + q > 0) && ((scanBytes[i + q - 1] & 0xF0) == 0x40);
                        uint8_t* instrStart = hasRex ? (&scanBytes[i + q - 1]) : (&scanBytes[i + q]);

                        int32_t disp = *(int32_t*)(&scanBytes[i + q + 2]);
                        uint8_t* stringAdd = (&scanBytes[i + q] + 6) + disp;

                        if ((uint64_t)stringAdd >= imageBase && (uint64_t)stringAdd + sLen < imageBase + imageSize) {
                            __try {
                                if (memcmp(string, stringAdd, sLen) == 0) {
                                    return instrStart;
                                }
                            } __except(EXCEPTION_EXECUTE_HANDLER) {}
                        }
                    }
                }
            }
            return nullptr;
        }

        static uint8_t* FindStringRefInModule(uint64_t imageBase, const wchar_t* str) {
            size_t len = wcslen(str) * sizeof(wchar_t);
            return InternalFindStringRef(imageBase, str, len);
        }

        static uint8_t* FindStringRefInModule(uint64_t imageBase, const char* str) {
            size_t len = strlen(str);
            return InternalFindStringRef(imageBase, str, len);
        }

        static uint8_t* FindFunctionPrologue(uint8_t* strRef, bool bEOS) {
            if (!strRef) return nullptr;

            for (int i = 0; i < 4096; i++) {
                if (bEOS) {
                    if (CheckBytes3(strRef, i, 0x48, 0x89, 0x5C, true)) {
                        return strRef - i;
                    }
                    continue;
                }

                // Check common function prologues first (UE4 / UE5):
                if (CheckBytes3(strRef, i, 0x4C, 0x8B, 0xDC, true) ||
                    CheckBytes3(strRef, i, 0x48, 0x8B, 0xC4, true) ||
                    CheckBytes3(strRef, i, 0x48, 0x89, 0x5C, true)) {
                    return strRef - i;
                }

                // If stack adjustment is found, look slightly further up for the actual prologue:
                if (CheckBytes3(strRef, i, 0x48, 0x81, 0xEC, true) || 
                    CheckBytes3(strRef, i, 0x48, 0x83, 0xEC, true)) {
                    for (int x = 1; x < 64; x++) {
                        if (CheckBytes3(strRef, i + x, 0x4C, 0x8B, 0xDC, true) ||
                            CheckBytes3(strRef, i + x, 0x48, 0x8B, 0xC4, true) ||
                            CheckBytes3(strRef, i + x, 0x48, 0x89, 0x5C, true)) {
                            return strRef - (i + x);
                        }
                    }
                }
            }
            return nullptr;
        }

        static uint8_t* FindProcessRequest(uint64_t imageBase, bool bEOS) {
            // Fast path: Known 26.20 VTable entry verification
            if (!bEOS) {
                uint64_t vtableSlot = imageBase + 0x0A793690;
                if (IsReadablePtr((void*)vtableSlot, sizeof(void*))) {
                    uint8_t* target = *(uint8_t**)vtableSlot;
                    if (IsReadablePtr(target, 24)) {
                        static const uint8_t k2620Prologue[] = {
                            0x48, 0x89, 0x5C, 0x24, 0x20, 0x55, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57,
                            0x48, 0x8B, 0xEC, 0x48, 0x83, 0xEC, 0x40
                        };
                        if (memcmp(target, k2620Prologue, sizeof(k2620Prologue)) == 0) {
                            return target;
                        }
                    }
                }
            }

            // Universal string search across module
            uint8_t* strRef = FindStringRefInModule(imageBase, L"STAT_FCurlHttpRequest_ProcessRequest");
            if (!strRef) strRef = FindStringRefInModule(imageBase, L"%p: request (easy handle:%p) has been added to threaded queue for processing");
            if (!strRef) strRef = FindStringRefInModule(imageBase, "STAT_FCurlHttpRequest_ProcessRequest");
            if (!strRef) strRef = FindStringRefInModule(imageBase, "%p: request (easy handle:%p) has been added to threaded queue for processing");
            if (!strRef) strRef = FindStringRefInModule(imageBase, L"FCurlHttpRequest::ProcessRequest");
            if (!strRef) strRef = FindStringRefInModule(imageBase, "FCurlHttpRequest::ProcessRequest");

            if (strRef) {
                uint8_t* fn = FindFunctionPrologue(strRef, bEOS);
                if (fn) return fn;
            }

            // Pattern scan fallback in .text for known ProcessRequest prologues
            auto textSec = PE::GetSection(imageBase, ".text");
            if (textSec && !bEOS) {
                uint8_t* scanBytes = (uint8_t*)(imageBase + textSec->VirtualAddress);
                size_t sz = textSec->Misc.VirtualSize;
                static const uint8_t k2620Prologue[] = {
                    0x48, 0x89, 0x5C, 0x24, 0x20, 0x55, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57,
                    0x48, 0x8B, 0xEC, 0x48, 0x83, 0xEC, 0x40
                };
                for (size_t i = 0; i + sizeof(k2620Prologue) <= sz; i++) {
                    if (memcmp(scanBytes + i, k2620Prologue, sizeof(k2620Prologue)) == 0) {
                        return scanBytes + i;
                    }
                }
            }

            return nullptr;
        }

        static void** FindVTableEntry(uint64_t imageBase, uint8_t* processRequest) {
            if (!processRequest) return nullptr;

            // Fast path for known 26.20 slot
            uint64_t knownSlot = imageBase + 0x0A793690;
            if (IsReadablePtr((void*)knownSlot, sizeof(void*))) {
                if (*(uint64_t*)knownSlot == (uint64_t)processRequest) {
                    return (void**)knownSlot;
                }
            }

            auto rdataSec = PE::GetSection(imageBase, ".rdata");
            if (rdataSec) {
                uint8_t* rdataStart = (uint8_t*)(imageBase + rdataSec->VirtualAddress);
                size_t rdataSize = rdataSec->Misc.VirtualSize;

                for (size_t i = 0; i < rdataSize - sizeof(void*); i += sizeof(void*)) {
                    if (*(uint64_t*)(rdataStart + i) == (uint64_t)processRequest) {
                        return (void**)(rdataStart + i);
                    }
                }
            }

            auto dataSec = PE::GetSection(imageBase, ".data");
            if (dataSec) {
                uint8_t* dataStart = (uint8_t*)(imageBase + dataSec->VirtualAddress);
                size_t dataSize = dataSec->Misc.VirtualSize;

                for (size_t i = 0; i < dataSize - sizeof(void*); i += sizeof(void*)) {
                    if (*(uint64_t*)(dataStart + i) == (uint64_t)processRequest) {
                        return (void**)(dataStart + i);
                    }
                }
            }

            return nullptr;
        }

        // ============================================================================
        // Dynamic URL Offset Discovery (Strategy A + Strategy B)
        // ============================================================================
        static uint32_t DiscoverURLFieldOffset(void** vtable, void* requestObj) {
            if (vtable && vtable[0] && IsReadablePtr(vtable[0], 64)) {
                auto* fn = reinterpret_cast<uint8_t*>(vtable[0]);
                static const uint8_t patterns[][3] = {
                    {0x48, 0x8D, 0x81}, {0x48, 0x8D, 0x91},
                    {0x48, 0x8B, 0x81}, {0x48, 0x8B, 0x91},
                    {0x48, 0x8D, 0x82}, {0x48, 0x8D, 0x92},
                    {0x48, 0x8B, 0x82}, {0x48, 0x8B, 0x92},
                };

                for (int i = 0; i < 192; i++) {
                    for (auto& p : patterns) {
                        if (CheckBytes(fn, i, p, 3, false)) {
                            uint32_t off = *(uint32_t*)(fn + i + 3);
                            if (off >= 8 && off < 0x800) {
                                Config::Log("Authy", "URL offset found via disasm at vtable[0]+%d: 0x%X\n", i, off);
                                return off;
                            }
                        }
                    }
                }
            }

            if (requestObj && IsReadablePtr(requestObj, 0x600)) {
                auto* base = reinterpret_cast<uint8_t*>(requestObj);
                for (uint32_t off = 8; off < 0x500; off += 8) {
                    if (!IsReadablePtr(base + off, sizeof(FString))) continue;
                    auto* candidate = reinterpret_cast<FString*>(base + off);
                    if (candidate->Length == 0 || candidate->Length > 2048) continue;
                    if (candidate->MaxSize < candidate->Length) continue;
                    if (!IsReadablePtr(candidate->String, candidate->Length * sizeof(wchar_t))) continue;

                    __try {
                        const wchar_t* s = candidate->String;
                        if (s[0] == L'h' && s[1] == L't' && s[2] == L't' && s[3] == L'p') {
                            Config::Log("Authy", "URL offset found via object scan at 0x%X (url=%ls)\n", off, s);
                            return off;
                        }
                    } __except(EXCEPTION_EXECUTE_HANDLER) {}
                }
            }

            return 0;
        }

        static uint32_t GetURLFieldOffsetForObject(void** vtable, void* requestObj) {
            if (g_URLFieldOffset != 0 && requestObj && IsReadablePtr((uint8_t*)requestObj + g_URLFieldOffset, sizeof(FString))) {
                FString* candidate = (FString*)((uint8_t*)requestObj + g_URLFieldOffset);
                if (candidate->Length > 0 && candidate->Length < 2048 && candidate->String && IsReadablePtr(candidate->String, 8)) {
                    __try {
                        if (candidate->String[0] == L'h' && candidate->String[1] == L't' && candidate->String[2] == L't' && candidate->String[3] == L'p') {
                            return g_URLFieldOffset;
                        }
                    } __except(EXCEPTION_EXECUTE_HANDLER) {}
                }
            }

            uint32_t off = DiscoverURLFieldOffset(vtable, requestObj);
            if (off != 0) g_URLFieldOffset = off;
            return off;
        }

        static bool ModifyURLInPlace(FString* urlField, const FString& newUrl) {
            if (!urlField || !newUrl.String || newUrl.Length == 0) return false;

            // Direct in-place overwrite if capacity permits
            if (urlField->MaxSize >= newUrl.Length && urlField->String != nullptr) {
                memcpy(urlField->String, newUrl.String, newUrl.Length * sizeof(wchar_t));
                urlField->Length = newUrl.Length;
                return true;
            }

            // Safe reallocation using game's allocator
            if (Unreal::Memory::FMemory__Realloc && IsReadablePtr((void*)Unreal::Memory::FMemory__Realloc, 16)) {
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

        bool InstallCurlHook();

        static void RedirectRequest(void* request, bool bEOS) {
            if (!request) return;
            struct CurlReq { void** VTable; };
            auto* curlRequest = reinterpret_cast<CurlReq*>(request);
            if (!curlRequest || !curlRequest->VTable) return;

            if (!g_CurlHookInstalled) {
                InstallCurlHook();
            }

            uint32_t urlOff = GetURLFieldOffsetForObject(curlRequest->VTable, request);
            if (urlOff == 0) return;

            if (!IsReadablePtr((uint8_t*)request + urlOff, sizeof(FString))) return;
            FString* urlField = (FString*)((uint8_t*)request + urlOff);

            if (!urlField->String || urlField->Length == 0) return;
            if (!IsReadablePtr(urlField->String, urlField->Length * sizeof(wchar_t))) return;

            // Explicitly DO NOT redirect cdn2.unrealengine.com
            if (wcsstr(urlField->String, L"cdn2.unrealengine.com") != nullptr) return;

            if (Redirection::ShouldRedirectUrl(urlField->String)) {
                FString urlCopy(urlField->String);
                Redirection::URL parsed(urlCopy);

                FString backendFStr(Config::BackendW.c_str());
                parsed.SetHost(backendFStr);

                FString newUrl = parsed.GetUrl();
                if (newUrl.String && newUrl.Length > 0) {
                    Config::LogW("Redirect", L"%ls -> %ls\n", urlField->String, newUrl.String);
                    ModifyURLInPlace(urlField, newUrl);
                }

                newUrl.Dealloc();
                parsed.Dealloc();
                urlCopy.Dealloc();
            }
        }

        static bool ProcessRequestHook(void* request) {
            RedirectRequest(request, false);
            return g_ProcessRequestOG ? g_ProcessRequestOG(request) : true;
        }

        static bool EOSProcessRequestHook(void* request) {
            RedirectRequest(request, true);
            return g_EOSProcessRequestOG ? g_EOSProcessRequestOG(request) : true;
        }

        static bool InitializeForModule(uint64_t moduleBase, void* hook, void** og, bool bEOS) {
            if (!moduleBase) return false;

            uint8_t* processRequest = FindProcessRequest(moduleBase, bEOS);
            if (!processRequest) return false;

            void** vtableEntry = FindVTableEntry(moduleBase, processRequest);
            if (!vtableEntry) return false;

            DWORD oldProt;
            VirtualProtect(vtableEntry, sizeof(void*), PAGE_EXECUTE_READWRITE, &oldProt);
            if (og) *og = (void*)processRequest;
            *vtableEntry = hook;
            VirtualProtect(vtableEntry, sizeof(void*), oldProt, &oldProt);

            Config::Log("Authy", "Hook installed in %s (func=%p, vft=%p)\n",
                   bEOS ? "EOSSDK-Win64-Shipping" : "Main Executable",
                   processRequest, (void*)vtableEntry);
            return true;
        }

        // ============================================================================
        // Libcurl Hook Layer
        // ============================================================================
        typedef int (*PFN_curl_easy_setopt)(void* handle, int option, ...);
        static PFN_curl_easy_setopt g_Original_curl_easy_setopt = nullptr;

        static int Hooked_curl_easy_setopt(void* handle, int option, void* param) {
            if (option == 10002 && param != nullptr) { // CURLOPT_URL
                const char* urlStr = (const char*)param;

                // Explicitly DO NOT redirect cdn2.unrealengine.com
                if (strstr(urlStr, "cdn2.unrealengine.com") != nullptr) {
                    return g_Original_curl_easy_setopt(handle, option, param);
                }

                if (Redirection::ShouldRedirectUrlA(urlStr)) {
                    std::string url(urlStr);
                    static const char* redirectedHosts[] = {
                        "ol.epicgames.com", "ol.epicgames.net", "on.epicgames.com",
                        "game-social.epicgames.com", "ak.epicgames.com", "epicgames.dev",
                        "superawesome.com", "akamaized.net", "eosapi.epicgames.com", "epicgames.com"
                    };

                    for (const auto& host : redirectedHosts) {
                        size_t pos = url.find(host);
                        if (pos != std::string::npos) {
                            size_t slashAfter = url.find('/', pos);
                            std::string path = (slashAfter != std::string::npos) ? url.substr(slashAfter) : "";
                            std::string rewritten = Config::BackendA + path;

                            g_Original_curl_easy_setopt(handle, 64, (void*)0); // CURLOPT_SSL_VERIFYPEER = 0
                            g_Original_curl_easy_setopt(handle, 81, (void*)0); // CURLOPT_SSL_VERIFYHOST = 0

                            Config::Log("Redirect", "%s -> %s\n", urlStr, rewritten.c_str());
                            return g_Original_curl_easy_setopt(handle, option, (void*)rewritten.c_str());
                        }
                    }
                }
            }
            return g_Original_curl_easy_setopt(handle, option, param);
        }

        bool InstallCurlHook() {
            if (g_CurlHookInstalled) return true;

            void* fnSetOpt = nullptr;
            HMODULE hCurl = GetModuleHandleA("libcurl.dll");
            if (!hCurl) hCurl = GetModuleHandleA("libcurl-x64.dll");
            if (hCurl) fnSetOpt = (void*)GetProcAddress(hCurl, "curl_easy_setopt");

            if (!fnSetOpt && Globals::EOSModuleBase)
                fnSetOpt = (void*)GetProcAddress((HMODULE)Globals::EOSModuleBase, "curl_easy_setopt");

            if (!fnSetOpt && Globals::MainImageBase)
                fnSetOpt = (void*)GetProcAddress((HMODULE)Globals::MainImageBase, "curl_easy_setopt");

            if (fnSetOpt) {
                MH_CreateHook(fnSetOpt, (void*)Hooked_curl_easy_setopt, (void**)&g_Original_curl_easy_setopt);
                MH_EnableHook(fnSetOpt);
                g_CurlHookInstalled = true;
                Config::Log("Authy", "Libcurl curl_easy_setopt hook active at %p\n", fnSetOpt);
                return true;
            }
            return false;
        }

        // ============================================================================
        // Find FMemory::Realloc
        // ============================================================================
        static void FindFMemoryRealloc() {
            if (!Globals::MainTextBuf || !Globals::MainTextSize) return;

            static const uint8_t sig1[] = { 0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x74, 0x24, 0x10, 0x57, 0x48, 0x83, 0xEC };
            uint8_t* scanBytes = (uint8_t*)Globals::MainTextBuf;
            size_t sz = Globals::MainTextSize;

            for (size_t i = 0; i < sz - sizeof(sig1); i++) {
                if (memcmp(scanBytes + i, sig1, sizeof(sig1)) == 0) {
                    Unreal::Memory::FMemory__Realloc = (uint64_t)(scanBytes + i);
                    Config::Log("Authy", "Discovered FMemory::Realloc at %p\n", (void*)Unreal::Memory::FMemory__Realloc);
                    return;
                }
            }
        }

        bool Install() {
            FindFMemoryRealloc();

            bool curlActive = InstallCurlHook();

            // 1. Hook Main ProcessRequest via VTable Entry in .rdata (with retries)
            bool hookedMain = false;
            for (int retry = 0; retry < 50; retry++) {
                if (InitializeForModule((uint64_t)Globals::MainImageBase, (void*)ProcessRequestHook,
                                        (void**)&g_ProcessRequestOG, false)) {
                    hookedMain = true;
                    break;
                }
                Sleep(30);
            }

            // 2. Hook EOS ProcessRequest if present (with retries)
            bool hookedEOS = false;
            for (int retry = 0; retry < 30; retry++) {
                if (!Globals::EOSModuleBase) {
                    Globals::EOSModuleBase = GetModuleHandleA("EOSSDK-Win64-Shipping");
                    if (!Globals::EOSModuleBase) Globals::EOSModuleBase = LoadLibraryA("EOSSDK-Win64-Shipping");
                }
                if (Globals::EOSModuleBase) {
                    if (InitializeForModule((uint64_t)Globals::EOSModuleBase, (void*)EOSProcessRequestHook,
                                            (void**)&g_EOSProcessRequestOG, true)) {
                        hookedEOS = true;
                        break;
                    }
                }
                if (hookedMain) break;
                Sleep(30);
            }

            Config::Log("Authy", "Status -> Libcurl: %s | FCurlHttpRequest: %s\n",
                   curlActive ? "ACTIVE" : "STANDBY",
                   (hookedMain || hookedEOS) ? "ACTIVE" : "STANDBY");

            return (curlActive || hookedMain || hookedEOS);
        }

        void Remove() {
            MH_DisableHook(MH_ALL_HOOKS);
        }
    }
}
