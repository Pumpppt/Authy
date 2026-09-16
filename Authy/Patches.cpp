// Patches.cpp - Universal Anti-Crash, Anti-Exit, Pak Signature & UTOC Bypasses
#include "pch.h"
#include "Patches.h"
#include "Config.h"

namespace Authy {
    namespace Patches {
        static bool IsValidMemory(void* ptr, size_t size) {
            if (!ptr || (uintptr_t)ptr < 0x10000) return false;
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQuery(ptr, &mbi, sizeof(mbi))) return false;
            return (mbi.State == MEM_COMMIT) && !(mbi.Protect & PAGE_NOACCESS) && !(mbi.Protect & PAGE_GUARD);
        }

        template <typename T>
        static bool SafePatch(uintptr_t ptr, T val) {
            if (IsValidMemory((void*)ptr, sizeof(T))) {
                DWORD oldProt;
                if (VirtualProtect((LPVOID)ptr, sizeof(T), PAGE_EXECUTE_READWRITE, &oldProt)) {
                    *(T*)ptr = val;
                    VirtualProtect((LPVOID)ptr, sizeof(T), oldProt, &oldProt);
                    return true;
                }
            }
            return false;
        }

        static bool MatchPattern(const uint8_t* data, const char* pattern) {
            const char* pat = pattern;
            const uint8_t* ptr = data;
            while (*pat) {
                if (*pat == ' ') { pat++; continue; }
                if (*pat == '?') {
                    ptr++;
                    pat++;
                    if (*pat == '?') pat++;
                    continue;
                }
                char byteStr[3] = { pat[0], pat[1], 0 };
                uint8_t expected = (uint8_t)strtoul(byteStr, nullptr, 16);
                if (*ptr != expected) return false;
                ptr++;
                pat += 2;
            }
            return true;
        }

        static uint8_t* FindPattern(uint8_t* start, size_t size, const char* pattern) {
            if (!start || !size) return nullptr;
            const char* pat = pattern;
            while (*pat == ' ') pat++;
            uint8_t firstByte = 0;
            bool hasFirst = false;
            if (*pat != '?') {
                char byteStr[3] = { pat[0], pat[1], 0 };
                firstByte = (uint8_t)strtoul(byteStr, nullptr, 16);
                hasFirst = true;
            }

            for (size_t i = 0; i < size - 64; i++) {
                if (hasFirst && start[i] != firstByte) continue;
                if (MatchPattern(start + i, pattern)) {
                    return start + i;
                }
            }
            return nullptr;
        }

        static void (*g_RequestExitWithStatusOG)(bool Force, unsigned char Code, wchar_t* CloseReason) = nullptr;

        static void RequestExitWithStatusHook(bool Force, unsigned char Code, wchar_t* CloseReason) {
            // Neutralize exit call — keep the game alive!
            return;
        }

        void Install() {
            uint64_t base = (uint64_t)Globals::MainImageBase;
            if (!base) return;

            MH_Initialize();

            uint8_t* textStart = (uint8_t*)Globals::MainTextBuf;
            size_t textSize = Globals::MainTextSize;

            // 1. Hook RequestExitWithStatus (32.11 RVA: 0x4336BAC)
            bool is3211 = false;
            void* exitFn = (void*)(base + 0x4336BAC);
            if (IsValidMemory(exitFn, 16)) {
                uint8_t* b = (uint8_t*)exitFn;
                if (b[0] == 0x4C && b[1] == 0x8B && b[2] == 0xDC) {
                    MH_CreateHook(exitFn, (LPVOID)RequestExitWithStatusHook, (LPVOID*)&g_RequestExitWithStatusOG);
                    MH_EnableHook(exitFn);
                    is3211 = true;
                }
            }

            // 2. Universal Exit Patterns & Security Bypass Patches (from Eclipse / Universal)
            if (textStart && textSize) {
                // Exit patterns
                static const char* exitPatterns[] = {
                    "48 89 5C 24 ? 57 48 83 EC 40 41 B9 ? ? ? ? 0F B6 F9 44 38 0D ? ? ? ? 0F B6 DA 72 24 89 5C 24 30 48 8D 05 ? ? ? ? 89 7C 24 28 4C 8D 05 ? ? ? ? 33 D2 48 89 44 24 ? 33 C9 E8 ? ? ? ?",
                    "48 8B C4 48 89 58 18 88 50 10 88 48 08 57 48 83 EC 30",
                    "4C 8B DC 49 89 5B 08 49 89 6B 10 49 89 73 18 49 89 7B 20 41 56 48 83 EC 30 80 3D ? ? ? ? ? 49 8B"
                };

                for (const auto& pat : exitPatterns) {
                    uint8_t* addr = FindPattern(textStart, textSize, pat);
                    if (addr) {
                        SafePatch<uint8_t>((uintptr_t)addr, 0xC3);
                        break;
                    }
                }

                // Security / Environment checks
                static const char* envPatterns[] = {
                    "4C 8B DC 55 49 8D AB ? ? ? ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? 49 89 73 F0 49 89 7B E8 48 8B F9 4D 89 63 E0 4D 8B E0 4D 89 6B D8",
                    "48 89 5C 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 8D 6C 24 ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 45 ? 41 0F B6 D8 48 89 55 ? 88 5C 24 ?",
                    "48 89 5C 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 8D AC 24 ? ? ? ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? 80 B9 ? ? ? ? ? 48 8B DA 48 8B F1",
                    "48 89 5C 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 8D AC 24 ? ? ? ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? ? 0F B6 ? 44 88 44 24 ?",
                    "48 89 5C 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 8D 6C 24 ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 45 ? 45 0F B6 F8",
                    "40 55 53 56 57 41 54 41 56 41 57 48 8D AC 24 ? ? ? ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? ? 0F B6 ?",
                    "4C 8B DC 55 49 8D AB ? ? ? ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ?"
                };

                for (const auto& pat : envPatterns) {
                    uint8_t* addr = FindPattern(textStart, textSize, pat);
                    if (addr) {
                        SafePatch<uint8_t>((uintptr_t)addr, 0xC3);
                        break;
                    }
                }
            }

            // 3. 32.11 Signature Bypasses, UTOC TOC validation & Anti-Crash Patches
            if (is3211) {
                // Anti-crash & integrity check bypasses
                SafePatch<uint8_t>(base + 0x537F4A0, 0xC3);
                SafePatch<uint32_t>(base + 0x8E80410, 0x90C3C031); // xor eax, eax; ret; nop
                SafePatch<uint32_t>(base + 0x8E6FE60, 0x90C301B0); // mov al, 1; ret; nop
                SafePatch<uint8_t>(base + 0x8E6C3A8, 0xC3);
                SafePatch<uint8_t>(base + 0x20B0A78, 0xEB);
                SafePatch<uint8_t>(base + 0x8E70033, 0xEB);

                // UTOC signature/TOC patch
                SafePatch<uint32_t>(base + 0x3321458, 0x000001C7);
                SafePatch<uint32_t>(base + 0x3321458 + 4, 0x90C30000);

                // Pak chunk signature check patch
                SafePatch<uint32_t>(base + 0x20C525A, 0x90909090);
                SafePatch<uint16_t>(base + 0x20C525A + 4, 0x9090);

                // Missing signature patch
                SafePatch<uint32_t>(base + 0x20C26E2 + 4, 0x0);

                Config::Log("Authy", "32.11 Signature & UTOC Bypasses Applied\n");
            }

            Config::Log("Authy", "Anti-Exit & Anti-Crash Patches Active\n");
        }
    }
}
