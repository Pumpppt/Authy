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

        static void (*g_RequestExitWithStatusOG)(bool Force, unsigned char Code, wchar_t* CloseReason) = nullptr;

        static void RequestExitWithStatusHook(bool Force, unsigned char Code, wchar_t* CloseReason) {
            // Neutralize exit call — keep the game alive!
            return;
        }

        void Install() {
            uint64_t base = (uint64_t)Globals::MainImageBase;
            if (!base) return;

            MH_Initialize();

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

            // 2. Pattern scan fallback for RequestExitWithStatus across versions
            if (!is3211 && Globals::MainTextBuf && Globals::MainTextSize) {
                static const uint8_t exitSig[] = {
                    0x4C, 0x8B, 0xDC, 0x4B, 0x89, 0x5B, 0x08, 0x49, 0x89, 0x6B, 0x10,
                    0x4B, 0x89, 0x73, 0x18, 0x4B, 0x89, 0x7B, 0x20, 0x43, 0x56, 0x48, 0x83, 0xEC, 0x30, 0x0F, 0xB6, 0xF2
                };
                uint8_t* scanBytes = (uint8_t*)Globals::MainTextBuf;
                size_t sz = Globals::MainTextSize;
                for (size_t i = 0; i < sz - sizeof(exitSig); i++) {
                    if (memcmp(scanBytes + i, exitSig, sizeof(exitSig)) == 0) {
                        void* target = (void*)(scanBytes + i);
                        MH_CreateHook(target, (LPVOID)RequestExitWithStatusHook, (LPVOID*)&g_RequestExitWithStatusOG);
                        MH_EnableHook(target);
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
