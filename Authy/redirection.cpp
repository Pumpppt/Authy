// Redirection.cpp - FString, URL Parsing, and Universal Redirection Engine
#include "pch.h"
#include "Redirection.h"
#include "Config.h"

namespace Unreal {
    namespace Memory {
        uint64_t FMemory__Realloc = 0;

        void* Realloc(void* ptr, int64_t newSize, uint32_t alignment) {
            if (FMemory__Realloc) {
                __try {
                    return ((void* (*)(void*, int64_t, uint32_t))FMemory__Realloc)(ptr, newSize, alignment);
                } __except(EXCEPTION_EXECUTE_HANDLER) {}
            }
            if (newSize == 0) {
                if (ptr) free(ptr);
                return nullptr;
            }
            return realloc(ptr, (size_t)newSize);
        }
    }

    FString::FString() : String(nullptr), Length(0), MaxSize(0) {}

    FString::FString(const char* other) {
        if (other) {
            MaxSize = Length = static_cast<uint32_t>(strlen(other) + 1);
            AllocString(Length);
            if (String) {
                size_t converted = 0;
                mbstowcs_s(&converted, String, Length, other, _TRUNCATE);
            }
        }
    }

    FString::FString(const wchar_t* other) {
        if (other) {
            MaxSize = Length = static_cast<uint32_t>(wcslen(other) + 1);
            AllocString(Length);
            if (String) {
                memcpy(String, other, Length * sizeof(wchar_t));
            }
        }
    }

    FString::FString(uint32_t len) {
        MaxSize = Length = len + 1;
        AllocString(Length);
        if (String) String[0] = L'\0';
    }

    FString::FString(const FString& other) {
        if (other.String) {
            MaxSize = Length = other.Length;
            AllocString(Length);
            if (String) {
                memcpy(String, other.String, Length * sizeof(wchar_t));
            }
        }
    }

    FString::FString(FString&& other) noexcept {
        String = other.String;
        Length = other.Length;
        MaxSize = other.MaxSize;
        other.String = nullptr;
        other.Length = other.MaxSize = 0;
    }

    FString::~FString() {
        Dealloc();
    }

    FString& FString::operator=(const FString& other) {
        if (this != &other) {
            Dealloc();
            if (other.String) {
                MaxSize = Length = other.Length;
                AllocString(Length);
                if (String) {
                    memcpy(String, other.String, Length * sizeof(wchar_t));
                }
            }
        }
        return *this;
    }

    FString& FString::operator=(FString&& other) noexcept {
        if (this != &other) {
            Dealloc();
            String = other.String;
            Length = other.Length;
            MaxSize = other.MaxSize;
            other.String = nullptr;
            other.Length = other.MaxSize = 0;
        }
        return *this;
    }

    FString FString::operator+(const FString& other) const {
        if (!String || !other.String) return *this;
        auto sLen = Length ? Length - 1 : 0;
        auto oLen = other.Length ? other.Length - 1 : 0;
        FString nStr(static_cast<uint32_t>(sLen + oLen));
        if (nStr.String) {
            if (sLen) memcpy(nStr.String, String, sLen * sizeof(wchar_t));
            if (oLen) memcpy(nStr.String + sLen, other.String, oLen * sizeof(wchar_t));
            nStr.String[nStr.Length - 1] = 0;
        }
        return nStr;
    }

    void FString::operator+=(const FString& other) {
        if (!String || !other.String) return;
        auto sLen = Length ? Length - 1 : 0;
        auto oLen = other.Length ? other.Length - 1 : 0;
        Length = static_cast<uint32_t>(sLen + oLen + 1);
        auto* oldStr = String;
        AllocString(Length);
        if (String) {
            if (sLen) memcpy(String, oldStr, sLen * sizeof(wchar_t));
            if (oLen) memcpy(String + sLen, other.String, oLen * sizeof(wchar_t));
            String[Length - 1] = 0;
        }
        if (oldStr) free(oldStr);
    }

    FString FString::substr(size_t off, size_t count) const {
        if (!String || off >= Length) return FString();
        if (count == npos || off + count > Length - 1) count = Length - 1 - off;
        FString nStr(static_cast<uint32_t>(count));
        if (nStr.String) {
            memcpy(nStr.String, String + off, count * sizeof(wchar_t));
            nStr.String[count] = 0;
        }
        return nStr;
    }

    size_t FString::find(wchar_t c, size_t start) const {
        if (!String) return npos;
        for (uint32_t i = (uint32_t)start; i < Length; i++) {
            if (String[i] == c) return i;
        }
        return npos;
    }

    size_t FString::find(char c, size_t start) const {
        return find(static_cast<wchar_t>(c), start);
    }

    size_t FString::find(const wchar_t* c, size_t start) const {
        if (!String || !c) return npos;
        size_t cLen = wcslen(c);
        if (cLen > Length) return npos;
        for (uint32_t i = (uint32_t)start; i <= Length - cLen; i++) {
            if (memcmp(String + i, c, cLen * sizeof(wchar_t)) == 0) return i;
        }
        return npos;
    }

    size_t FString::find_first_of(char c, size_t start) const {
        return find(static_cast<wchar_t>(c), start);
    }

    size_t FString::find_first_of(wchar_t c, size_t start) const {
        return find(c, start);
    }

    bool FString::contains(wchar_t c) const {
        return find(c) != npos;
    }

    bool FString::contains(const wchar_t* c) const {
        return find(c) != npos;
    }

    bool FString::starts_with(const wchar_t* c) const {
        if (!String || !c) return false;
        size_t cLen = wcslen(c);
        if (cLen > Length) return false;
        return memcmp(String, c, cLen * sizeof(wchar_t)) == 0;
    }

    bool FString::ends_with(const wchar_t* c) const {
        if (!String || !c) return false;
        size_t cLen = wcslen(c);
        if (cLen > Length || Length < 1) return false;
        return memcmp(String + (Length - 1 - cLen), c, cLen * sizeof(wchar_t)) == 0;
    }

    void FString::Dealloc() {
        if (String) {
            free(String);
            String = nullptr;
            Length = MaxSize = 0;
        }
    }

    void FString::AllocString(size_t len) {
        String = (wchar_t*)malloc(len * sizeof(wchar_t));
    }
}

namespace Authy {
    namespace Redirection {
        // Universal redirected host list (DO NOT include cdn2.unrealengine.com)
        static constexpr const wchar_t* g_RedirectedHosts[] = {
            L"ol.epicgames.com",
            L"ol.epicgames.net",
            L"on.epicgames.com",
            L"game-social.epicgames.com",
            L"ak.epicgames.com",
            L"epicgames.dev",
            L"superawesome.com",
            L"akamaized.net",
            L"eosapi.epicgames.com",
            L"epicgames.com"
        };

        // Explicitly blocked hosts (NEVER redirect these)
        static constexpr const wchar_t* g_BlockedHosts[] = {
            L"cdn2.unrealengine.com",
        };

        URL::URL(FString& url) {
            Construct(url);
        }

        void URL::Construct(FString& url) {
            Dealloc();
            auto protoEnd = url.find(L':');
            if (protoEnd == FString::npos) {
                Domain = url;
                return;
            }

            Protocol = url.substr(0, protoEnd);
            size_t protoSize = (url.String && protoEnd + 2 < url.Length &&
                                url.String[protoEnd + 1] == L'/' && url.String[protoEnd + 2] == L'/') ? 3 : 1;
            Seperator = url.substr(protoEnd, protoSize);

            auto domainAndPortStart = url.substr(protoEnd + protoSize);
            auto pathEnd = domainAndPortStart.find_first_of(L'/');
            auto domainAndPort = domainAndPortStart.substr(0, pathEnd);
            auto pathStart = domainAndPortStart.substr(pathEnd != FString::npos ? pathEnd : 0);
            domainAndPortStart.Dealloc();

            auto portOff = domainAndPort.find_first_of(L':');
            Domain = domainAndPort.substr(0, portOff);
            if (portOff != FString::npos) Port = domainAndPort.substr(portOff);
            domainAndPort.Dealloc();

            auto queryOff = pathStart.find_first_of(L'?');
            Path = pathStart.substr(0, queryOff);
            if (queryOff != FString::npos) Query = pathStart.substr(queryOff);
            pathStart.Dealloc();
        }

        URL& URL::SetHost(const FString& host) {
            auto protoEnd = host.find(L':');
            if (protoEnd != FString::npos && host.String && protoEnd + 2 < host.Length) {
                Protocol.Dealloc();
                Protocol = host.substr(0, protoEnd);

                size_t protoSize = (host.String[protoEnd + 1] == L'/' && host.String[protoEnd + 2] == L'/') ? 3 : 1;
                Seperator.Dealloc();
                Seperator = host.substr(protoEnd, protoSize);

                auto domainAndPortStart = host.substr(protoEnd + protoSize);
                auto pathEnd = domainAndPortStart.find_first_of(L'/');
                auto domainAndPort = domainAndPortStart.substr(0, pathEnd);
                domainAndPortStart.Dealloc();

                auto portOff = domainAndPort.find_first_of(L':');
                Domain.Dealloc();
                Domain = domainAndPort.substr(0, portOff);

                Port.Dealloc();
                if (portOff != FString::npos) {
                    Port = domainAndPort.substr(portOff);
                }
                domainAndPort.Dealloc();
            }
            return *this;
        }

        URL& URL::SetHost(const wchar_t* host) {
            FString fHost(host);
            SetHost(fHost);
            return *this;
        }

        FString URL::GetUrl() const {
            FString outStr(
                (Protocol.Length ? Protocol.Length - 1 : 0) +
                (Seperator.Length ? Seperator.Length - 1 : 0) +
                (Domain.Length ? Domain.Length - 1 : 0) +
                (Port.String ? Port.Length - 1 : 0) +
                (Path.Length ? Path.Length - 1 : 0) +
                (Query.String ? Query.Length - 1 : 0)
            );

            if (!outStr.String) return outStr;

            size_t curPos = 0;
            if (Protocol.String && Protocol.Length > 1) {
                memcpy(outStr.String + curPos, Protocol.String, (Protocol.Length - 1) * sizeof(wchar_t));
                curPos += Protocol.Length - 1;
            }
            if (Seperator.String && Seperator.Length > 1) {
                memcpy(outStr.String + curPos, Seperator.String, (Seperator.Length - 1) * sizeof(wchar_t));
                curPos += Seperator.Length - 1;
            }
            if (Domain.String && Domain.Length > 1) {
                memcpy(outStr.String + curPos, Domain.String, (Domain.Length - 1) * sizeof(wchar_t));
                curPos += Domain.Length - 1;
            }
            if (Port.String && Port.Length > 1) {
                memcpy(outStr.String + curPos, Port.String, (Port.Length - 1) * sizeof(wchar_t));
                curPos += Port.Length - 1;
            }
            if (Path.String && Path.Length > 1) {
                memcpy(outStr.String + curPos, Path.String, (Path.Length - 1) * sizeof(wchar_t));
                curPos += Path.Length - 1;
            }
            if (Query.String && Query.Length > 1) {
                memcpy(outStr.String + curPos, Query.String, (Query.Length - 1) * sizeof(wchar_t));
                curPos += Query.Length - 1;
            }
            outStr.String[curPos] = L'\0';
            return outStr;
        }

        void URL::Dealloc() {
            Protocol.Dealloc();
            Seperator.Dealloc();
            Domain.Dealloc();
            Port.Dealloc();
            Path.Dealloc();
            Query.Dealloc();
        }

        bool ShouldRedirect(const URL& uri) {
            if (!uri.Domain.String) return false;

            // Never redirect blocked domains (including cdn2.unrealengine.com)
            for (const auto& blocked : g_BlockedHosts) {
                if (uri.Domain.contains(blocked)) {
                    return false;
                }
            }

            for (const auto& host : g_RedirectedHosts) {
                if (uri.Domain.ends_with(host)) {
                    return true;
                }
            }
            return false;
        }

        bool ShouldRedirectUrl(const wchar_t* url) {
            if (!url) return false;

            // Explicitly DO NOT redirect cdn2.unrealengine.com or blocked hosts
            for (const auto& blocked : g_BlockedHosts) {
                if (wcsstr(url, blocked) != nullptr) return false;
            }

            for (const auto& host : g_RedirectedHosts) {
                if (wcsstr(url, host) != nullptr) return true;
            }
            return false;
        }

        bool ShouldRedirectUrlA(const char* url) {
            if (!url) return false;

            // Explicitly DO NOT redirect cdn2.unrealengine.com
            if (strstr(url, "cdn2.unrealengine.com") != nullptr) return false;
            if (strstr(url, "tracking.epicgames.com") != nullptr) return false;
            if (strstr(url, "telemetry.epicgames.com") != nullptr) return false;
            if (strstr(url, "analytics.epicgames.com") != nullptr) return false;
            if (strstr(url, "ads.superawesome.com") != nullptr) return false;

            static const char* redirectedHostsA[] = {
                "ol.epicgames.com", "ol.epicgames.net", "on.epicgames.com",
                "game-social.epicgames.com", "ak.epicgames.com", "epicgames.dev",
                "superawesome.com", "akamaized.net", "eosapi.epicgames.com", "epicgames.com"
            };

            for (const auto& host : redirectedHostsA) {
                if (strstr(url, host) != nullptr) return true;
            }
            return false;
        }
    }
}
