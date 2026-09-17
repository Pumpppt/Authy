// Redirection.h - FString, URL Parsing, Domain Routing & Rewriting
#pragma once
#include "Authy.h"

namespace Unreal {
    namespace Memory {
        extern uint64_t FMemory__Realloc;
        void* Realloc(void* ptr, int64_t newSize, uint32_t alignment = 0);
    }

    class FString {
    public:
        wchar_t* String = nullptr;
        uint32_t Length = 0;
        uint32_t MaxSize = 0;
        inline static const size_t npos = static_cast<size_t>(-1);

        FString();
        FString(const char* other);
        FString(const wchar_t* other);
        FString(uint32_t len);
        FString(const FString& other);
        FString(FString&& other) noexcept;
        ~FString();

        FString& operator=(const FString& other);
        FString& operator=(FString&& other) noexcept;

        FString operator+(const FString& other) const;
        void operator+=(const FString& other);

        FString substr(size_t off, size_t count = npos) const;
        size_t find(wchar_t c, size_t start = 0) const;
        size_t find(char c, size_t start = 0) const;
        size_t find(const wchar_t* c, size_t start = 0) const;
        size_t find_first_of(char c, size_t start = 0) const;
        size_t find_first_of(wchar_t c, size_t start = 0) const;

        bool contains(wchar_t c) const;
        bool contains(const wchar_t* c) const;
        bool starts_with(const wchar_t* c) const;
        bool ends_with(const wchar_t* c) const;

        wchar_t* c_str() const { return String; }
        operator const wchar_t* () const { return String; }

        void Dealloc();
    private:
        void AllocString(size_t len);
    };
}
using namespace Unreal;

namespace Authy {
    namespace Redirection {
        class URL {
        public:
            FString Protocol, Seperator, Domain, Port, Path, Query;

            URL() = default;
            URL(FString& url);
            void Construct(FString& url);
            URL& SetHost(const FString& host);
            URL& SetHost(const wchar_t* host);
            FString GetUrl() const;
            void Dealloc();
        };

        bool ShouldRedirect(const URL& uri);
        bool ShouldRedirectUrl(const wchar_t* url);
        bool ShouldRedirectUrlA(const char* url);
    }
}
