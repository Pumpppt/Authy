// Hooks.h - ProcessRequest, Dynamic SetURL, Libcurl & EOS Interception
#pragma once
#include "Authy.h"
#include "Redirection.h"

namespace Unreal {
    class FCurlHttpRequest {
    public:
        void** VTable;
        static inline int64_t SetURLIdx = 0;
        static inline void** ProcessRequestVT = nullptr;

        FString GetURL();
    };
}

namespace Authy {
    namespace Hooks {
        bool Install();
        void Remove();
    }
}
