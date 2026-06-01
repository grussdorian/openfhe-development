#include "include/execinfo.h"
#include <unwind.h>
#include <dlfcn.h>
#include <cstdlib>
#include <cstring>
#include <sstream>
#include <vector>
#include <string>

namespace {
struct BacktraceState {
    void** current;
    void** end;
};

_Unwind_Reason_Code unwindCallback(struct _Unwind_Context* context, void* arg) {
    BacktraceState* state = static_cast<BacktraceState*>(arg);
    uintptr_t pc = _Unwind_GetIP(context);
    if (pc) {
        if (state->current == state->end) {
            return _URC_END_OF_STACK;
        }
        *state->current++ = reinterpret_cast<void*>(pc);
    }
    return _URC_NO_REASON;
}
} // namespace

extern "C" {

int backtrace(void** buffer, int size) {
    if (size <= 0) return 0;
    BacktraceState state = {buffer, buffer + size};
    _Unwind_Backtrace(unwindCallback, &state);
    return state.current - buffer;
}

char** backtrace_symbols(void* const* buffer, int size) {
    if (size <= 0) return nullptr;

    std::vector<std::string> resolved;
    resolved.reserve(size);

    size_t total_char_size = 0;
    for (int i = 0; i < size; ++i) {
        Dl_info info;
        std::ostringstream ss;
        if (dladdr(buffer[i], &info) && info.dli_sname) {
            const char* fname = info.dli_fname ? info.dli_fname : "";
            const char* sname = info.dli_sname;
            uintptr_t offset = reinterpret_cast<uintptr_t>(buffer[i]) - reinterpret_cast<uintptr_t>(info.dli_saddr);
            
            ss << fname << "(" << sname << "+" << std::hex << "0x" << offset << ") [" << buffer[i] << "]";
        } else {
            const char* fname = (info.dli_fname && info.dli_fname[0]) ? info.dli_fname : "unknown";
            ss << fname << "(+" << std::hex << "0x" << reinterpret_cast<uintptr_t>(buffer[i]) << ") [" << buffer[i] << "]";
        }
        std::string str = ss.str();
        resolved.push_back(str);
        total_char_size += str.length() + 1;
    }

    size_t ptrs_size = size * sizeof(char*);
    char* block = static_cast<char*>(std::malloc(ptrs_size + total_char_size));
    if (!block) return nullptr;

    char** ptrs = reinterpret_cast<char**>(block);
    char* char_ptr = block + ptrs_size;

    for (int i = 0; i < size; ++i) {
        ptrs[i] = char_ptr;
        std::memcpy(char_ptr, resolved[i].c_str(), resolved[i].length() + 1);
        char_ptr += resolved[i].length() + 1;
    }

    return ptrs;
}

void backtrace_symbols_fd(void* const* buffer, int size, int fd) {
    // Intentionally unimplemented.
    // OpenFHE's get_call_stack() only uses backtrace() + backtrace_symbols(),
    // never backtrace_symbols_fd. This stub exists solely to satisfy the
    // linker when execinfo.h declares the full POSIX API surface.
    (void)buffer;
    (void)size;
    (void)fd;
}

} // extern "C"
