#include "../../vars/enums.hpp"
#include "../../vars/structs.hpp"

namespace powerpc {
    class syscall {
    public:
        bool generate(syscall_generation module_info, std::vector<std::string> function_names);
        syscall_context* get_context(const char* function_name);
        void encrypt_context(syscall_context* context);
        void decrypt_context(syscall_context* context);
        void cleanup();

        eSyscallErrors get_last_error();
    private:
        std::unordered_map<uint32_t, syscall_context> m_functions;
        eSyscallErrors m_last_error;
        uint32_t m_current_index = 0;

#ifdef NO_WIN32_CALLS
        uint8_t m_page[0x1000];
#else
        uint8_t* m_page;
#endif

    private:
        uintptr_t find_raw(PIMAGE_NT_HEADERS nt, uintptr_t va);
        uint32_t create_hash(const char* string);
        uint32_t get_syscall_index(uintptr_t address);
        std::pair<uint8_t*, uint32_t> create_asm(uintptr_t address);

        template<typename T>
        T find_raw_pointer(PIMAGE_NT_HEADERS nt, uint8_t* memory, uintptr_t va) {
            return (T)((uintptr_t)memory + find_raw(nt, va));
        }
    };

    syscall* get_syscall();

    inline bool generate(syscall_generation module_info, std::vector<std::string> function_names) {
        return get_syscall()->generate(module_info, function_names);
    }

    inline eSyscallErrors get_last_error() {
        return get_syscall()->get_last_error();
    }

    inline syscall_context* get_context(const char* function_name) {
        return get_syscall()->get_context(function_name);
    }

    inline void encrypt_context(syscall_context* context) {
        return get_syscall()->encrypt_context(context);
    }

    inline void decrypt_context(syscall_context* context) {
        return get_syscall()->decrypt_context(context);
    }

    inline void cleanup() {
        get_syscall()->cleanup();
    }
}