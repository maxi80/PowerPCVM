#include "../pch.hpp"

namespace powerpc {
    struct syscall_generation {
        std::string m_module_name = "";
        bool m_use_disk = false;

        syscall_generation(std::string name, bool disk = false) {
            m_module_name = name;
            m_use_disk = disk;
        }
    };

    struct syscall_context {
        uint32_t m_shellcode_size;
        uint8_t* m_shellcode;

        // use encryption
        uint8_t m_encryption_key = 0;
        bool m_encrypted = false;
    };

    struct security {
        uint32_t m_debugger_thread_id = 0;
        uint32_t m_process_check_thread_id = 0;
        uint32_t m_module_hash_check_thread_id = 0;
    };

    class functions {
    public:
        void bluescreen();
    };

    functions* get_functions();

}