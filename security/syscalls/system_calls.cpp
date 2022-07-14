#include "system_calls.hpp"
namespace powerpc {
    bool syscall::generate(syscall_generation module_info, std::vector < std::string > function_names) {
        uint8_t* memory = nullptr;

        if (module_info.m_module_name.empty()) {
            m_last_error = ERROR_MODULE_NAME_EMPTY;
            return false;
        }

        if (module_info.m_use_disk) {
            char path[MAX_PATH];

            // not a full path, attempt to get the module location from memory
            if (module_info.m_module_name.find('\\') == std::string::npos &&
                module_info.m_module_name.find('/') == std::string::npos) {
                if (GetModuleHandleA(module_info.m_module_name.c_str())) {
                    if (!GetModuleFileNameA(GetModuleHandleA(module_info.m_module_name.c_str()), path, MAX_PATH)) {
                        m_last_error = ERROR_GET_FILE_NAME_FAILED;
                        return false;
                    }
                }
                else {
                    m_last_error = ERROR_GET_MODULE_HANDLE_FAILED;
                    return false;
                }
            }
            else {
                strcpy_s(path, module_info.m_module_name.c_str());
            }

            FILE* fp;
            if (!fopen_s(&fp, path, "rb")) {
                fseek(fp, 0, SEEK_END);
                long file_size = ftell(fp);
                fseek(fp, 0, SEEK_SET);

                memory = (uint8_t*)VirtualAlloc(0, file_size, MEM_COMMIT, PAGE_READONLY);
                if (memory) {
                    fread(memory, 1, file_size, fp);
                    fclose(fp);

                    // sanity
                    if (memory[0] != 'M' || memory[1] != 'Z') {
                        m_last_error = ERROR_FAILED_HEADER_CHECK;
                        VirtualFree(memory, 0, MEM_RELEASE);
                        return false;
                    }
                }
                else {
                    m_last_error = ERROR_FAILED_DISK_ALLOC;
                    return false;
                }
            }
            else {
                m_last_error = ERROR_FAILED_TO_OPEN;
                return false;
            }
        }
        else {
            memory = (uint8_t*)GetModuleHandleA(module_info.m_module_name.c_str());
            if (!memory) {
                m_last_error = ERROR_MODULE_NOT_LOADED;
                return false;
            }
        }

        PIMAGE_NT_HEADERS nt_header = RVA2VA(PIMAGE_NT_HEADERS, memory, ((PIMAGE_DOS_HEADER)memory)->e_lfanew);
        if (!nt_header) {
            m_last_error = ERROR_NT_HEADER_FAILED;
            return false;
        }

        PIMAGE_DATA_DIRECTORY data_directory = nt_header->OptionalHeader.DataDirectory;
        if (!data_directory) {
            m_last_error = ERROR_DATA_DIR_FAILED;
            return false;
        }

        std::vector < std::pair < uint32_t, uintptr_t >> to_add;
        uint32_t export_va = data_directory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

        if (module_info.m_use_disk) {
            PIMAGE_EXPORT_DIRECTORY exports = find_raw_pointer < PIMAGE_EXPORT_DIRECTORY >(nt_header, memory, export_va);
            if (exports) {
                uint16_t* name_ordinals = find_raw_pointer < uint16_t* >(nt_header, memory, exports->AddressOfNameOrdinals);
                uint32_t* functions = find_raw_pointer < uint32_t* >(nt_header, memory, exports->AddressOfFunctions);
                uint32_t* names = find_raw_pointer < uint32_t* >(nt_header, memory, exports->AddressOfNames);

                if (name_ordinals && functions && names) {
                    for (uint32_t i = 0; i < exports->NumberOfFunctions; i++) {
                        const char* export_name = find_raw_pointer <
                            const char* >(nt_header, memory, names[i]);
                        if (export_name) {
                            auto it = std::find(begin(function_names), end(function_names), export_name);
                            if (it != end(function_names)) {
                                uint32_t offset = functions[name_ordinals[i]];
                                if (offset) {
                                    uintptr_t export_address = find_raw_pointer < uintptr_t >(nt_header, memory, offset);
                                    if (export_address) {
                                        to_add.push_back({
                                          create_hash(export_name),
                                          export_address
                                            });
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        else {
            PIMAGE_EXPORT_DIRECTORY exports = RVA2VA(PIMAGE_EXPORT_DIRECTORY, memory, export_va);
            if (exports) {
                uint16_t* name_ordinals = RVA2VA(uint16_t*, memory, exports->AddressOfNameOrdinals);
                uint32_t* functions = RVA2VA(uint32_t*, memory, exports->AddressOfFunctions);
                uint32_t* names = RVA2VA(uint32_t*, memory, exports->AddressOfNames);

                if (name_ordinals && functions && names) {
                    for (uint32_t i = 0; i < exports->NumberOfFunctions; i++) {
                        const char* export_name = RVA2VA(const char*, memory, names[i]);
                        if (export_name) {
                            auto it = std::find(begin(function_names), end(function_names), export_name);
                            if (it != end(function_names)) {
                                uint32_t offset = functions[RVA2VA(uint16_t, memory, name_ordinals[i])];
                                if (offset) {
                                    uintptr_t export_address = (uintptr_t)memory + offset;
                                    if (export_address) {
                                        to_add.push_back({
                                          create_hash(export_name),
                                          export_address
                                            });
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // now that the functions we want are added to the local vector "to_add", we can process them and generate some asm.
        // TODO: add custom section with nops, use that instead of allocating
        if (!m_page) {
            m_page = (uint8_t*)VirtualAlloc(0, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        }

        std::vector < uint32_t > to_encrypt;
        for (std::pair < uint32_t, uintptr_t > export_name : to_add) {
            std::pair < uint8_t*, uint32_t > created_asm = create_asm(export_name.second);
            if (created_asm.first) {
                syscall_context context;
                context.m_shellcode_size = created_asm.second;
                context.m_shellcode = (uint8_t*)&m_page[m_current_index];

                // increment the page index
                m_current_index += created_asm.second;;

                // copy the created asm to the shellcode page
                memcpy(context.m_shellcode, created_asm.first, created_asm.second);

                // delete the allocated syscall asm memory
                delete[] created_asm.first;

                // add the syscall context to our function list
                m_functions[export_name.first] = context;
                to_encrypt.push_back(export_name.first);
            }
        }

        // encrypt the page space used in the recent generation
#ifdef USE_ENCRYPTION
        for (uint32_t name_hash : to_encrypt) {
            syscall_context* context = &m_functions[name_hash];
            if (context) {
                encrypt_context(context);
            }
        }
#endif

        if (module_info.m_use_disk) {
            if (memory) {
                VirtualFree(memory, 0, MEM_RELEASE);
            }
        }

        return true;
    }

    syscall_context* syscall::get_context(const char* function_name) {
        syscall_context* context = &m_functions[create_hash(function_name)];
        if (context) {
            return context;
        }

        return nullptr;
    }

    void syscall::encrypt_context(syscall_context* context) {
#ifdef USE_ENCRYPTION
        if (!context->m_encrypted) {
            context->m_encrypted = true;

            // regenerate the encryption key each call
            std::random_device r;
            std::seed_seq seed2{
              r(), r(), r(), r(), r(), r(), r(), r()
            };
            std::mt19937 rng(seed2);
            std::uniform_int_distribution < int > encryption_key(1, 255);

            context->m_encryption_key = (uint8_t)encryption_key(rng);

            for (uint32_t i = 0; i < context->m_shellcode_size; i++) {
                context->m_shellcode[i] ^= context->m_encryption_key;
            }
        }
#endif
    }

    void syscall::decrypt_context(syscall_context* context) {
#ifdef USE_ENCRYPTION
        if (context->m_encrypted) {
            context->m_encrypted = false;

            for (uint32_t i = 0; i < context->m_shellcode_size; i++) {
                context->m_shellcode[i] ^= context->m_encryption_key;
            }
        }
#endif
    }

    std::pair <uint8_t*, uint32_t> syscall::create_asm(uintptr_t address) {
        std::pair < uint8_t*, uint32_t > syscall = {
          nullptr,
          0
        };

#ifdef _WIN64
        syscall.second = 11;
        syscall.first = new uint8_t[syscall.second];

        memcpy(syscall.first, "\x4C\x8B\xD1\xB8\xFF\xFF\xFF\xFF\x0F\x05\xC3", syscall.second);
        *(uint32_t*)(&syscall.first[4]) = get_syscall_index(address);

        return syscall;
#else
        // Windows 7 - SP0/SP1     
        if (IsWindows7OrGreater() && !IsWindows8OrGreater()) {
            syscall.second = 15;
            syscall.first = new uint8_t[syscall.second];

            memcpy(syscall.first, "\xB8\xFF\xFF\xFF\xFF\xBA\xFF\xFF\xFF\xFF\xFF\x12\xC2\x14\x00", syscall.second);
            *(uint32_t*)(&syscall.first[1]) = get_syscall_index(address);
            *(uint32_t*)(&syscall.first[6]) = *(uint32_t*)(address + 6);
            return syscall;
        }

        // Windows 8.0/8.1
        if (IsWindows8OrGreater() && !IsWindows10OrGreater()) {
            syscall.second = 12;
            syscall.first = new uint8_t[syscall.second];

            memcpy(syscall.first, "\xB8\xFF\xFF\xFF\xFF\x8B\xD4\x0F\x34\xC2\x18\x00", syscall.second);
            *(uint32_t*)(&syscall.first[1]) = get_syscall_index(address);

            return syscall;
        }

        // Windows 10, altho identical to above, kept as is in case of future changes
        if (IsWindows10OrGreater()) {
            syscall.second = 12;
            syscall.first = new uint8_t[syscall.second];

            memcpy(syscall.first, "\xB8\xFF\xFF\xFF\xFF\x8B\xD4\x0F\x34\xC2\x18\x00", syscall.second);
            *(uint32_t*)(&syscall.first[1]) = get_syscall_index(address);
            return syscall;
        }
#endif

        return syscall;
    }

    uint32_t syscall::get_syscall_index(uintptr_t address) {
#ifdef _WIN64
        // Windows 7 - SP0/SP1, Windows 8.0/8.1
        if (IsWindows7OrGreater() && !IsWindows10OrGreater()) {
            if (*(uint8_t*)(address + 3) == 0xB8) {
                return *(uint32_t*)(address + 4);
            }

            return 0;
        }

        // Windows 10, altho identical to above, kept as is in case of future changes
        if (IsWindows10OrGreater()) {
            if (*(uint8_t*)(address + 3) == 0xB8) {
                return *(uint32_t*)(address + 4);
            }

            return 0;
        }

#else
        // Windows 7 - SP0/SP1, Windows 8.0/8.1
        if (IsWindows7OrGreater() && !IsWindows10OrGreater()) {
            if (*(uint8_t*)(address) == 0xB8) {
                return *(uint32_t*)(address + 1);
            }

            return 0;
        }

        // Windows 10, altho identical to above, kept as is in case of future changes
        if (IsWindows10OrGreater()) {
            if (*(uint8_t*)(address) == 0xB8) {
                return *(uint32_t*)(address + 1);
            }

            return 0;
        }
#endif

        return 0;
    }

    uint32_t syscall::create_hash(const char* string) {
        uint32_t hash = 0x811c9dc5;

        for (int i = 0; i < strlen(string); ++i) {
            uint8_t value = string[i];
            hash = hash ^ value;
            hash *= 0x1000193;
        }

        return hash;
    }

    uintptr_t syscall::find_raw(PIMAGE_NT_HEADERS nt, uintptr_t va) {
        PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
        for (uint16_t i = 0; i < nt->FileHeader.NumberOfSections; i++) {
            if (va >= section->VirtualAddress && va <= (section->VirtualAddress + section->Misc.VirtualSize)) {
                uintptr_t offset = va - section->VirtualAddress;
                uintptr_t raw_address = section->PointerToRawData + offset;
                return raw_address;
            }

            section++;
        }

        return 0;
    }

    eSyscallErrors syscall::get_last_error() {
        return m_last_error;
    }

    void syscall::cleanup() {
        if (m_page) {
            VirtualFree(m_page, 0, MEM_RELEASE);
        }
    }

    syscall* get_syscall() {
        static syscall instance;
        return &instance;
    }
}