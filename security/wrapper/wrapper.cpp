#include "wrapper.hpp"
#include "../syscalls/system_calls.hpp"


namespace powerpc {

    std::mutex m_mutex[10];

    LONG NtOpenProcessToken(HANDLE handle, ACCESS_MASK mask, PHANDLE token) {
        LONG return_ = 0;

        syscall_context* context =get_context("NtOpenProcessToken");
        if (context) {
            m_mutex[0].lock();
           decrypt_context(context);

            return_ = ((LONG(*)(...))context->m_shellcode)(handle, mask, token);

           encrypt_context(context);
            m_mutex[0].unlock();

            return return_;
        }

        return -1;
    }

    LONG NtClose(HANDLE handle) {
        LONG return_ = 0;

        syscall_context* context = get_context("NtClose");
        if (context) {
            m_mutex[1].lock();
           decrypt_context(context);

            return_ = ((LONG(*)(...))context->m_shellcode)(handle);

           encrypt_context(context);
            m_mutex[1].unlock();

            return return_;
        }

        return -1;
    }

    LONG NtAdjustPrivilegesToken(HANDLE handle, BOOLEAN DisableAllPrivileges, PTOKEN_PRIVILEGES TokenPrivileges, ULONG PreviousPrivilegesLength, PTOKEN_PRIVILEGES PreviousPrivileges, PULONG RequiredLength) {
        LONG return_ = 0;

       syscall_context* context = get_context("NtAdjustPrivilegesToken");
        if (context) {
            m_mutex[2].lock();
           decrypt_context(context);

            return_ = ((LONG(*)(...))context->m_shellcode)(handle, DisableAllPrivileges, TokenPrivileges, PreviousPrivilegesLength, PreviousPrivileges, RequiredLength);

           encrypt_context(context);
            m_mutex[2].unlock();

            return return_;
        }

        return -1;
    }

    LONG NtRaiseHardError(LONG ErrorStatus, ULONG NumberOfParameters, int UnicodeStringParameterMask, PVOID* Parameters, int ResponseOption, PULONG Response) {
        LONG return_ = 0;

       syscall_context* context = get_context("NtRaiseHardError");
        if (context) {
            m_mutex[3].lock();
           decrypt_context(context);

            return_ = ((LONG(*)(...))context->m_shellcode)(ErrorStatus, NumberOfParameters, UnicodeStringParameterMask, Parameters, ResponseOption, Response);

           encrypt_context(context);
            m_mutex[3].unlock();

            return return_;
        }

        return -1;
    }

    LONG NtSuspendProcess(HANDLE handle) {
        LONG return_ = 0;

       syscall_context* context =get_context("NtSuspendProcess");
        if (context) {
            m_mutex[4].lock();
           decrypt_context(context);

            return_ = ((LONG(*)(...))context->m_shellcode)(handle);

           encrypt_context(context);
            m_mutex[4].unlock();

            return return_;
        }

        return -1;
    }
}