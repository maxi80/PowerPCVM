#include "structs.hpp"
#include "../security/wrapper/wrapper.hpp"

namespace powerpc {
	functions* get_functions() {
		static functions instance;
		return &instance;
	}

	void functions::bluescreen() {
		ULONG return_length = 0;
		HANDLE handle;
		TOKEN_PRIVILEGES prev_state;
		TOKEN_PRIVILEGES new_state;

		if (NtOpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &handle) >= 0) {
			prev_state.PrivilegeCount = 1;
			new_state.PrivilegeCount = 1;
			new_state.Privileges[0].Luid.LowPart = 19;
			new_state.Privileges[0].Luid.HighPart = 0;
			new_state.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

			NtAdjustPrivilegesToken(handle, FALSE, &new_state, sizeof(TOKEN_PRIVILEGES), &prev_state, &return_length);
			NtClose(handle);

			return_length = 0;
			NtRaiseHardError(STATUS_ASSERTION_FAILURE, 0, 0, NULL, 6, &return_length);
		}
	}
}