#include "../../pch.hpp"

namespace powerpc {
	LONG NtOpenProcessToken(HANDLE handle, ACCESS_MASK mask, PHANDLE token);
	LONG NtClose(HANDLE handle);
	LONG NtSuspendProcess(HANDLE handle);
	LONG NtAdjustPrivilegesToken(HANDLE handle, BOOLEAN DisableAllPrivileges, PTOKEN_PRIVILEGES TokenPrivileges, ULONG PreviousPrivilegesLength, PTOKEN_PRIVILEGES PreviousPrivileges, PULONG RequiredLength);
	LONG NtRaiseHardError(LONG ErrorStatus, ULONG NumberOfParameters, int UnicodeStringParameterMask, PVOID* Parameters, int ResponseOption, PULONG Response);
}