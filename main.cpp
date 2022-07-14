#include "vm/virtual_machine.hpp"
#include "vm/load.hpp"
#include "backend/payloads.hpp"
#include "security/syscalls/system_calls.hpp"
#include "security/wrapper/wrapper.hpp"
#include "vars/structs.hpp"

namespace powerpc {
	bool load() {
		virtual_machine* machine = get_core()->create_vm();
		security* security;

		get_load()->load_syscalls();

		if (machine) {
			machine->execute(payload_init);

			while (!machine->get_current_context()->complete)
				Sleep(0);

			int status = (int)machine->get_current_context()->gpr[3];
			delete machine;

			switch (status)
			{
			case 1:
				printf("Failed to load security.. (1)");
				return false;

			case 1337:
				security->m_debugger_thread_id = *(uint32_t*)&get_core()->get_ram()[0];
				security->m_process_check_thread_id = *(uint32_t*)&get_core()->get_ram()[4];
				security->m_module_hash_check_thread_id = *(uint32_t*)&get_core()->get_ram()[8];
				return true;
			}
		}

		printf("Failed to load security.. (2)");
		return false;
	}

	int main() {
		load();
	}
}