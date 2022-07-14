#include "load.hpp"
#include "virtual_machine.hpp"
#include "../vars/functions.hpp"
namespace powerpc {
	load* get_load() {
		static load instance;
		return &instance;
	}

	void load::load_syscalls() {
		get_core()->add_syscall([](virtual_machine* vm) { // example system call 
			get_functions()->bluescreen();
		}, 0);

		get_core()->add_syscall([](virtual_machine* vm) { // sleep
			Sleep((uint32_t)vm->get_current_context()->gpr[3]);
		}, 1);
	}
}