namespace powerpc {
    enum eSyscallErrors {
        ERROR_MODULE_NAME_EMPTY,
        ERROR_GET_MODULE_HANDLE_FAILED,
        ERROR_GET_FILE_NAME_FAILED,
        ERROR_FAILED_TO_OPEN,
        ERROR_FAILED_DISK_ALLOC,
        ERROR_FAILED_HEADER_CHECK,
        ERROR_MODULE_NOT_LOADED,
        ERROR_NT_HEADER_FAILED,
        ERROR_DATA_DIR_FAILED,
    };

	enum opcode {
		op_cmpli = 10,
		op_cmpi = 11,
		op_li = 14, // same as addi?
		op_lis = 15,
		op_sc = 17,
		op_b = 18,
		op_bc = 16,
		op_bundle_19 = 19, // branches
		op_bundle_31 = 31,
		op_lwz = 32,
		op_stw = 36,
		op_stwu = 37,
		op_stb = 38,
		op_ld = 58,
	};

	enum extended_opcode {
		eop_none = -1,
		eop_cmp = 0,
		eop_cmpl = 32,
		eop_add = 266,
		eop_or = 444,
		eop_bclr = 16,
		eop_mtspr = 467,
		eop_mfspr = 339,
	};

	enum iteration_reason {
		it_ok,
		it_continue,
		it_return,
	};
}