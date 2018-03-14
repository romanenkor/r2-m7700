#include <string.h>
#include <r_asm.h>
#include <r_lib.h>

#define OPS 15 // placeholder for number of ops, will implement later

static const  char *ops[OPS * 2] = {

	//TODO: include ops/params
};

/* Main disassembly func */
static int disassemble(RAsm *a, RAsmOp *op, ut8 *buf, ut64 len) {

	char arg[32];

	int idx = (buf[0] & 0x0f) * 2;

	op->size = 2;

}

/* Structure of exported functions/data (used in R2) */
RAsmPlugin r_asm_plugin_m7700 = {

	.name = "m7700",
	.desc = "Disassembly plugin for Mitsubishi M7700 Arch",
	.arch = "m7700",
	.init = NULL,
	.fini = NULL,
	.disassemble = &disassemble,
	.modify = NULL,
	.assemble = NULL
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {

	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_m7700
};
#endif

