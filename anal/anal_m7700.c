/* Analysis file for the Mitsubishi 7700 Series CPU */

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>
#include "../asm/arch/m7700.c"
#include "m7700_parser.c"

enum {
	I, /*IGNORE BIT*/
	M, /*M and X allow for selecting between word/byte	*/
	X  /* operations, decreasing instruction size		*/
};

static int m7700_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *b, int len) {

	if (op == NULL)
		return 1;

	/* TODO: fully implement opcodes for the whole lib 
		Figure out how to handle the m and x flags for the device
	
	*/

	memset(op, 0, sizeof(RAnalOp));
	
	op->addr = addr;
	op->size = 2;
}

struct r_anal_plugin_t r_anal_plugin_m7700 = {

	.name = "m7700",
	.desc = "Disassembly plugin for Mitsubishi M7700 Arch",
	.arch = "m7700",
	.bits = 16,
	.init = NULL,
	.fini = NULL,
	.op = &m7700_op,
	.set_reg_profile = NULL,
	.fingerprint_bb = NULL,
	.fingerprint_fcn = NULL,
	.diff_bb = NULL,
	.diff_fcn = NULL,
	.diff_eval = NULL
};