#include <string.h>
#include <r_asm.h>
#include <r_lib.h>
#include "m7700.h"

static ut16 getInstruction(const ut8 *data, unsigned int offset) {

	ut8 data = data[offset];
}

/*
	Reads args from the opcode prefix arrays in the header, based off of prefix

	Each prefix contains func name, the addressing flag bit, and the arg
 */
static OpCode *GET_OPCODE(ut16 instruction, byte prefix) {

	OpCode ret =  (prefix == 0x89 ? ops89 + instruction : prefix == 0x42 ? ops42 + instruction : ops + instruction);
}

/* Main disassembly func */
static int disassemble(RAsm *a, RAsmOp *op, ut8 *buf, ut64 len) {

	int idx = (buf[0] & 0x0f) * 2;
	
	op->size = 2;

	// TODO: implement ut16 and ut8 differentiation for instructions, get from buff

	ut16 instruction;
	OpCode* opcd;
	
	instruction = getInstruction(*buf, 0); // grab instruction from buffer, with offset of 0
	
	Dprintf("Parse Bytes %08x]n", ((ut16 *) buf)[0]);

	// pull the prefix of the instruction off, grabing from the tables corresponding to the addressing mode
	switch (instruction){
		// first two cases, remove prefix - otherwise just pass instruction
		case 0x42: // x42 prefix - 
			instruction = getInstruction(*buf, 1); // grab next instruction from buffer, with offset of 0
			opcd = GET_OPCODE (instruction, 0x42); // grab opcode from instruction
			break;
		case 0x89: // x89 prefix  -
			instruction = getInstruction(*buf, 1); // grab next instruction from buffer, with offset of 0
			opcd = GET_OPCODE (instruction, 0x89); // grab opcode from instruction
			break;
		default:   // other prefixes
			opcd = GET_OPCODE (instruction, 0x00); // grab opcode from instruction
			break;
	}
	
	sprintf(op->buf_asm, "%s", instruction_set[opcd->op]); // print instruction out

	unsigned int ptr = buf + strlen(buf);

	switch (opcd->arg)
	{
	// process the opcode structures
	case IMP :
		break;
	case ACC :
		sprintf(ptr, " A");
		break;
	case ACCB :
		sprintf(ptr, " B");
		break;
	case RELB :
		sprintf(ptr, )
	
	}
}

/* Structure of exported functions/data (used in R2) */
RAsmPlugin r_asm_plugin_m7700 = {

	.name = "m7700",
	.desc = "Disassembly plugin for Mitsubishi M7700 Arch",
	.arch = "m7700",
	.bits= (int[]) {8, 16},
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