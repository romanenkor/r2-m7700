#include <string.h>
#include <r_asm.h>
#include <r_lib.h>
#include "m7700.h"

#define byte unsigned char

static ut8 read8(const ut8 *data, unsigned int offset) {

	ut8 ret = data[offset];
	return ret;
}

static ut16 read16(const ut8 *data, unsigned int offset) {

	ut16 ret = data[offset];
	return ret | data[offset + 1] << 8;
}

static ut24 read24(const ut8 *data, unsigned int offset) {

	ut24 ret = data[offset];
	ret |= ret | data[offset + 1] << 8;
	return ret | data[offset + 2] << 16;
}

/*
	Reads args from the opcode prefix arrays in the header, based off of prefix

	Each prefix contains func name, the addressing flag bit, and the arg
 */
static OpCode *GET_OPCODE(ut16 instruction, byte prefix) {

	return (prefix == 0x89 ? ops89 + instruction : (prefix == 0x42 ? ops42 + instruction : ops + instruction));
}

/* Main disassembly func */
static int disassemble(RAsm *a, RAsmOp *op, ut8 *buf, ut64 len) {

	a->immdisp = true; // force immediate display with # symbol (not ARM, but it uses the same syntax)

	int idx = (buf[0] & 0x0f) * 2;
	
	op->size = 2;

	ut16 instruction;
	OpCode* opcd;
	
	instruction = read8(*buf, 0); // grab instruction from buffer, with offset of 0
	
	Dprintf("Parse Bytes %08x]n", ((ut16 *) buf)[0]);

	// pull the prefix of the instruction off, grabing from the tables corresponding to the addressing mode
	switch (instruction){
		// first two cases, remove prefix - otherwise just pass instruction
		case 0x42: // x42 prefix - 
			instruction = read8(*buf, 0); // grab next instruction from buffer, with offset of 0
			opcd = GET_OPCODE (instruction, 0x42); // grab opcode from instruction
			break;
		case 0x89: // x89 prefix  -
			instruction = read8(*buf, 0); // grab next instruction from buffer, with offset of 0
			opcd = GET_OPCODE (instruction, 0x89); // grab opcode from instruction
			break;
		default:   // other prefixes
			opcd = GET_OPCODE (instruction, 0x00); // grab opcode from instruction
			break;
	}
	
	
	// the idea here is that you write the disassembled string to buf_asm - parsing out the args as you go
	switch (opcd->arg)
	{
	// process the opcode structures
	// switched using their params

	case IMP :
		sprintf(op->buf_asm, "%s", instruction_set[opcd->op]); 
		break;

	// accumulator register used
	case ACC :
		sprintf(op->buf_asm, "%s A", instruction_set[opcd->op]); 
		break;
	case ACCB :
		sprintf(op->buf_asm, "%s B", instruction_set[opcd->op]); 
		break;

	case RELB :
		sprintf(op->buf_asm, "%s %06x (%s)", instruction_set[opcd->op], (a->pc + len + read8(*buf, 1)) & 0xffff, read8(*buf, 1)); // Need to add a way to parse the param from the instruction in buff for last param
		break;

	case RELW :
	case PER : 
		sprintf(op->buf_asm, "%s %06x (%s)", instruction_set[opcd->op], (a->pc + len + read16(*buf, 1)) & 0xffff, read16(*buf, 1)); // Need to add a way to parse the param from the instruction in buff for last param
		break;

	case IMM : // immediate store values
		// check addressing mode - first is for 16 bit addressing mode, second for 8 bit
		if ((opcd->flag == M) || (opcd->flag == X)) {
			sprintf(op->buf_asm, "%s #$%04x", instruction_set[opcd->op], read_16(*buf, 1));
		}
		else {
			sprintf(op->buf_asm, "%s #$%02x", instruction_set[opcd->op], read_8(*buf, 1));
		}
		break;

	case BBCD :
		// check addressing mode - first is for 16 bit addressing mode, second for 8 bit
		if ((opcd->flag == M) || (opcd->flag == X)) {
			sprintf(op->buf_asm, "%s #$%04x, $02x, %06x (%s)", instruction_set[opcd->op], read_16(*buf, 2), read_8(*buf, 1), (a->pc + len + 4 + read_8(*buf, 4)), read_8(*buf, 4));
		}
		else {
			sprintf(op->buf_asm, "%s #$%02x, $02x, %06x (%s)", instruction_set[opcd->op], read_8(*buf, 2), read_8(*buf, 1), (a->pc + len + 3 + read_8(*buf, 3)), read_8(*buf, 3));
		}
		break;

	case BBCA :
		// check addressing mode - first is for 16 bit addressing mode, second for 8 bit
		if ((opcd->flag == M) || (opcd->flag == X)) {
			sprintf(op->buf_asm, "%s #$%04x, $04x, %06x (%s)", instruction_set[opcd->op], read_16(*buf, 3), read_16(*buf, 1), (a->pc + len + 5 + read_8(*buf, 5)), read_8(*buf, 5));
		}
		else {
			sprintf(op->buf_asm, "%s #$%02x, $04x, %06x (%s)", instruction_set[opcd->op], read_8(*buf, 3), read_16(*buf, 1), (a->pc + len + 4 + read_8(*buf, 4)), read_8(*buf, 4));
		}
		break;

	case LDM4 :
		if ((opcd->flag == M) || (opcd->flag == X)) {
			sprintf(op->buf_asm, "%s #$%04x, $04x", instruction_set[opcd->op], read_16(*buf, 3), read_16(*buf, 1));
		}
		else {
			sprintf(op->buf_asm, "%s #$%02x, $04x", instruction_set[opcd->op], read_8(*buf, 3), read_16(*buf, 1));
		}
		break;
		
	case LDM5 :
		if ((opcd->flag == M) || (opcd->flag == X)) {
			sprintf(op->buf_asm, "%s #$%04x, $04x", instruction_set[opcd->op], read_16(*buf, 2), read_8(*buf, 1));
		}
		else {
			sprintf(op->buf_asm, "%s #$%04x, $02x", instruction_set[opcd->op], read_8(*buf, 2), read_8(*buf, 1));
		}
		break;

	case LDM4X : 
		if ((opcd->flag == M) || (opcd->flag == X)) {
			sprintf(op->buf_asm, "%s #$%04x, $02x, X", instruction_set[opcd->op], read_16(*buf, 2), read_8(*buf, 1));
		}
		else {
			sprintf(op->buf_asm, "%s #$%02x, $02x, X", instruction_set[opcd->op], read_8(*buf, 2), read_8(*buf, 1));
		}
		break;
	case LDM5X : 
		if ((opcd->flag == M) || (opcd->flag == X)) {
			sprintf(op->buf_asm, "%s #$%04x, $04x, X", instruction_set[opcd->op], read_16(*buf, 2), read_16(*buf, 1));
		}
		else {
			sprintf(op->buf_asm, "%s #$%02x, $04x, X", instruction_set[opcd->op], read_8(*buf, 3), read_16(*buf, 1));
		}
		break;

	case A :
	case PEA : 
		sprintf(op->buf_asm, "%s $%04x", instruction_set[opcd->op], read_16(*buf, 1));
		break;
	case AI :
		sprintf(op->buf_asm, "%s ($%04x)", instruction_set[opcd->op], read_16(*buf, 1));
		break;
	case AL :
		sprintf(op->buf_asm, "%s $%08x", instruction_set[opcd->op], read_24(*buf, 1)); // might need to be set to 06x
		break;
	case ALX : 
		sprintf(op->buf_asm, "%s $%08x, X", instruction_set[opcd->op], read_24(*buf, 1));
		break;
	case AX :
		sprintf(op->buf_asm, "%s $%04x, X", instruction_set[opcd->op], read_16(*buf, 1));
		break;
	case AXI :
		sprintf(op->buf_asm, "(%s $%04x, X)", instruction_set[opcd->op], read_16(*buf, 1));
		break;
	case AY :
		sprintf(op->buf_asm, "%s $%04x, Y", instruction_set[opcd->op], read_16(*buf, 1));
		break;

	case D :
		sprintf(op->buf_asm, "%s $%02x", instruction_set[opcd->op], read_8(*buf, 1));
		break;
	case DI :
	case PEI :
		sprintf(op->buf_asm, "%s ($%02x)", instruction_set[opcd->op], read_8(*buf, 1));
		break;
	case DIY :
		sprintf(op->buf_asm, "%s ($%02x), Y", instruction_set[opcd->op], read_8(*buf, 1));
		break;
	case DLI :
		sprintf(op->buf_asm, "%s [$%02x]", instruction_set[opcd->op], read_8(*buf, 1));
		break;
	case DLIY :
		sprintf(op->buf_asm, "%s [$%02x], Y", instruction_set[opcd->op], read_8(*buf, 1));
		break;	
	case DX :
		sprintf(op->buf_asm, "%s $%02x, X", instruction_set[opcd->op], read_8(*buf, 1));
		break;
	case DXI : 
		sprintf(op->buf_asm, "%s ($%02x, X)", instruction_set[opcd->op], read_8(*buf, 1));
		break;
	case DY :
		sprintf(op->buf_asm, "%s $%02x, Y", instruction_set[opcd->op], read_8(*buf, 1));
		break;

	case S: 
		sprintf(op->buf_asm, "%s %s", instruction_set[opcd->op], read_8(*buf, 1));
		break;
	case SIY : 
		sprintf(op->buf_asm, "%s %s, S", instruction_set[opcd->op], read_8(*buf, 1));
		break;
	case SIG : 
		sprintf(op->buf_asm, "%s $%02x", instruction_set[opcd->op], read_8(*buf, 1));
		break;

	case MVN :
	case MVP :
		sprintf(op->buf_asm, "%s $%02x, $%02x", instruction_set[opcd->op], read_8(*buf, 2), read_8(*buf, 1));
		break;
	}
}

//Test main func
#ifdef MAIN_ASM
int main(int argc, char **argv) {

	char *c = "move 1 2\n forprep 13 -2";
	int p = 0;
	current_write_prt = malloc(8);
	current_write_index = 0;
	Dprintf("Parsing String: %s\n", c);
	Dprintf("-----------------------\n");
	doParse0(p, parseNextInstruction, c, (int)strlen(c));
	Dprintf("Parsed Characters %i\n", p);
	Dprintf("%d   %08x\n", current_write_index, current_write_prt[current_write_index - 1]);

	Dprintf("------------\n");

	doParse0(p, parseNextInstruction, c, (int)strlen(c));
	Dprintf("Parsed Characters %i\n", p);
	Dprintf("%d   %08x\n", current_write_index, current_write_prt[current_write_index - 1]);

	Dprintf("------------\n");

	RAsmOp *asmOp = (RAsmOp *)malloc(sizeof(RAsmOp));
	RAsm a = (RAsm *)malloc(sizeof(RAsm));
	int advanced = disassemble(a, asmOp, (const char *)current_write_prt, 4);

	Dprintf("%s\n", asmOp->buf_asm);
	disassemble(a, asmOp, (const char *)current_write_prt + advanced, 4);
	Dprintf("%s\n", asmOp->buf_asm);

	free(current_write_prt);
	return 0;
}
#endif	// MAIN_ASM


/* Structure of exported functions/data (used in R2) */
RAsmPlugin r_asm_plugin_m7700 = {

	.name = "m7700",
	.desc = "Disassembly plugin for Mitsubishi M7700 Arch",
	.arch = "m7700",
	.bits = 16,
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