/* Analysis file for the Mitsubishi 7700 Series CPU */

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>
#include "../asm/asm_m7700.c"
#include "m7700_parser.c"

static int m7700_anal_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len) {

	if (op == NULL)
		return 0;

	/* TODO: fully implement opcodes for the whole lib 
		Figure out how to handle the m and x flags for the device
	
	*/

	memset(op, 0, sizeof(RAnalOp));
	const ut8 instruction = read_8(data, 0); // grab the instruction from the r_asm method
	OpCode * opcd = GET_OPCODE(instruction, instruction);

	op->addr = addr;
	op->size = 2;
	op->type = R_ANAL_OP_TYPE_UNK;
	op->eob = false;

	switch (opcd->op) {
	
		// load instructions
		case LDA: // load to accumulator
		case LDM: // load to memory
		case LDT: // load to data bank reg
		case LDX: // load to index reg X
		case LDY: // load to index reg Y
			op->type = R_ANAL_OP_TYPE_LOAD;
			break;

		// store instructions
		case STA: // store accumulator to mem
		case STX: // store reg X to mem
		case STY: // store reg Y to mem
			op->type = R_ANAL_OP_TYPE_STORE;
			break;

		// transfer instructions
		case TAX: // transfers A's contents -> X
		case TXA: // X -> A
		case TAY: // A -> Y
		case TYA: // Y -> A
		case TSX: // STACK -> X
		case TXS: // X -> STACK
		case TAD: // A -> Direct Page
		case TDA: // Direct Page -> A
		case TAS: // A -> STACK
		case TSA: // STACK -> A
		case TBD: // B -> Direct Page
		case TDB: // Direct Page -> B
		case TBS: // B -> STACK
		case TSB: // STACK -> B
		case TBX: // B -> X
		case TXB: // X -> B
		case TBY: // B -> Y
		case TYB: // Y -> B
		case TXY: // X -> Y
		case TYX: // Y -> X
		case MVN: // transfer block of data from lower addresses
		case MVP: // transfer block of data from higher address
		case PSH: // push content of register to stack
			op->type = R_ANAL_OP_TYPE_LOAD;
			break;
		
		// branch instructions
		case BBC: // branch on bit clear 
		case BBS: // branch on bit set
		case BCC: // branch on carry clear
		case BCS: // branch if carry is set
		case BNE: // branch if zero flag clear
		case BEQ: // branch if zero flag set
		case BPL: // branch if negative flag clear
		case BMI: // branch if negative flag set
		case BVC: // branch if overflow flag clear
		case BVS: // branch if overflow flag set
			op->type = R_ANAL_OP_TYPE_CJMP; // conditional jump
			op->jump = op->addr + 8; 
			break;
		case JSR: // save current address in stack, jump to subroutine
		case JMP: // jump to new address via program counter
			op->type = R_ANAL_OP_TYPE_JMP;
			op->jump = op->addr;
		case RTI: // return from interrupt
		case RTS: // return from subroutine, do not restore program bank contents
		case RTL: // return from subroutine, restore program bank contents
			op->type = R_ANAL_OP_TYPE_RET;
			op->eob = true;
			
			// find the prefix89 instruction corresponding to this op
			break;
		case BRK: // execute software interrupt
			op->type = R_ANAL_OP_TYPE_TRAP;
			break;
		case NOP:
			op->type = R_ANAL_OP_TYPE_NOP;
			break;
		case UNK: // unknown op
			op->type = R_ANAL_OP_TYPE_UNK;

		default:

			break;
	}
	
	return op->size;

}

struct r_anal_plugin_t r_anal_plugin_m7700 = {

	.name = "m7700",
	.desc = "Disassembly plugin for Mitsubishi M7700 Arch",
	.arch = "m7700",
	.bits = 16,
	.init = NULL,
	.fini = NULL,
	.op = &m7700_anal_op,
	.set_reg_profile = NULL,
	.fingerprint_bb = NULL,
	.fingerprint_fcn = NULL,
	.diff_bb = NULL,
	.diff_fcn = NULL,
	.diff_eval = NULL
};