/* Analysis file for the Mitsubishi 7700 Series CPU */

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>
//#include "../asm/asm_m7700.c"
#include "../asm/arch/m7700.c"
//#include "m7700_parser.c"

static int reg_read(RAnalEsil *esil, const char *regname, ut64 *num) {
	RRegItem *reg = r_reg_get (esil->anal->reg, regname, -1);
	if (reg) {
		if (num)
			*num = r_reg_get_value (esil->anal->reg, reg);
		return 1;
	}
	return 0;
}

static int reg_write(RAnalEsil *esil, const char *regname, ut64 num) {
	RRegItem *reg = r_reg_get (esil->anal->reg, regname, -1);
	if (reg) {
		if (num)
			r_reg_set_value (esil->anal->reg, reg,num);
		return 1;
	}
	return 0;
}

static int m7700_anal_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len) {

	if (op == NULL)
		return 0;

 	r_strbuf_init (&op->esil); 
	OpCode* opcd;
	memset(op, 0, sizeof(RAnalOp));

	ut8 instruction = read_8(data, 0); // grab the instruction from the r_asm method
	// pull the prefix of the instruction off, grabing from the tables corresponding to the addressing mode
	switch (instruction){
		// first two cases, remove prefix - otherwise just pass instruction
		case 0x42: // x42 prefix - 
	//		sprintf(dest, "b"); // b reg prefix;
			instruction = read_8(data, 1); // grab next instruction from buffer, with offset of 1
			opcd = GET_OPCODE (instruction, 0x42); // grab opcode from instruction
			op->size++;
			//a->pc++;
			break;
		case 0x89: // x89 prefix  -
			
			instruction = read_8(data, 1); // grab next instruction from buffer, with offset of 1
			opcd = GET_OPCODE (instruction, 0x89); // grab opcode from instruction
			op->size++; 
			//a->pc++;
			break;
		default:   // other prefixes
	//		sprintf(dest, "a");
			opcd = GET_OPCODE (instruction, 0x00); // grab opcode from instruction
			break;
	}
	op->id = opcd->op;
	op->addr = addr;
	op->size = 1;
	op->type = R_ANAL_OP_TYPE_UNK;
	op->nopcode = 1;
	op->jump = -1;
	op->fail = -1;
	op->ptr = -1;
	op->family = R_ANAL_OP_FAMILY_CPU;
	op->eob = false;

	r_strbuf_init(&op->esil);
	RReg *reg = anal->reg;

	// tmp registers for writing to
	ut16 op1 = 0x0;
	ut16 op2 = 0x0;
	ut16 op3 = 0x0;

	switch (opcd->op) {
	
		// load instructions
		case LDA: // load to accumulator
			//r_strbuf_setf(&op->esil, "%s,[],%s,=,", read_16(data, op->size), "A");
			op->type = R_ANAL_OP_TYPE_LOAD;
			break;
		case LDM: // load to memory
			//r_strbuf_setf(&op->esil, "%s,[],%s,=,", read_16(data, op->size), "0x6000");
			op->type = R_ANAL_OP_TYPE_LOAD;
			break;
		case LDT: // load to data bank reg
			//r_strbuf_setf(&op->esil, "%s,[],%s,=,", read_16(data, op->size), "DB");
			op->type = R_ANAL_OP_TYPE_LOAD;
			break;
		case LDX: // load to index reg X
			//r_strbuf_setf(&op->esil, "%s,[],%s,=,", read_16(data, op->size), "X");
			op->type = R_ANAL_OP_TYPE_LOAD;
			
			break;
		case LDY: // load to index reg Y
			//r_strbuf_setf(&op->esil, "%s,[],%s,=,", read_16(data, op->size), "Y");
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

static int set_reg_profile_7700(RAnal *anal) {
	const char *p = 
		"=PC	pc\n"
		"=SP	s\n"
		"=ZF	zf\n"
		"=OF	v\n"
		"=NF	n\n"
		"gpr	pc	.24 0	0\n" // program counter
		"gpr	pg	.8  16	0\n"  // program bank register, high 8 bits of PC
		"gpr	pch	.8  8	0\n"  // high bits for program counter 
		"gpr	pcl	.8  0	0\n"  // low bits for program counter 
		"gpr	s	.16 24	0\n" // stack pointer
		"gpr	ax	.16 40	0\n" // accumulator A
		//"gpr    ah      .8  8  0\n"  // high 8 bits of A - remains unchanged when M flag set
		"gpr	al	.8  40	0\n"  // low 8 bits of A
		"gpr	bx	.16 56	0\n" // accumulator B
		//"gpr    bh      .8  8  0\n"  // high 8 bits of B
		"gpr	bl	.8  56	0\n"  // low 8 bits of B
		"gpr	x	.16  72	0\n"  // index register X 
		"gpr	xl	.8  72	0\n"  // low bits for index register X - active when X flag set		
		"gpr	y	.16  88	0\n"  // index register Y 
		"gpr	yl	.8  88	0\n"  // low bits for index register Y - active when X flag set
		"gpr	db	.8	96	0\n"  // data bank register
		"gpr	dpr	.16	104	0\n"  // direct page register
		"gpr	ps	.8	120	0\n"  // processor status register
		"flg	cf	.1	127	0\n"  // carry flag - bit 0 of PS
		"flg	zf	.1	126	0\n"  // zero flag - bit 1 of PS
		"flg	id	.1	125	0\n"  // interrupt disable flag - bit 2
		"flg	dm	.1	124	0\n"  // decimal mode flag - bit 3
		"flg	x	.1	123	0\n"  // index register length flag - bit 4
		"flg	m	.1	122	0\n"  // data length flag - bit 5
		"flg	v	.1	121	0\n"  // overflow flag	- bit 6
		"flg	n	.1	120	0\n"  // negative flag - bit 7
		"gpr	ipr	.3	128	0\n"  // interrupt priority reg
		;
	return r_reg_set_profile_string (anal->reg, p);
}

static int esil_m7700_init (RAnalEsil *esil) {
  return true;
}


static int esil_m7700_fini (RAnalEsil *esil) {
  return true;
}


struct r_anal_plugin_t r_anal_plugin_m7700 = {
	.name = "m7700",
	.desc = "Disassembly plugin for Mitsubishi M7700 Arch",
	.license = "None",
	.arch = "m7700",
	.bits = 16,
	.esil=true,
	.op = &m7700_anal_op,
	.set_reg_profile = &set_reg_profile_7700,
	.init = &esil_m7700_init,
	.fini = &esil_m7700_fini,
	.fingerprint_bb = NULL,
	.fingerprint_fcn = NULL,
	.diff_bb = NULL,
	.diff_fcn = NULL,
	.diff_eval = NULL
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
  .type = R_LIB_TYPE_ANAL,
  .data = &r_anal_plugin_m7700,
  .version = R2_VERSION
};
#endif