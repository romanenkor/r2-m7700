/* Analysis file for the Mitsubishi 7700 Series CPU */

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>
//#include "../asm/asm_m7700.c"
#include "../asm/arch/m7700.c"
//#include "m7700_parser.c"

RStack* stack;// global stack object from the API

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

//  return the current value of a status flag
static ut16 read_flag_value(const char* flag_name, RAnal *anal){
	
  return r_reg_get_value(anal->reg, r_reg_get(anal->reg, flag_name, -1));
}

static char* parse_anal_args(OpCode *opcd, RAnalOp *op, const unsigned char *buf, int prefix, bool flag_x, bool flag_m, RAnal* a, ut64 addr){

	char* args = (char*)(malloc(sizeof(char*) * 60));	// alloc bufspace

	switch (opcd->arg) {

		case IMP : // implied addressing mode - single instruction addressed to int. register
			sprintf(args, "0");
			break;

	// accumulator register used
		case ACC :
			if (flag_x){

				sprintf(args, "1,al");
			} else {

				sprintf(args, "1,ax");
			}
			break;
		case ACCB :
			if (!flag_x){

				sprintf(args, "1,bl");
			} else {

				sprintf(args, "1,bx");
			}
			break;

		// below occasonally causes segfault for some reason
		case RELB :
			op->size++;
			sprintf(args, "1,0x%04x", (addr + op->size + read_8(buf, 1)) & 0xffff); // Need to add a way to parse the param from the instruction in buff for last param
		break;

		case RELW :
		case PER : 
			op->size+=2;
			sprintf(args, "1,0x%06x", (addr + op->size + read_16(buf, 1)) & 0xffff); // Need to add a way to parse the param from the instruction in buff for last param
		break;

		case IMM : // immediate addressing - format: acc val

			// check addressing mode - first is for 16 bit addressing mode, second for 8 bit
			if ((flag_m) || (flag_x)) {
				if (prefix == 42)//b
					sprintf(args, "2,bx,#0x%04x", read_16(buf, op->size));			
				else			 //a
					sprintf(args, "2,ax,#0x%04x", read_16(buf, op->size));			
				op->size += 2;
			}
			else { // smaller instruction/params
				if (prefix == 42)//b
					sprintf(args, "2,bl,#0x%02x", read_8(buf, op->size));			
				else			 //a
					sprintf(args, "2,al,#0x%02x", read_8(buf, op->size));			
				op->size++;
			}
		break;

		case BBCD :
			// check addressing mode - first is for 16 bit addressing mode, second for 8 bit
			if (flag_m || flag_x){ //larger flags asserted
				op->size += 4;
				sprintf(args, "3,0x%04x,0x%02x,%06x\0", read_16(buf, 2), read_8(buf, 1), (addr + op->size + read_8(buf, 4)));
				//op->size += 4;
			}
			else {// smaller
				op->size += 3;
				sprintf(args, "3,0x%02x,0x%02x,%06x\0", read_8(buf, 2), read_8(buf, 1), (addr + op->size + read_8(buf, 3)));
			}
		break;

		case BBCA :
			// check addressing mode - first is for 16 bit addressing mode, second for 8 bit
			if (flag_m || flag_x) { // larger
				op->size += 5;
				sprintf(args, "3,%04x,%04x,%06x\0", read_16(buf, 3), read_16(buf, 1), (addr + op->size + read_8(buf, 5)));
			}
			else { // smaller
				op->size += 4;
				sprintf(args, "3,%02x,%04x,%06x\0", read_8(buf, 3), read_16(buf, 1), (addr + op->size + read_8(buf, 4)));
			}
		break;

		case LDM4 :
			if (flag_m || flag_x) {
				sprintf(args, "2,%04x,%04x\0", read_16(buf, 3), read_16(buf, 1));
				op->size += 3;
			}
			else {
				sprintf(args, "2,%02x,%04x\0", read_8(buf, 3), read_16(buf, 1));
				op->size += 2;
			}
		break;
		
		case LDM5 :
			if (flag_m || flag_x) {
				sprintf(args, "2,%04x,%04x\0", read_16(buf, 2), read_16(buf, 1));
				op->size += 4;
			}
			else {
				sprintf(args, "2,%04x,%02x\0", read_16(buf, 2), read_8(buf, 1));
				op->size += 3;
			}
		break;

		case LDM4X : 
			if (flag_m || flag_x) {
				sprintf(args, "3,%04x,%02x,xl\0", read_16(buf, 2), read_8(buf, 1));
				op->size += 3;
			}
			else {
				sprintf(args, "3,%02x,%02x,xl\0", read_8(buf, 2), read_8(buf, 1));
				op->size += 2;
			}
		break;
		case LDM5X : 		
			if (flag_m || flag_x) {
				sprintf(args, "3,%04x,%04x,xl\0", read_16(buf, 3), read_16(buf, 1));
				op->size += 4;
			}
			else {
				sprintf(args, "3,%02x,04x,xl\0", read_8(buf, 3), read_16(buf, 1));
				op->size += 3;
			}
		break;
		case A : // accumulator addressing mode
		case PEA : 
			sprintf(args, "1,%04x\0", read_16(buf, 1));
			op->size +=2;
		break;
		case AI :
			sprintf(args, "1,%04x\0", read_16(buf, 1));
			op->size +=2;
		break;
	
		case AL :
			sprintf(args, "1,%08x\0", read_24(buf, 1)); // might need to be set to 06x
			op->size += 3;
		break;
	
		case ALX : 
			sprintf(args, "2,%08x,xl\0", read_24(buf, 1));
			op->size += 3;
		break;
		case AX :
			sprintf(args, "2,%04x,xl\0", read_16(buf, 1));
			op->size += 2;
		break;
		case AXI :
			sprintf(args, "2,%04x,xl)\0", read_16(buf, 1));
			op->size += 2;
		break;
		case AY :
			sprintf(args, "2,%04x,yl\0", read_16(buf, 1));
			op->size += 2;
		break;

		case D : // direct addressing mode
			sprintf(args, "1,%02x\0", read_8(buf, 1));
			op->size++;
		break;
		case DI : // direct indirect addressing mode
		case PEI :
			sprintf(args, "1,%02x\0", read_8(buf, 1));
			op->size++;
		break;
		case DIY : // direct indexed Y addressing mode
			sprintf(args, "2,%02x,yl\0", read_8(buf, 1));
			op->size++;
		break;
		case DLI :
			sprintf(args, "1,%02x\0", read_8(buf, 1));		
			op->size++;
		break;
		case DLIY :
			sprintf(args, "1,%02x,yl\0", read_8(buf, 1));
			op->size++;
		break;	
		case DX :
			sprintf(args, "1,$%02x,xl\0", read_8(buf, 1));
			op->size++;
		break;
		case DXI :  //direct indexed X addressing mode
			sprintf(args, "2,($%02x),xl\0", read_8(buf, 1));
			op->size++;
		break;
		case DY :
			sprintf(args, "2,$%02x,yl\0", read_8(buf, 1));
			op->size++;
		break;

	// causes segfault
		case S: 
			sprintf(args, "2,%s,s\0", int_8_str(read_8(buf, 1)));
			op->size++;
		break;
		case SIY : 
			sprintf(args, "3,%s,S,yl\0", int_8_str(read_8(buf, 1)));
			op->size++;
		break;
		case SIG : 
			sprintf(args, "1,$%02x\0", read_8(buf, 1));
			op->size += 2;
		break;

		case MVN :
		case MVP :
			sprintf(args, "2,$%02x,$%02x\0", read_8(buf, 2), read_8(buf, 1));
			op->size += 2;
		break;	
		default:
			break;
	}

	return args;
}

static int m7700_anal_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len) {

	if (op == NULL)
		return 0;


 	r_strbuf_init (&op->esil); 
	OpCode* opcd;
	memset(op, 0, sizeof(RAnalOp));
	ut16 flag = 0x0;
	int prefix = 0;
	ut8 instruction = read_8(data, 0); // grab the instruction from the r_asm method
	// pull the prefix of the instruction off, grabing from the tables corresponding to the addressing mode
	switch (instruction){
		// first two cases, remove prefix - otherwise just pass instruction
		case 0x42: // x42 prefix - 
			instruction = read_8(data, 1); // grab next instruction from buffer, with offset of 1
			opcd = GET_OPCODE (instruction, 0x42); // grab opcode from instruction
			op->size++;
			prefix = 42;
			break;
		case 0x89: // x89 prefix  -
			
			instruction = read_8(data, 1); // grab next instruction from buffer, with offset of 1
			opcd = GET_OPCODE (instruction, 0x89); // grab opcode from instruction
			op->size++;
			prefix = 89;
			break;
		default:   // other prefixes
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

	char* vars = parse_anal_args(opcd, op, data, prefix, !read_flag_value("ix", anal) && (opcd->flag == X), !read_flag_value("m", anal) && (opcd->flag == M), anal, addr);
	vars = strtok(vars, " ,.-");

	int num_ops = (int) (vars[0] - '0');

	char ops[5][20]; // allocate 5 20 char arrays

	int i = 0; while (vars != NULL)	{
    	strcpy (ops[i], (const char*) vars);
    	vars = strtok (NULL, " ,.-");
		i++;
  	}

	unsigned char* buf;
	free (vars);

	switch (opcd->op) {
	
		// flag manipulation instructions
		case SEM:
			//m
			r_strbuf_setf(&op->esil, "m,1,=");
			op->type = R_ANAL_OP_TYPE_COND;

			break;
		case CLM: 
			//m
			r_strbuf_setf(&op->esil, "m,0,=");
			op->type = R_ANAL_OP_TYPE_COND;
			break;

		// Carry flag mutators
		case SEC:
			//ix
			r_strbuf_setf(&op->esil, "ix,1,=");
			op->type = R_ANAL_OP_TYPE_COND;
			break;

		case CLC:
			//ix
			r_strbuf_setf(&op->esil, "ix,0,=");
			op->type = R_ANAL_OP_TYPE_COND;
			break;

		// I flag mutators
		case SEI: 
			// id
			r_strbuf_setf(&op->esil, "id,1,=");
			op->type = R_ANAL_OP_TYPE_COND;
			break;

		case CLI :
			// id
			r_strbuf_setf(&op->esil, "id,0,=");
			op->type = R_ANAL_OP_TYPE_COND;
			break;

		// load instructions (all kind of the same)
		case LDA: // load to accumulator A
		case LDB: // load to accumulator B
		case LDX: // load to index reg X
		case LDY: // load to index reg Y
			// TODO: Implement ESIL for all memory loads, not just acc<-mem
			r_strbuf_setf(&op->esil, "%s,[],%s,=,", ops[1], ops[2]); // store in accumulator 
			op->type = R_ANAL_OP_TYPE_LOAD;
			break;
		case LDM: // load to memory (immediate)
			r_strbuf_setf(&op->esil, "%s,%s,[],=,", ops[1], ops[2]);
			op->type = R_ANAL_OP_TYPE_LOAD;
			break;
		case LDT: // load to data bank reg (immediate)
			r_strbuf_setf(&op->esil, "%s,db,=", ops[1]);
			op->type = R_ANAL_OP_TYPE_LOAD;
			break;

		// store instructions
		case STA: // store accumulator to mem
		case STX: // store reg X to mem
		case STY: // store reg Y to mem
			r_strbuf_setf (&op->esil, "%s,%s,[],=",ops[1], ops[2]);
			op->type = R_ANAL_OP_TYPE_STORE;
			break;

		// mathematical instructions
		case CMP:
			r_strbuf_setf (&op->esil, "%s,%s,[],-",ops[1], ops[2]);
			op->type = R_ANAL_OP_TYPE_CMP;
			break;

		case ADC: // add with carry
			op->type = R_ANAL_OP_TYPE_ADD;
			r_strbuf_setf (&op->esil, "ax,%s,[],+,ax,=",ops[1]);
			break;

		case SBC: // sub with carry			
			r_strbuf_setf (&op->esil, "ax,%s,[],-,ax,=",ops[1]);
			op->type = R_ANAL_OP_TYPE_SUB;
			break;

		case MPY: //multiply (UNSIGNED) - pull from addr, multiply, store in A
			op->type = R_ANAL_OP_TYPE_MUL;
			r_strbuf_setf (&op->esil, "ax,%s,[],*,ax,=", ops[1]);
			break;

		case MPYS: // multiply (SIGNED)
			op->type = R_ANAL_OP_TYPE_MUL;
			r_strbuf_setf (&op->esil, "ax,%s,[],*,ax,=", ops[1]);
			break;

		case AND: // AND, duh.	
			r_strbuf_setf (&op->esil, "%s,%s,[],&,%s,=", ops[1], ops[2], ops[1]);
			op->type = R_ANAL_OP_TYPE_AND;
			break;

		case ORA: // ORA ORA ORA ORA
			r_strbuf_setf (&op->esil, "%s,%s,[],|,%s,=",ops[1], ops[2], ops[1]);
			op->type = R_ANAL_OP_TYPE_OR;
			break;

		case INA: // increment A by 1
			r_strbuf_setf(&op->esil, "ax,++,=");// add 1 to A
			op->type = R_ANAL_OP_TYPE_ADD;
			break;
		case INB: // same but with B
			r_strbuf_setf(&op->esil, "bx,++,=");// add 1 to B
			op->type = R_ANAL_OP_TYPE_ADD;
			break;
		case INX: // same but with X
			r_strbuf_setf(&op->esil, "x,++,=");// add 1 to B
			op->type = R_ANAL_OP_TYPE_ADD;
			break;
		
		case EOR: // XOR - Mem and accumulator A
		case EORB: // mem and accumulator B
			r_strbuf_setf (&op->esil, "%s,%s,[],^,%s,=",op[1],op[2],op[1] 
				// XOR value at Mem address with the specified accumulator, then put in acc.
			);
			op->type = R_ANAL_OP_TYPE_XOR;
			break;

		// ROTATE and SHIFTs
		case ROR:
			r_strbuf_setf (&op->esil, "%s,1,>>>,%s,=", op[1], op[1]);
			op->type = R_ANAL_OP_TYPE_ROR;
			break;
		case LSR:
			r_strbuf_setf (&op->esil, "%s,1,<<<,%s,=", op[1], op[1]);
			op->type = R_ANAL_OP_TYPE_ROL; // I don't know what op type to use for this, so placeholder
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
			op->type = R_ANAL_OP_TYPE_MOV;
			break;

		case PSH: // push op to stack
			op->type = R_ANAL_OP_TYPE_PUSH;
			r_strbuf_setf(&op->esil,"%s,stk,=[2],2,stk,-=", ops[1]);
			break;
		case PHB: // push register B to stack
			op->type = R_ANAL_OP_TYPE_PUSH;
			r_strbuf_setf(&op->esil,"bl,stk,=[2],2,stk,-=");
			break;
		case PHA: // push register A to stack
			op->type = R_ANAL_OP_TYPE_PUSH;
			r_strbuf_setf(&op->esil,"al,stk,=[2],2,stk,-=");
			break;
		case PLB: // pull register B from stack
			op->type = R_ANAL_OP_TYPE_POP;
			r_strbuf_setf(&op->esil,"2,stk,+=,stk,[2],bl,=");
			break;
		case PLA: // pull register A from stack
			op->type = R_ANAL_OP_TYPE_POP;
			r_strbuf_setf(&op->esil,"2,stk,+=,stk,[2],al,=");
			break;

		case XAB: // swap contents of A and B
			op->type = R_ANAL_OP_TYPE_MOV;
			break;
		
		// branch instructions
		case BRA: // branch ALWAYS
			op->jump = r_num_get (NULL, (const char *)ops[1]); // grab op conditional			
			r_strbuf_setf(&op->esil, "%d,pc,+=,%s,pc,=", op->size, ops[1]);// restore stack pointer
			op->type = R_ANAL_OP_TYPE_JMP;
			op->fail = addr + op->size;

			break;

		case BBC: // branch on bit clear 
		case BBS: // branch on bit set
			op->type = R_ANAL_OP_TYPE_CJMP;
			break;
		case BCC: // branch on carry clear
			op->type = R_ANAL_OP_TYPE_CJMP; // conditional jump
			op->jump = r_num_get (NULL, (const char *)ops[1]);//r_num_get (NULL, (const char *)ops[1]);; // grab op conditional 
			op->fail = addr + op->size;
			r_strbuf_setf(&op->esil,"cf,!,?{,\
											2,s,+=,[2],pc,=,%s,pc,=,\
										}",
										ops[1]
			); // push PC to stack

			break;
		case BCS: // branch if carry is set
			op->type = R_ANAL_OP_TYPE_CJMP; // conditional jump
			op->jump = r_num_get (NULL, (const char *)ops[1]);//r_num_get (NULL, (const char *)ops[1]);; // grab op conditional 
			op->fail = addr + op->size;
			r_strbuf_setf(&op->esil,"cf,?{,\
											2,s,+=,[2],pc,=,%s,pc,=,\
										}",  
										ops[1]
			); // push PC to stack
			break;
		case BNE: // branch if zero flag clear
			op->type = R_ANAL_OP_TYPE_CJMP; // conditional jump
			op->jump = r_num_get (NULL, (const char *)ops[1]);//r_num_get (NULL, (const char *)ops[1]);; // grab op conditional 
			op->fail = addr + op->size;
			r_strbuf_setf(&op->esil,"zf,!,?{,\
											2,s,+=,[2],pc,=,%s,pc,=,\
											}",  ops[1]); // push PC to stack
			break;
		case BEQ: // branch if zero flag set
			op->type = R_ANAL_OP_TYPE_CJMP; // conditional jump
			op->jump = r_num_get (NULL, (const char *)ops[1]);//r_num_get (NULL, (const char *)ops[1]);; // grab op conditional 
			op->fail = addr + op->size;
			r_strbuf_setf(&op->esil,"zf,?{,\
											2,s,+=,[2],pc,=,%s,pc,=,\
											}",  ops[1]); // push PC to stack
			break;
		case BPL: // branch if negative flag clear
		case BMI: // branch if negative flag set -- have to change implementation of neg flag
			op->type = R_ANAL_OP_TYPE_CJMP;
			break;
		case BVC: // branch if overflow flag clear			
			op->type = R_ANAL_OP_TYPE_CJMP; // conditional jump
			op->jump = r_num_get (NULL, (const char *)ops[1]);//r_num_get (NULL, (const char *)ops[1]);; // grab op conditional 
			op->fail = addr + op->size;
			r_strbuf_setf(&op->esil,"v,!,?{,\
											2,s,+=,[2],pc,=,%s,pc,=,\
											}", ops[1]); // push PC to stack
			break;
		case BVS: // branch if overflow flag set
			r_strbuf_setf(&op->esil,"2,s,+=,[2],pc,="); // push PC to stack
			op->type = R_ANAL_OP_TYPE_CJMP; // conditional jump
			op->jump = r_num_get (NULL, (const char *)ops[1]);//r_num_get (NULL, (const char *)ops[1]);; // grab op conditional 
			op->fail = addr + op->size;
			r_strbuf_setf(&op->esil,"v,?{,2,s,+=,[2],pc,=,%s,pc,=,}", ops[1]); // push PC to stack
			break;
		case JSR: // save current address in stack, jump to subroutine
			op->jump = r_num_get (NULL, (const char *)ops[1]);//r_num_get (NULL, (const char *)ops[1]);;
			r_strbuf_setf(&op->esil,"2,s,+=,[2],pc,="); // push PC to stack
			op->fail = addr + op->size;
			op->type = R_ANAL_OP_TYPE_CALL; // conditional jump
			break;
		case JMP: // jump to new address via program counter
			op->type = R_ANAL_OP_TYPE_JMP;
			op->jump = r_num_get (NULL, (const char *)ops[1]);
			op->fail = addr + op->size;
			break;
		case RTI: // return from interrupt

			r_strbuf_setf(&op->esil,
				"2,s,+=,pc\
				,s,=[2]"
				);			// this esil does the following
			// increments stack pointer by 2
			// assigns the PC to the 2 bit value from the stack
			op->type = R_ANAL_OP_TYPE_RET;
			op->delay = 1;
			op->eob = true;
			
			// find the prefix89 instruction corresponding to this op
			break;
		case RTL: // return from subroutine long, restore program bank contents
			
			r_strbuf_setf(&op->esil,
				"2,s,+=,pc\
				,s,=[2]"
				);
			// this esil does the following
			// increments stack pointer by 2
			// assigns the PC to the 2 bit value from the stack
			op->type = R_ANAL_OP_TYPE_RET;
			op->delay = 1;
			op->eob = true;
			
			// find the prefix89 instruction corresponding to this op
			break;
		case RTS: // return from subroutine, do not restore program bank contents

			r_strbuf_setf(&op->esil,
				"s,=[2]\
				,2,s,+=,pc"
				);
			// this esil does the following
			// increments stack pointer by 2
			// assigns the PC to the 2 bit value from the stack
			op->type = R_ANAL_OP_TYPE_RET;
			op->delay = 1;
			op->eob = true;
			
			// find the prefix89 instruction corresponding to this op
			break;

		case BRK: // execute software interrupt
			r_strbuf_setf(&op->esil,
				"1,id,=,\
				%02x,$$,+,s,=[2],2,s,+=,\
				%s,pc,=",
				op->size, ops[1]
			);
			// the above ESIL does the following
			// - sets the ID flag bit to 1, disabling interrupts
			// - takes the program address size, and the PC, adds them together, then loads it to the stack
			// - sets the program counter to the first operand from the instruction
			op->jump = r_num_get (NULL, (const char *)ops[1]);
			op->type = R_ANAL_OP_TYPE_TRAP;
			op->fail = addr + op->size;
			
			break;
		case NOP:
			op->type = R_ANAL_OP_TYPE_NOP;
			r_strbuf_setf(&op->esil, "nop");
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
		"=CF	cf\n"
//		"=NF	n\n"
		"gpr	pc	.16 0	0\n" // program counter
		"gpr	pch	.8  8	0\n"  // high bits for program counter 
		"gpr	pcl	.8  0	0\n"  // low bits for program counter
		"gpr	pg	.8  16	0\n"  // program bank register, high 8 bits of PC
 
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
		"flg	ix	.1	123	0\n"  // index register length flag - bit 4
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
	stack = r_stack_new(8);
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
	.fini = NULL, //&esil_m7700_fini,
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