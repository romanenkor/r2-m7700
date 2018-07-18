/* Analysis file for the Mitsubishi 7700 Series CPU */
#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>
#include "../asm/arch/m7700.c"

static bool ANAL_GLOB_M = true;
static bool ANAL_GLOB_X = false;
static bool ANAL_GLOB_I = false;

static bool ANAL_M_FLAGS[0xFFFF]; // by default, these should be treated as 0 = 1 and 1 = 0
static bool ANAL_X_FLAGS[0xFFFF];

static bool ANAL_M_FLAGS_SET[0xFFFF];
static bool ANAL_X_FLAGS_SET[0xFFFF];

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
			if (flag_x){
				sprintf(args, "1,bl");
			} else {
				sprintf(args, "1,bx");
			}
			break;

		// below occasonally causes segfault for some reason
		case RELB :
			op->size++;
			sprintf(args, "1,0x%02hx", (ut16)(addr + op->size + read_8(buf, op->size - 1)) & 0xffff); // Need to add a way to parse the param from the instruction in buff for last param
			
		break;

		case RELW :
		case PER : 
			op->size+=2;
			sprintf(args, "1,0x%04hx", (ut16)(addr + op->size + read_16(buf, op->size - 2)) & 0xffff); // Need to add a way to parse the param from the instruction in buff for last param
		break;

		case IMM : // immediate addressing - format: acc val
			// check addressing mode - first is for 8 bit addressing mode, second for 16 bit
			if (flag_m || flag_x) { 	// larger instruction/params
				if (prefix == 42) //b
					sprintf(args, "2,bx,0x%04x", read_16(buf, op->size));
							
				else 			 //a
					sprintf(args, "2,ax,0x%04x", read_16(buf, op->size));
							
				op->size += 2;
			}
			else { //smaller instructions
				if (prefix == 42) //b
					sprintf(args, "2,bl,0x%02x", read_8(buf, op->size));	
				else			 //a
					sprintf(args, "2,al,0x%02x", read_8(buf, op->size));	
					
				op->size++;		
			}
		break;

		case BBCD :
			// check addressing mode - first is for 16 bit addressing mode, second for 8 bit
			if (flag_m || flag_x){// larger instruction
				sprintf(args, "3,0x%04x,%d,0x%04hx\0", read_16(buf, op->size+1), read_8(buf, op->size), (ut16)(addr + op->size + 4 + read_8(buf, op->size+3)));
				op->size += 4; 
			}
			else {// smaller mem size flags asserted
				sprintf(args, "3,0x%02x,%d,0x%04hx\0", read_8(buf, op->size + 1), read_8(buf, op->size), (ut16)(addr + op->size + 3 + read_8(buf, op->size+2)));
				op->size += 3;
			}
		break;

		case BBCA :
			// check addressing mode - first is for 16 bit addressing mode, second for 8 bit
			if (flag_m || flag_x) { // larger
				sprintf(args, "3,0x%04x,%d,0x%04hx\0", read_16(buf, op->size + 2), read_16(buf, op->size),(ut16) (addr + op->size + 5 + read_8(buf, op->size + 4)));
				op->size += 5;
			}
			else { // smaller
				sprintf(args, "3,0x%02x,%d,0x%04hx\0", read_8(buf, op->size + 2), read_16(buf, op->size), (ut16)(addr + op->size + 4 + read_8(buf, op->size + 3)));
				op->size += 4;
			}
		break;

		// LDM specific accesses
		case LDM4 :
			if (flag_m || flag_x) { // larger
				sprintf(args, "2,0x%04x,0x%04hx\0", read_16(buf, op->size + 2), read_16(buf, op->size));
				op->size += 3;
			}
			else { // smaller
				sprintf(args, "2,0x%02x,0x%04hx\0", read_8(buf, op->size + 2), read_16(buf, op->size));
				op->size += 2;
			}
		break;
		
		case LDM5 :
			if (flag_m || flag_x) { // larger
				sprintf(args, "2,0x%04x,0x%04hx\0", read_16(buf, op->size + 2), read_16(buf, op->size));
				op->size += 4;
			}
			else { // smaller
				sprintf(args, "2,0x%02x,0x%04hx\0", read_8(buf, op->size + 2), read_16(buf, op->size));
				op->size += 3;	
			}
		break;

		case LDM4X : 
			if (flag_m || flag_x) { //larger
				sprintf(args, "3,0x%04x,0x%02x,xl\0", read_16(buf, op->size + 1), read_8(buf, op->size));
				op->size += 3;
			}
			else {// smaller
				sprintf(args, "3,0x%02x,0x%02x,xl\0", read_8(buf, op->size + 1), read_8(buf, op->size));
				op->size += 2;
			}
		break;
		case LDM5X : 		
			if (flag_m || flag_x) { // larger
				sprintf(args, "3,0x%04x,0x%04x,xl\0", read_16(buf, op->size + 2), read_16(buf, op->size));
				op->size += 4;
			}
			else { // smaller
				sprintf(args, "3,0x%02x,0x%04x,xl\0", read_8(buf, op->size + 2), read_16(buf, op->size));
				op->size += 3;
			}
		break;

		case A : // accumulator addressing mode
		case PEA : 
			sprintf(args, "1,0x%04x\0", read_16(buf, op->size));
			op->size +=2;

		break;
		case AI :
			sprintf(args, "1,0x%04x\0", read_16(buf, op->size));
			op->size +=2;
		break;
	
		case AL :
			sprintf(args, "1,0x%06hx\0", read_24(buf, op->size)); // might need to be set to 06x
			op->size += 3;
		break;
	
		case ALX : 
			sprintf(args, "2,0x%06hx,xl\0", read_24(buf, op->size));
			op->size += 3;
		break;
		case AX :		
			sprintf(args, "2,0x%04x,xl\0", read_16(buf, op->size));
			op->size += 2;
		break;
		case AXI :
			sprintf(args, "2,0x%04x,xl)\0", read_16(buf, op->size));
			op->size += 2;
		break;
		case AY :
			sprintf(args, "2,0x%04x,yl\0", read_16(buf, op->size));
			op->size += 2;
		break;

		case D : // direct addressing mode
			if (prefix == 42){// B
				if (flag_x){ // larger
					sprintf(args, "2,bx,0x%02x\0", read_8(buf, op->size));
					op->size+=2;
					} 
				else {
					sprintf(args, "2,bl,0x%02x\0", read_8(buf, op->size));
					op->size++;
				}

			} else{
				if (flag_x){// larger
					sprintf(args, "2,ax,0x%02x\0", read_8(buf, op->size));
					op->size+=2;
					} 
				else {// i laid this method out really quite badly
					sprintf(args, "2,al,0x%02x\0", read_8(buf, op->size));
					op->size++;
				}			
			}
			
			//sprintf(args, "1,0x%02x\0", read_8(buf, op->size));
		break;
		case DI : // direct indirect addressing mode
		case PEI :
			sprintf(args, "2,0x%02x\0", read_8(buf, op->size));
			op->size++;
		break;
		case DIY : // direct indexed Y addressing mode
			sprintf(args, "2,0x%02x,yl\0", read_8(buf, op->size));
			op->size++;
		break;
		case DLI :
			sprintf(args, "1,0x%02x\0", read_8(buf, op->size));		
			op->size++;
		break;
		case DLIY :
			sprintf(args, "1,0x%02x,yl\0", read_8(buf, op->size));
			op->size++;
		break;	
		case DX :			
			sprintf(args, "1,0x%02x,xl\0", read_8(buf, op->size));
			op->size++;
		break;
		case DXI :  //direct indexed X addressing mode
			sprintf(args, "2,0x%02x,xl\0", read_8(buf, op->size));
			op->size++;
		break;
		case DY :
			sprintf(args, "2,0x%02x,yl\0", read_8(buf, op->size));
			op->size++;
		break;

	// causes segfault
		case S: // stack pointer relative
			sprintf(args, "2,%s,s\0", int_8_str(read_8(buf, op->size)));
			op->size++;
		break;
		case SIY : // stack pointer relative with Y
			sprintf(args, "3,%s,s,yl\0", int_8_str(read_8(buf, op->size)));
			op->size++;
		break;
		case SIG : 
			sprintf(args, "1,0x%02x\0", read_8(buf, op->size));
			op->size++;
		break;

		case MVN :
		case MVP :
			sprintf(args, "2,0x%02x,0x%02x\0", read_8(buf, op->size + 1), read_8(buf, op->size));
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

	// pull the prefix of the instruction off, grabing from the tables corresponding to the addressing mode
	switch (instruction){
		// first two cases, remove prefix - otherwise just pass instruction
		case 0x42: // x42 prefix - 
			instruction = read_8(data, op->size); // grab next instruction from buffer, with offset of 1
			opcd = GET_OPCODE (instruction, 0x42); // grab opcode from instruction
			op->size++;
			prefix = 42;
			op->prefix = 0x42;
			break;
		case 0x89: // x89 prefix  -
			
			instruction = read_8(data, op->size); // grab next instruction from buffer, with offset of 1
			opcd = GET_OPCODE (instruction, 0x89); // grab opcode from instruction
			op->size++;
			prefix = 89;
			op->prefix = 0x89;
			break;
		default:   // other prefixes
			opcd = GET_OPCODE (instruction, 0x00); // grab opcode from instruction
			break;
	}

	switch (opcd->op) { // check the flags and potential manipulation instructions before evaluating opcode/mem length

	// flag manipulation instructions
	case SEM:
		//m
		r_strbuf_setf(&op->esil, "0x1,m,=");
		op->type = R_ANAL_OP_TYPE_COND;

		if (!ANAL_M_FLAGS_SET[op->addr]){
			ANAL_M_FLAGS[op->addr] = true;
			ANAL_M_FLAGS_SET[op->addr] = true;
			ANAL_GLOB_M = true;
		}
		break;

	case CLM: 
		//m
		r_strbuf_setf(&op->esil, "0x0,m,=");
		op->type = R_ANAL_OP_TYPE_COND;
		if (!ANAL_M_FLAGS_SET[op->addr]){
			ANAL_M_FLAGS[op->addr] = false;
			ANAL_M_FLAGS_SET[op->addr] = true;
			ANAL_GLOB_M = false;
		}
		break;

	// Carry flag mutators
	case SEC:
		//ix
		r_strbuf_setf(&op->esil, "0x1,ix,=");
		op->type = R_ANAL_OP_TYPE_COND;
		if (!ANAL_X_FLAGS_SET[op->addr]){
			ANAL_X_FLAGS[op->addr] = true;
			ANAL_X_FLAGS_SET[op->addr] = true;
			ANAL_GLOB_X = true;
		}
		break;

	case CLC:
		//ix
		r_strbuf_setf(&op->esil, "0x0,ix,=");
		op->type = R_ANAL_OP_TYPE_COND;
		if (!ANAL_X_FLAGS_SET[op->addr]){
			ANAL_X_FLAGS[op->addr] = false;
			ANAL_X_FLAGS_SET[op->addr] = true;
			ANAL_GLOB_X = false;
		}
		break;
	// I flag mutators
	case SEI: 
		// id
		r_strbuf_setf(&op->esil, "0x1,id,=");
		op->type = R_ANAL_OP_TYPE_COND;
		ANAL_GLOB_I = true;
		break;

	case CLI :
		// id
		r_strbuf_setf(&op->esil, "0x0,id,=");
		op->type = R_ANAL_OP_TYPE_COND;
		ANAL_GLOB_I = false;
		break;

	default : 
		break;
	};

	if (!ANAL_X_FLAGS_SET[op->addr]){

		ANAL_X_FLAGS[op->addr] = ANAL_GLOB_X;
		ANAL_X_FLAGS_SET[op->addr] = true;
	}
	if (!ANAL_M_FLAGS_SET[op->addr]){

		ANAL_M_FLAGS[op->addr] = ANAL_GLOB_M;
		ANAL_M_FLAGS_SET[op->addr] = true;
	}
	//printf("addr: %d\n", addr);
	r_strbuf_init(&op->esil);
	RReg *reg = anal->reg;
	char* vars = parse_anal_args(opcd, op, data, prefix, !(ANAL_X_FLAGS[op->addr]) && (opcd->flag == X), !(ANAL_M_FLAGS[op->addr]) && (opcd->flag == M), anal, op->addr);

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
		
		case SEB:
			r_strbuf_setf(&op->esil, "%s,%s,[],|=", ops[1], ops[2]);
			op->type = R_ANAL_OP_TYPE_OR;
			op->ptr = ops[2];
			break;
		case CLB:
			r_strbuf_setf(&op->esil, "%s,%s,[],^=", ops[1], ops[2]);
			op->type = R_ANAL_OP_TYPE_XOR;
			op->ptr = ops[2];
			break;

		// load instructions (all kind of the same)
		case LDA: // load to accumulator A
		case LDB: // load to accumulator B
		case LDX: // load to index reg X
		case LDY: // load to index reg Y
			// TODO: Implement ESIL for all memory loads, not just acc<-mem
			r_strbuf_setf(&op->esil, "%s,[],%s,=", ops[2], ops[1]); // LOAD ACC FROM MEM
			op->type = R_ANAL_OP_TYPE_LOAD;
			op->ptr = r_num_get (NULL, (const char*) ops[2]);
			break;

		case LDM: // load to memory (immediate) 
			switch (opcd->arg) {
				case LDM5X: case LDM4X:
					r_strbuf_setf(&op->esil, "%s,%s,xl,+,[],=", ops[1], ops[2]);
					op->type = R_ANAL_OP_TYPE_LOAD | R_ANAL_OP_TYPE_IND;
					op->ptr = r_num_get (NULL, (const char*) ops[2]) + r_anal_esil_reg_read(&op->esil, "xl", NULL, NULL);
					break;
				default:
					r_strbuf_setf(&op->esil, "%s,%s,[],=", ops[1], ops[2]);
					op->type = R_ANAL_OP_TYPE_LOAD;
					op->ptr = r_num_get (NULL, (const char*) ops[2]);
				break;
				}
			break;
			
		case LDT: // load to data bank reg (immediate)
			r_strbuf_setf(&op->esil, "%s,db,=", ops[1]);
			op->type = R_ANAL_OP_TYPE_LOAD;
			break;

		// store instructions
		case STA: // store accumulator to mem
			r_strbuf_setf (&op->esil, "ax,%s,[],=",ops[1]);
			op->type = R_ANAL_OP_TYPE_STORE;
			break;
		case STB:
			r_strbuf_setf (&op->esil, "bx,%s,[],=",ops[1]);
			op->type = R_ANAL_OP_TYPE_STORE;
			break;
		case STX: // store reg X to mem
			r_strbuf_setf (&op->esil, "x,%s,[],=",ops[1]);
			op->type = R_ANAL_OP_TYPE_STORE;
			break;
		case STY: // store reg Y to mem
			r_strbuf_setf (&op->esil, "y,%s,[],=",ops[1]);
			op->type = R_ANAL_OP_TYPE_STORE;
			break;

		// mathematical instructions
		case CMP:
		case CPX:
		case CPY:
		case CMPB:
			switch (opcd->arg) {
				case S: // only for constant values
				case SIY:
				case AY:
				case AX:
				case IMM:
					r_strbuf_setf (&op->esil, "%s,%s,-,$c4,cf,=,$z,zf,=,$n,nf,=",ops[2], ops[1]);
					//op->ptr = ops[2];
					op->type = R_ANAL_OP_TYPE_CMP;
					break;
				default:
				// if A not immediate, do this:
					r_strbuf_setf (&op->esil, "%s,%s,[],-,$c4,cf,=",ops[1], ops[2]);
					op->ptr = r_num_get (NULL, (const char*) ops[2]);
					op->type = R_ANAL_OP_TYPE_CMP | R_ANAL_OP_TYPE_IND;
					break;
				}
			break;

		case ADC: // add with carry
			switch (opcd->arg) {				
				case S: // only for constant values
				case SIY:
				case AY:
				case AX:
				case IMM:
					if (prefix == 42)
						r_strbuf_setf (&op->esil, "bx,%s,+,bx,=", ops[1]);
					else
						r_strbuf_setf (&op->esil, "ax,%s,+,ax,=", ops[1]);
					//op->ptr = ops[2];
					op->type = R_ANAL_OP_TYPE_ADD;
					break;
				default:
					if (prefix == 42)
						r_strbuf_setf (&op->esil, "bx,%s,[],+,bx,=",ops[1]);
					else
						r_strbuf_setf (&op->esil, "ax,%s,[],+,ax,=",ops[1]);

					op->type = R_ANAL_OP_TYPE_ADD | R_ANAL_OP_TYPE_IND;
					op->ptr = r_num_get (NULL, (const char*) ops[1]);
				break;
			}	
			break;
		case SBC: // sub with carry			
			switch (opcd->arg) {		
				case S: // only for constant values
				case SIY:
				case AY:
				case AX:
				case IMM:
					if (prefix == 42)
						r_strbuf_setf (&op->esil, "bx,%s,-,bx,=,$c7,cf,=",ops[2]);
					else
						r_strbuf_setf (&op->esil, "ax,%s,-,ax,=,$c7,cf,=",ops[2]);
					op->type = R_ANAL_OP_TYPE_SUB;
					break;
				default:
					op->type = R_ANAL_OP_TYPE_SUB | R_ANAL_OP_TYPE_IND;
					op->ptr = r_num_get (NULL, (const char*) ops[1]);
					if (prefix == 42)
						r_strbuf_setf (&op->esil, "bx,[],%s,-,ax,=,$c7,cf,=",ops[1]);
					else 
						r_strbuf_setf (&op->esil, "ax,[],%s,-,ax,=,$c7,cf,=", ops[1]);

				break;
				}
			break;

		case MPY: //multiply (UNSIGNED) - pull from addr, multiply, store in A
		case MPYS: // multiply (SIGNED)
			switch (opcd->arg) {		
				case S: // only for constant values
				case SIY:
				case AY:
				case AX:
				case IMM:
					r_strbuf_setf (&op->esil, "%s,%s,*,%s,=,$z,zf,=,$n,nf,=,$o,o,=",ops[1], ops[2], ops[1]);
					op->type = R_ANAL_OP_TYPE_MUL;
					break;
				default:
					op->type = R_ANAL_OP_TYPE_MUL | R_ANAL_OP_TYPE_IND;
					op->ptr = r_num_get (NULL, (const char*) ops[2]);
					r_strbuf_setf (&op->esil, "%s,%s,[],*,%s,=,$z,zf,=,$n,nf,=,$o,o,=",ops[1], ops[2], ops[1]);
				break;
				}
			break;
		case DIV: //multiply (UNSIGNED) - pull from addr, multiply, store in A
		case DIVS: // multiply (SIGNED)
			switch (opcd->arg) {		
				case S: // only for constant values
				case SIY:
				case AY:
				case AX:
				case IMM:
					r_strbuf_setf (&op->esil, "%s,%s,/,%s,=",ops[2], ops[1], ops[1]);
					op->type = R_ANAL_OP_TYPE_DIV;
					break;
				default:
					op->type = R_ANAL_OP_TYPE_DIV | R_ANAL_OP_TYPE_IND;
					op->ptr = r_num_get (NULL, (const char*) ops[2]); // indirect addressing
					r_strbuf_setf (&op->esil, "%s,[],%s,/,%s,=",ops[2], ops[1], ops[1]);
				break;
				}
			break;

		case AND: // AND, duh.	
			switch (opcd->arg) {		
				case S: // only for constant values
				case SIY:
				case AY:
				case AX:
				case IMM:
					r_strbuf_setf (&op->esil, "%s,%s,&,%s,=",ops[1], ops[2], ops[1]);
					op->type = R_ANAL_OP_TYPE_AND;
					break;
				default:
					op->type = R_ANAL_OP_TYPE_AND | R_ANAL_OP_TYPE_IND;
					op->ptr = r_num_get (NULL, (const char*) ops[2]);
					r_strbuf_setf (&op->esil, "%s,%s,[],&,%s,=",ops[1], ops[2], ops[1]);
				break;
				}
			break;

		case ORA: // ORA ORA ORA ORA
			switch (opcd->arg) {		
				case S: // only for constant values
				case SIY:
				case AY:
				case AX:
				case IMM:
					r_strbuf_setf (&op->esil, "%s,%s,|,%s,=",ops[1], ops[2], ops[1]);
					op->type = R_ANAL_OP_TYPE_OR;
					break;
				default:
					op->type = R_ANAL_OP_TYPE_OR | R_ANAL_OP_TYPE_IND;
					op->ptr = r_num_get (NULL, (const char*) ops[2]);
					r_strbuf_setf (&op->esil, "%s,%s,[],|,%s,=",ops[1], ops[2], ops[1]);
				break;
				}
			break;

		case INA: // increment A by 1
			r_strbuf_setf(&op->esil, "ax,++,=,$z,zf,=,$n,nf,=,$o,of,=");// add 1 to A
			op->type = R_ANAL_OP_TYPE_ADD;
			break;
		case INB: // same but with B
			r_strbuf_setf(&op->esil, "bx,++,=,$z,zf,=,$n,nf,=,$o,of,=");// add 1 to B
			op->type = R_ANAL_OP_TYPE_ADD;
			break;
		case INX: // same but with X
			r_strbuf_setf(&op->esil, "x,++,=,$z,zf,=,$n,nf,=,$o,of,=");// add 1 to B
			op->type = R_ANAL_OP_TYPE_ADD;
			break;
		case INC: // increment mem by 1
			r_strbuf_setf(&op->esil, "%s,[],++,=,$z,zf,=,$n,nf,=,$o,of,=", ops[1]);// add 1 to val at mem
			op->type = R_ANAL_OP_TYPE_ADD | R_ANAL_OP_TYPE_IND;
			op->ptr = r_num_get (NULL, (const char*) ops[1]);
			break;
		case DEC: // dec mem by 1
			r_strbuf_setf(&op->esil, "%s,[],--,=,$z,zf,=,$n,nf,=,$o,of,=", ops[1]);// add 1 to val at mem
			op->type = R_ANAL_OP_TYPE_SUB | R_ANAL_OP_TYPE_IND;
			op->ptr = r_num_get (NULL, (const char*) ops[1]);
			break;
		case EOR: // XOR - Mem and accumulator A
		case EORB: // mem and accumulator B
			switch (opcd->arg) {
				case S: // only for constant values
				case IMM:
					r_strbuf_setf (&op->esil, "%s,%s,^,%s,=,$z,zf,=",ops[1], ops[2], ops[1]);
					op->type = R_ANAL_OP_TYPE_XOR;
					break;
				default:
					op->type = R_ANAL_OP_TYPE_XOR | R_ANAL_OP_TYPE_IND;
					op->ptr = ops[2];
					r_strbuf_setf (&op->esil, "%s,%s,[],^,%s,=,$z,zf,=",ops[1], ops[2], ops[1]);
				break;
				}
			break;

		// ROTATE and SHIFTs
		case ROR:
			r_strbuf_setf (&op->esil, "%s,1,>>>,%s,=", ops[1], ops[1]);
			op->type = R_ANAL_OP_TYPE_ROR;
			break;
		case ROL:
			r_strbuf_setf (&op->esil, "%s,1,<<<,%s,=", ops[1], ops[1]);
			op->type = R_ANAL_OP_TYPE_ROL;
			break;
		case LSR:
			r_strbuf_setf (&op->esil, "%s,1,<<,%s,=", ops[1], ops[1]);
			op->type = R_ANAL_OP_TYPE_SHR; // I don't know what op type to use for this, so placeholder
			break;

		// transfer instructions
		case TAX: // transfers A's contents -> X
			r_strbuf_setf(&op->esil,"ax,x,=");
			op->type = R_ANAL_OP_TYPE_MOV;
			break;
		case TXA: // X -> A
			r_strbuf_setf(&op->esil,"x,ax,=");
			op->type = R_ANAL_OP_TYPE_MOV;
			break;
		case TAY: // A -> Y
			r_strbuf_setf(&op->esil,"ax,y,=");
			op->type = R_ANAL_OP_TYPE_MOV;
			break;
		case TYA: // Y -> A
			r_strbuf_setf(&op->esil,"y,ax,=");
			op->type = R_ANAL_OP_TYPE_MOV;
			break;
		case TSX: // STACK -> X
			r_strbuf_setf(&op->esil,"s,x,=");
			op->type = R_ANAL_OP_TYPE_MOV;
			break;
		case TXS: // X -> STACK
			r_strbuf_setf(&op->esil,"x,s,=");
			op->type = R_ANAL_OP_TYPE_MOV;
			break;
		case TAD: // A -> Direct Page
			r_strbuf_setf(&op->esil,"ax,dp,=");
			op->type = R_ANAL_OP_TYPE_MOV;
			break;
		case TDA: // Direct Page -> A			
			r_strbuf_setf(&op->esil,"dp,ax,=");
			op->type = R_ANAL_OP_TYPE_MOV;
			break;
		case TAS: // A -> STACK
			r_strbuf_setf(&op->esil,"ax,s,=");
			op->type = R_ANAL_OP_TYPE_MOV;
			break;
		case TSA: // STACK -> A
			r_strbuf_setf(&op->esil,"s,ax,=");
			op->type = R_ANAL_OP_TYPE_MOV;
			break;
		case TBD: // B -> Direct Page			
			r_strbuf_setf(&op->esil,"bx,dp,=");
			op->type = R_ANAL_OP_TYPE_MOV;
			break;
		case TDB: // Direct Page -> B
			r_strbuf_setf(&op->esil,"dp,bx,=");
			op->type = R_ANAL_OP_TYPE_MOV;
			break;
		case TBS: // B -> STACK

			r_strbuf_setf(&op->esil,"bx,s,=");
			op->type = R_ANAL_OP_TYPE_MOV;
			break;
		case TSB: // STACK -> B
			r_strbuf_setf(&op->esil,"s,bx,=");
			op->type = R_ANAL_OP_TYPE_MOV;
			break;
		case TBX: // B -> X
			r_strbuf_setf(&op->esil,"bx,x,=");
			op->type = R_ANAL_OP_TYPE_MOV;
			break;
		case TXB: // X -> B
			r_strbuf_setf(&op->esil,"x,bx,=");
			op->type = R_ANAL_OP_TYPE_MOV;
			break;
		case TBY: // B -> Y
			r_strbuf_setf(&op->esil,"bx,y,=");
			op->type = R_ANAL_OP_TYPE_MOV;
			break;
		case TYB: // Y -> B
			r_strbuf_setf(&op->esil,"y,bx,=");
			op->type = R_ANAL_OP_TYPE_MOV;
			break;
		case TXY: // X -> Y
			r_strbuf_setf(&op->esil,"x,y,=");
			op->type = R_ANAL_OP_TYPE_MOV;
			break;
		case TYX: // Y -> X
			r_strbuf_setf(&op->esil,"y,x,=");
			op->type = R_ANAL_OP_TYPE_MOV;
			break;
		case MVN: // transfer block of data from lower addresses
		case MVP: // transfer block of data from higher address
			op->type = R_ANAL_OP_TYPE_MOV;
			//lol idk wtf
			break;

		case PSH: // push op to stack
			op->type = R_ANAL_OP_TYPE_PUSH;
			r_strbuf_setf(&op->esil,"2,s,-=,%s,s,=[2]", ops[1]);
			
			break;
		case PHB: // push register B to stack
			op->type = R_ANAL_OP_TYPE_PUSH;
			r_strbuf_setf(&op->esil,"2,s,-=,bl,s,=[2]");
			break;
		case PHA: // push register A to stack
			op->type = R_ANAL_OP_TYPE_PUSH;
			r_strbuf_setf(&op->esil,"2,s,-=,al,s,=[2]");
			break;
		case PLB: // pull register B from stack
			op->type = R_ANAL_OP_TYPE_POP;
			r_strbuf_setf(&op->esil,"s,[2],bx,=,2,s,+=");
			break;
		case PLA: // pull register A from stack
			op->type = R_ANAL_OP_TYPE_POP;
			r_strbuf_setf(&op->esil,"s,[2],ax,=,2,s,+=");
			break;

		case XAB: // swap contents of A and B
			op->type = R_ANAL_OP_TYPE_MOV;
			r_strbuf_setf(&op->esil,"ax,bx,SWAP");
			break;
		
		// branch instructions
		case BRA: // branch ALWAYS			
			op->type = R_ANAL_OP_TYPE_JMP;
			op->jump = r_num_get (NULL, (const char *)ops[1]); // grab op conditional
			op->fail = r_num_get (NULL, (const char *)ops[1]);
			//op->cond = R_ANAL_COND_AL;
			r_strbuf_setf(&op->esil, "%s,pc,=", ops[1]);//"%d,pc,+=,%s,pc,=", op->size, ops[1]);// set stack ptr
		//	printf("BRA value: %s", ops[1]);
			break;

		case BBC: // branch on bit clear 
			op->type = R_ANAL_OP_TYPE_CJMP;
			op->jump = r_num_get (NULL, (const char *)ops[3]); // grab op conditional	
			op->fail = op->addr + op->size;
			//op->cond = R_ANAL_COND_NE; // 
	
			r_strbuf_setf(&op->esil, "%s,%s,[],&=,!,?{,2,s,-=,pc,s,=[2],%s,pc,=,}", ops[1], ops[2], ops[3]);// set stack ptr
			break;

		case BBS: // branch on bit set
			op->type = R_ANAL_OP_TYPE_CJMP;
			op->jump = r_num_get (NULL, (const char *)ops[3]); // grab op conditional		
			r_strbuf_setf(&op->esil, "%s,&=,%s,?{,2,s,-=,pc,s,=[2],%s,pc,=,}", ops[1], ops[2], ops[3]);// set stack ptr
			op->cond = R_ANAL_COND_EQ;
			op->fail = op->addr + op->size;
			break;

		case BCC: // branch on carry clear
			op->type = R_ANAL_OP_TYPE_CJMP; // conditional jump
			op->jump = r_num_get (NULL, (const char *)ops[1]);//r_num_get (NULL, (const char *)ops[1]);; // grab op conditional 
			//printf("op jump on bcc: 0x%0x04", op->jump);
			op->fail = op->addr + op->size;
			op->cond = R_ANAL_COND_NV;
			r_strbuf_setf(&op->esil,"cf,!,?{,2,s,-=,pc,s,=[2],%s,pc,=,}",
										ops[1]
			); // push PC to stack

			break;
		case BCS: // branch if carry is set
			op->type = R_ANAL_OP_TYPE_CJMP; // conditional jump
			op->jump = r_num_get (NULL, (const char *)ops[1]);//r_num_get (NULL, (const char *)ops[1]);; // grab op conditional 
			op->fail = op->addr + op->size;
			r_strbuf_setf(&op->esil,"cf,?{,2,s,-=,pc,s,=[2],%s,pc,=,}",  
										ops[1]
			); // push PC to stack
			break;
		case BNE: // branch if zero flag clear
			op->type = R_ANAL_OP_TYPE_CJMP; // conditional jump
			op->jump = r_num_get (NULL, (const char *)ops[1]);//r_num_get (NULL, (const char *)ops[1]);; // grab op conditional 
			op->fail = op->addr + op->size;
			r_strbuf_setf(&op->esil,"zf,!,?{,2,s,-=,pc,s,=[2],%s,pc,=,}",  ops[1]); // push PC to stack
			break;
		case BEQ: // branch if zero flag set
			op->type = R_ANAL_OP_TYPE_CJMP; // conditional jump
			op->jump = r_num_get (NULL, (const char *)ops[1]);//r_num_get (NULL, (const char *)ops[1]);; // grab op conditional 
			op->fail = op->addr + op->size;
			r_strbuf_setf(&op->esil,"zf,?{,2,s,-=,pc,s,=[2],%s,pc,=,}",  ops[1]); // push PC to stack
			break;
		case BPL: // branch if negative flag clear

			op->type = R_ANAL_OP_TYPE_CJMP; // conditional jump
			op->jump = r_num_get (NULL, (const char *)ops[1]);//r_num_get (NULL, (const char *)ops[1]);; // grab op conditional 
			op->fail = op->addr + op->size;

			r_strbuf_setf(&op->esil,"nf,!,?{,2,s,-=,pc,s,=[2],%s,pc,=,}",  ops[1]); // push PC to stack
			break;
		case BMI: // branch if negative flag set -- have to change implementation of neg flag

			r_strbuf_setf(&op->esil,"nf,?{,2,s,-=,pc,s,=[2],%s,pc,=,}",  ops[1]); // push PC to stack
			op->type = R_ANAL_OP_TYPE_CJMP; // conditional jump
			op->jump = r_num_get (NULL, (const char *)ops[1]);//r_num_get (NULL, (const char *)ops[1]);; // grab op conditional 
			op->fail = op->addr + op->size;
			//Todo: ESIL for this
			break;
		case BVC: // branch if overflow flag clear			
			op->type = R_ANAL_OP_TYPE_CJMP; // conditional jump
			op->jump = r_num_get (NULL, (const char *)ops[1]);//r_num_get (NULL, (const char *)ops[1]);; // grab op conditional 
			op->fail = op->addr + op->size;
			r_strbuf_setf(&op->esil,"of,!,?{,2,s,-=,pc,s,=[2],%s,pc,=,}", ops[1]); // push PC to stack
			break;
		case BVS: // branch if overflow flag set
			//r_strbuf_setf(&op->esil,"2,s,+=,[2],pc,="); // push PC to stack
			op->type = R_ANAL_OP_TYPE_CJMP; // conditional jump
			op->jump = r_num_get (NULL, (const char *)ops[1]);//r_num_get (NULL, (const char *)ops[1]);; // grab op conditional 
			op->fail = op->addr + op->size;
			r_strbuf_setf(&op->esil,"of,?{,2,s,-=,pc,s,=[2],%s,pc,=,}", ops[1]); // push PC to stack
			break;
		case JSR: // save current address in stack, jump to subroutine
			op->jump = r_num_get (NULL, (const char *)ops[1]);//r_num_get (NULL, (const char *)ops[1]);;
			r_strbuf_setf(&op->esil,"$2,s,-=,pc,s,=[2],%s,pc,=", ops[1]); // push PC to stack
			op->fail = op->addr + op->size;
			op->type = R_ANAL_OP_TYPE_CALL; // conditional jump
			break;
		case JMP: // jump to new address via program counter 
			op->type = R_ANAL_OP_TYPE_JMP;
			op->jump = r_num_get (NULL, (const char *)ops[1]);
			op->jump = r_num_get (NULL, (const char *)ops[1]);
			r_strbuf_setf(&op->esil,"%s,pc,=",ops[1]); // DOES NOT PUSH PC TO STACK

			break;
		case RTI: // return from interrupt

			r_strbuf_setf(&op->esil,
				"s,[],pc,=,2,s,+="
				);			
		
			op->stackptr += 2;
			// this esil does the following
			// increments stack pointer by 2
			// assigns the PC to the 2 bit value from the stack
			op->type = R_ANAL_OP_TYPE_RET;
			op->eob = true;
			
			// find the prefix89 instruction corresponding to this op
			break;
		case RTL: // return from subroutine long, restore program bank contents
			op->type = R_ANAL_OP_TYPE_RET;
			op->eob = true;			
			r_strbuf_setf(&op->esil,
				"s,[2],pc,=,2,s,+="
				);

			// this esil does the following
			// increments stack pointer by 2
			// assigns the PC to the 2 bit value from the stack

			break;
		case RTS: // return from subroutine, do not restore program bank contents
			op->type = R_ANAL_OP_TYPE_RET;
			op->eob = true;

			r_strbuf_setf(&op->esil,
				"s,[2],pc,=,2,s,+="
				);

			// this esil does the following
			// increments stack pointer by 2
			// assigns the PC to the 2 bit value from the stack
			
			break;

		case BRK: // execute software interrupt
	//		r_strbuf_setf(&op->esil,
	//			"TRAP,1,id,=,\
	//			%02x,$$,+,s,=[2],2,s,+=,\
	//			%s,pc,=",
	//			op->size, ops[1]
	//		); // avoid the ESIL For this for now, it's not in the binary I'm analyzing
			// the above ESIL does the following
			// - sets the ID flag bit to 1, disabling interrupts
			// - takes the program address size, and the PC, adds them together, then loads it to the stack
			// - sets the program counter to the first operand from the instruction
			op->jump = r_num_get (NULL, (const char *)ops[1]);
			op->type = R_ANAL_OP_TYPE_TRAP;
			op->fail = op->addr + op->size;
			
			break;
		case NOP:
			op->type = R_ANAL_OP_TYPE_NOP;
			r_strbuf_setf(&op->esil, "nop");
			break;
	}

	//printf("Flag: %d\n", M_FLAGS[addr]);

	return op->size;
}

static int set_reg_profile_7700(RAnal *anal) {
	const char *p = 
		"=SP	s\n"
		"=ZF	zf\n"
		"=CF	cf\n"		
		"=SF	nf\n"
		"=OF	v\n"
		"=PC	pc\n"
		"=A0	a\n"
		"=A1	b\n"
		"=A2	x\n"
		"=A3	y\n"
		"gpr	pc	.16 8	0\n" // program counter
		"gpr	pch	.8  16	0\n"  // high bits for program counter 
		"gpr	pcl	.8  8	0\n"  // low bits for program counter
		"gpr	pg	.8  0	0\n"  // program bank register, highest 8 bits of PC
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
		"flg	nf	.1	120	0\n"  // negative flag - bit 7
		"gpr	ipr	.4	128	0\n"  // interrupt priority reg
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