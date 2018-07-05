#include <string.h>
#include <r_asm.h>
#include <r_lib.h>
#include "m7700_new.h"

static ut8 read_8(const ut8 *data, unsigned int offset) {

	ut8 ret = data[offset];
	return ret;
}

static ut16 read_16(const ut8 *data, unsigned int offset) {

	ut16 ret = data[offset];
	return ret | data[offset + 1] << 8;
}

static ut24 read_24(const ut8 *data, unsigned int offset) {

	ut24 ret = data[offset];
	ret |= ret | data[offset + 1] << 8;
	return ret | data[offset + 2] << 16;
}

char* int_8_str(unsigned int val)
{
   static char str[20];

   val &= 0xff;

   if(val & 0x80)
      sprintf(str, "-$%x", (0-val) & 0x7f);
   else
      sprintf(str, "$%x", val & 0x7f);

   return str;
}

/*
	Reads args from the opcode prefix arrays in the header, based off of prefix

	Each prefix contains func name, the addressing flag bit, and the arg
 */
static OpCode *GET_OPCODE(ut16 instruction, byte prefix) {

	return (prefix == 0x89 ? ops89 + instruction : (prefix == 0x42 ? ops42 + instruction : ops + instruction));
}

static char* parse_args(OpCode *opcd, RAsmOp *op, ut8 *buf, int prefix, bool flag_x, bool flag_m, RAsm* a){

	char* args = (char*)(malloc(sizeof(char*) * 60));	// alloc bufspace

	switch (opcd->arg) {

		case IMP : // implied addressing mode - single instruction addressed to int. register
			sprintf(args, "0");
			break;

	// accumulator register used
		case ACC :
			if (!flag_x){
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
			sprintf(args, "1,0x%02x", (a->pc + op->size + read_8(buf, op->size - 1)) & 0xffff); // Need to add a way to parse the param from the instruction in buff for last param
		break;

		case RELW :
		case PER : 
			op->size+=2;
			sprintf(args, "1,0x%04x", (a->pc + op->size + read_16(buf, op->size - 2)) & 0xffff); // Need to add a way to parse the param from the instruction in buff for last param
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
				sprintf(args, "3,#0x%04x,0x%02x,0x%04x\0", read_16(buf, op->size+1), read_8(buf, op->size), (a->pc + op->size + 4 + read_8(buf, op->size+3)));
				op->size += 4;
			}
			else {// smaller
				sprintf(args, "3,#0x%02x,0x%02x,0x%04x\0", read_8(buf, op->size+1), read_8(buf, op->size), (a->pc + op->size + 5 +  read_8(buf, op->size+2)));
				op->size += 3;
			}
		break;

		case BBCA :
			// check addressing mode - first is for 16 bit addressing mode, second for 8 bit
			if (flag_m || flag_x) { // larger
				sprintf(args, "3,#0x%04x,0x$04x, dp + 0x00 + ix (0x%04x)\0", read_16(buf, op->size+2), read_16(buf, op->size), (a->pc + op->size + 5 + read_8(buf, op->size+4)));
				op->size += 5;
			}
			else { // smaller
				sprintf(args, "3,#0x%02x,0x$04x,dp + 0x00 + ix (0x%04x)\0", read_8(buf, op->size+2), read_16(buf, op->size), (a->pc + op->size + 4 + read_8(buf, op->size+3)));
				op->size += 4;
				}
		break;

		case LDM4 :
			if (flag_m || flag_x) {
				sprintf(args, "2,#$%04x,$04x\0", read_16(buf, op->size+2), read_16(buf, op->size));
				op->size += 4;
			}
			else {
				sprintf(args, "2,#$%02x,$04x\0", read_8(buf, op->size+2), read_16(buf, op->size));
				op->size += 3;
			}
		break;
		
		case LDM5 :
			if (flag_m || flag_x) {
				sprintf(args, "2,#$%04x,$04x\0", read_16(buf, op->size+2), read_16(buf, op->size));
				op->size += 4;
			}
			else {
				sprintf(args, "2,#$%04x,$02x\0", read_16(buf, op->size+1), read_8(buf, op->size));
				op->size += 3;
			}
		break;

		case LDM4X : 
			if (flag_m || flag_x) {
				sprintf(args, "3,#$%04x,$02x,xl\0", read_16(buf, op->size+1), read_8(buf, op->size));
				op->size += 3;
			}
			else {
				sprintf(args, "3,#$%02x,$02x,xl\0", read_8(buf, op->size+1), read_8(buf, op->size));
				op->size += 2;
			}
		break;
		case LDM5X : 		
			if (flag_m || flag_x) {
				sprintf(args, "3,#$%04x,$04x,xl\0", read_16(buf, op->size+2), read_16(buf, op->size));
				op->size += 4;
			}
			else {
				sprintf(args, "3,#$%02x,$04x,xl\0", read_8(buf, op->size+2), read_16(buf, op->size));
				op->size += 3;
			}
		break;
		case A : // accumulator addressing mode
		case PEA : 
			// flip the bits
			sprintf(args, "1,0x%04x\0", read_16(buf, op->size));			
			op->size +=2;
		break;
		case AI :
			sprintf(args, "1,($%04x)\0", read_16(buf, op->size));
			op->size +=2;
		break;
	
		case AL :
			sprintf(args, "1,$%08x\0", read_24(buf, op->size)); // might need to be set to 06x
			op->size += 3;
		break;
	
		case ALX : 
			sprintf(args, "2,$%08x,xl\0", read_24(buf, op->size));
			op->size += 3;
		break;
		case AX :
			sprintf(args, "2,$%04x,xl\0", read_16(buf, op->size));
			op->size += 2;
		break;
		case AXI :
			sprintf(args, "2,$%04x,xl)\0", read_16(buf, op->size));
			op->size += 2;
		break;
		case AY :
			sprintf(args, "2,$%04x,yl\0", read_16(buf, op->size));
			op->size += 2;
		break;

		case D : // direct addressing mode
			sprintf(args, "1,$%02x\0", read_8(buf, op->size));
			op->size++;
		break;
		case DI : // direct indirect addressing mode
		case PEI :
			sprintf(args, "1,($%02x)\0", read_8(buf, op->size));
			op->size++;
		break;
		case DIY : // direct indexed Y addressing mode
			sprintf(args, "2,yl,($%02x)\0", read_8(buf, op->size));
			op->size++;
		break;
		case DLI :
			sprintf(args, "1,[$%02x]\0", read_8(buf, op->size));		
			op->size++;
		break;
		case DLIY :
			sprintf(args, "1,yl,[$%02x]\0", read_8(buf, op->size));
			op->size++;
		break;	
		case DX :
			sprintf(args, "1,xl,$%02x\0", read_8(buf, op->size));
			op->size++;
		break;
		case DXI :  //direct indexed X addressing mode
			sprintf(args, "2,,xl,($%02x)\0", read_8(buf, op->size));
			op->size++;
		break;
		case DY :
			sprintf(args, "2,yl,$%02x\0", read_8(buf, op->size));
			op->size++;
		break;

	// causes segfault
		case S: 
			sprintf(args, "1,%s\0", int_8_str(read_8(buf, op->size)));
			op->size++;
		break;
		case SIY : 
			sprintf(args, "3,yl,%s\0", int_8_str(read_8(buf, op->size)));
			op->size++;
		break;
		case SIG : 
			sprintf(args, "1,$%02x\0", read_8(buf, op->size));
			op->size += 2;
		break;

		case MVN :
		case MVP :
			sprintf(args, "2,$%02x,$%02x\0", read_8(buf, op->size+1), read_8(buf, op->size));
			op->size += 2;
		break;	
		default:
			break;
	}

	return args;

}

/* Main disassembly func */
static int m7700_disassemble(RAsm *a, RAsmOp *op, ut8 *buf, ut64 len) {

	//a->immdisp = true; // force immediate display with # symbol (not ARM, but it uses the same syntax)

	//int idx = (buf[0] & 0x0f) * 2;
	
	op->size = 1;
	//char dest[20];
	char arg[50];
	ut16 instruction;
	OpCode* opcd;
	int prefix = 0;
	
	instruction = read_8(buf, 0); // grab instruction from buffer, with offset of 0

	// pull the prefix of the instruction off, grabing from the tables corresponding to the addressing mode
	switch (instruction){
		// first two cases, remove prefix - otherwise just pass instruction
		case 0x42: // x42 prefix - 
			//sprintf(dest, "b"); // b reg prefix;
			instruction = read_8(buf, 1); // grab next instruction from buffer, with offset of 1
			opcd = GET_OPCODE (instruction, 0x42); // grab opcode from instruction
			op->size++;
			prefix = 42;
			break;
		case 0x89: // x89 prefix  -
			instruction = read_8(buf, 1); // grab next instruction from buffer, with offset of 1
			opcd = GET_OPCODE (instruction, 0x89); // grab opcode from instruction
			op->size++; 
			prefix = 89;
			break;
		default:   // other prefixes
			//sprintf(dest, "a");
			opcd = GET_OPCODE (instruction, 0x00); // grab opcode from instruction
			break;
	}

	switch (opcd->op){
	// Data len selection flag mutators

	case SEM:
		GLOB_M = true;
		break;
	case CLM: 
		GLOB_M = false;
		break;
		
	// Carry flag mutators
	case SEC:
		GLOB_X = true;
		break;

	case CLC:
		GLOB_X = false;
		break;

	// I flag mutators
	case SEI: 
		GLOB_I= true;
		break;

	case CLI :
		GLOB_I = false;
		break;
	default:
		break;
	};
		
    strcpy (op->buf_asm, instruction_set[opcd->op]);
		
	char* vars = strtok(parse_args(opcd, op, buf, prefix, !GLOB_X && (opcd->flag == X), !GLOB_M && (opcd->flag == M), a), ",");
	
	vars = vars+2; // drop leading argno and space
	int i = 0;

  	while (vars != NULL)
  	{
		if (i > 1){
			strcat (arg, " ");
    		strcat (arg, vars);
    		vars = strtok (NULL, " ,.-");
	  	}
		else if (i == 1) {
    		strcat (arg, vars);
    		vars = strtok (NULL, " ,.-");
		}
		else {
			vars = strtok (NULL, " ,.-");
		}
		i++;
  	}

	op->buf_inc += op->size;

    if (*arg) {
        strcat (op->buf_asm, " ");
        strcat (op->buf_asm, arg);
    }

	free(vars);
	return op->size;
}