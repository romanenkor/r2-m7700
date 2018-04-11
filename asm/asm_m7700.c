#include <string.h>
#include <r_asm.h>
#include <r_lib.h>


<<<<<<< HEAD
const char *instruction_set[] = {

	"ADC", "AND", "ASL", "BCC", "BCS", "BEQ", "BIT", "BMI", "BNE",  "BPL", "BRA",
	"BRK", "BRL", "BVC", "BVS", "CLC", "CLD", "CLI", "CLV", "CMP",  "COP", "CPX",
	"CPY", "DEA", "DEC", "DEX", "DEY", "EOR", "INA", "INC", "INX",  "INY", "JML",
	"JMP", "JSL", "JSR", "LDA", "LDX", "LDY", "LSR", "MVN", "MVP",  "NOP", "ORA",
	"PEA", "PEI", "PER", "PHA", "PHT", "PHD", "PHK", "PHP", "PHX",  "PHY", "PLA",
	"PLT", "PLD", "PLP", "PLX", "PLY", "CLP", "ROL", "ROR", "RTI",  "RTL", "RTS",
	"SBC", "SEC", "SED", "SEI", "SEP", "STA", "STP", "STX", "STY",  "STZ", "TAX",
	"TAY", "TAS", "TAD", "TDA", "TRB", "TSB", "TSA", "TSX", "TXA",  "TXS", "TXY",
	"TYA", "TYX", "WIT", "WDM", "XBA", "XCE", "MPY", "DIV", "MPYS", "DIVS", "RLA",
	"EXTS","EXTZ","LDT", "LDM", "UNK", "SEB", "SEM", "CLM", "STB",  "LDB", "ADCB",
	"SBCB","EORB","TBX", "CMPB","INB", "DEB", "TXB", "TYB", "LSRB", "ORB", "CLB",
	"BBC", "BBS", "TBY", "ANDB","PUL", "PSH", "PLB", "XAB", "PHB",  "TBS", "TBD",
	"TDB"
};

static ut32 getInstruction(const ut8 *data) {


}

static const  char *ops[OPS * 2] = {

};

/* Main disassembly func */
static int disassemble(RAsm *a, RAsmOp *op, ut8 *buf, ut64 len) {

	char arg[16];

	int idx = (buf[0] & 0x0f) * 2;
	op->size = 2;

	// TODO: implement ut16 and ut8 differentiation for instructions, get from buff
	ut16 instruction = get16Instruction(buf);
	ut8 instruction = get8Instruction(buf);
	OpCode opcode = GET_OPCODE(instruction);

	switch (opcode) {
	
		//TODO: Begin implementation of switch for operators
	
	};

};

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