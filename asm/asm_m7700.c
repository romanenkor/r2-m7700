#include "./arch/m7700.c"
#include <r_asm.h>
#include <r_lib.h>
#include <string.h>
//#include "./arch/m7700.h"

/* Main disassembly func */
static int disassemble(RAsm *a, RAsmOp *op, ut8 *buf, ut64 len) {

  return m7700_disassemble(a, op, buf, len);
}

// Test main func
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
  Dprintf("%d   %08x\n", current_write_index,
          current_write_prt[current_write_index - 1]);

  Dprintf("------------\n");

  doParse0(p, parseNextInstruction, c, (int)strlen(c));
  Dprintf("Parsed Characters %i\n", p);
  Dprintf("%d   %08x\n", current_write_index,
          current_write_prt[current_write_index - 1]);

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
#endif // MAIN_ASM

/* Structure of exported functions/data (used in R2) */
RAsmPlugin r_asm_plugin_m7700 = {
    .name = "m7700",
    .arch = "m7700",
    .license = "None",
    .bits = 16,
    .desc = "Disassembly plugin for Mitsubishi M7700 Arch",
    .disassemble = &disassemble};

#ifndef CORELIB
RLibStruct radare_plugin = {.type = R_LIB_TYPE_ASM,
                            .data = &r_asm_plugin_m7700};
#endif
