# r2-m7700
Radare2 arch support for Mitsubishi M7700 chipset


This is basically a port of MAME's M7700 reverse engineer into Radare2, but with WIP ESIL support. 
Credit to MAME for their disassembler (https://github.com/mamedev/historic-mame/tree/master/src/emu/cpu/m37710).

I've made a few small changes to the disassembler with some small bugs I found, or just some things that made it a bit easier
to read in Radare. 

To install, use the makefiles located in the anal and asm directories. It should automatically install in your radare2 plugin
directory. You'll need Radare2's various library files in your $PATH somewhere, otherwise it won't compile correctly (WIP).
