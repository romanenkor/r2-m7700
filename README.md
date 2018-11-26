# r2-m7700
Radare2 arch support for Mitsubishi M7700 chipset


This is basically a port of MAME's M7700 reverse engineer into Radare2, but with WIP ESIL support. 
Credit to MAME for their disassembler (https://github.com/mamedev/historic-mame/tree/master/src/emu/cpu/m37710).

I've made a few small changes to the disassembler with some small bugs I found, or just some things that made it a bit easier
to read in Radare. 

To install, use the makefiles located in the anal and asm directories. It should automatically install in your radare2 plugin
directory. You'll also need to paste Radare2's headers (found here: https://github.com/radare/radare2/tree/master/libr/include) in the /r2_bin/include/libr/ starting at the r2-m7700 root directory. If the r2_bin directory isn't included, then you'll need to add that to the root. Our Makefiles should automatically add anything there to $PATH when compiling, it needs these headers to install the radare2 plugins.

Obviously also requires radare2 (https://github.com/radare/radare2/) to work, and will be installed in your local R2 plugins directory. Running the L command after install should tell you if the plugins have been loaded, there should be an analysis and an assembler plugin running within R2 after successful installation. 
