asm=./asm/
anal=./anal/

all: 
	+$(MAKE) -C asm
	+$(MAKE) -C anal

clean:
	+$(MAKE) clean -C asm
	+$(MAKE) clean -C anal
	
install:
	+$(MAKE) install -C asm
	+$(MAKE) install -C anal

uninstall:
	+$(MAKE) uninstall -C asm
	+$(MAKE) uninstall -C anal
