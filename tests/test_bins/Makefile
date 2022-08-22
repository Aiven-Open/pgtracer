%.elf: %.elf.c
	gcc -Wl,--build-id -gdwarf-5 -O0 -c $*.elf.c -o $@

%.main: %.main.c
	gcc -Wl,--build-id -gdwarf-5 -O0 $*.main.c -o $@

all: test.elf test_stack.main
