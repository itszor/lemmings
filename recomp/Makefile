# Static recompilation of Lemmings (LemProg + LemBoot)
CC      ?= gcc
CFLAGS  ?= -O2 -g -w -fno-strict-aliasing $(if $(TRACE),-DRECOMP_TRACE)
GEN     := $(wildcard gen/code*.c) gen/entries.c
GENBOOT := $(wildcard genboot/code*.c) genboot/entries.c
GENMUS  := $(wildcard genmus/code*.c) genmus/entries.c
OBJ     := $(GEN:.c=.o) $(GENBOOT:.c=.o) $(GENMUS:.c=.o) runtime.o vdu.o display.o sound.o
LIBS    := $(shell pkg-config --libs sdl3) -lm -lpthread
SDLCF   := $(shell pkg-config --cflags sdl3)

lemmings: $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ) $(LIBS)

gen/%.o: gen/%.c runtime.h gen/gen.h
	$(CC) $(CFLAGS) -I. -c -o $@ $<

genboot/%.o: genboot/%.c runtime.h genboot/gen.h
	$(CC) $(CFLAGS) -I. -c -o $@ $<

genmus/%.o: genmus/%.c runtime.h genmus/gen.h
	$(CC) $(CFLAGS) -I. -c -o $@ $<

runtime.o: runtime.c runtime.h os.h
	$(CC) $(CFLAGS) -c -o $@ $<

vdu.o: vdu.c runtime.h os.h
	$(CC) $(CFLAGS) -c -o $@ $<

sound.o: sound.c runtime.h os.h
	$(CC) $(CFLAGS) $(SDLCF) -c -o $@ $<

display.o: display.c os.h shaders/crt.frag.spv.h
	$(CC) $(CFLAGS) $(SDLCF) -c -o $@ $<

regen:
	python3 gen_c.py
	python3 gen_c.py --img=../extracted/\!LEMMINGS/LemBoot,fffff843-00000000 \
	    --json=../ghidra/lemboot.json --tsvdir=../ghidra/out/lemboot \
	    --prefix=B --tabprefix=recompB --pcbias --out=genboot --files=2
	python3 gen_c.py --img=../extracted/\!LEMMINGS/musmod2,fffffa43-00000000 \
	    --json=../ghidra/musmod.json --tsvdir=../ghidra/out/musmod \
	    --prefix=M --tabprefix=recompM --base=1800000 --out=genmus --files=2

clean:
	rm -f gen/*.o genboot/*.o genmus/*.o runtime.o vdu.o display.o sound.o lemmings
