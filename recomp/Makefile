# Static recompilation of Lemmings: LemProg (gen/), LemBoot (genboot/) and
# MusicModule (genmus/), from gen_c.py, and game.c, linked with libroger
# (the RISC OS runtime).
ROGER   ?= $(HOME)/stuff/libroger
CC      ?= gcc
CFLAGS  ?= -O2 -g -w -fno-strict-aliasing $(if $(TRACE),-DRECOMP_TRACE)
GEN     := $(wildcard gen/code*.c) gen/entries.c
GENBOOT := $(wildcard genboot/code*.c) genboot/entries.c
GENMUS  := $(wildcard genmus/code*.c) genmus/entries.c
OBJ     := $(GEN:.c=.o) $(GENBOOT:.c=.o) $(GENMUS:.c=.o) game.o
LIBS    := $(shell pkg-config --libs sdl3) -lm -lpthread
INC     := -I$(ROGER)/include

lemmings: $(OBJ) $(ROGER)/libroger.a
	$(CC) $(CFLAGS) -o $@ $(OBJ) $(ROGER)/libroger.a $(LIBS)

$(ROGER)/libroger.a: FORCE
	$(MAKE) -C $(ROGER) libroger.a

%.o: %.c $(ROGER)/include/roger.h $(ROGER)/include/roger_cpu.h
	$(CC) $(CFLAGS) $(INC) -c -o $@ $<

# Coverage build for SuperSpider (~/stuff/superspider/PLAN.md, phase 0):
# "make cov" builds lemmings-cov from separate *.cov.o objects (the normal
# build is untouched); it writes $$RECOMP_COV (default cov.out) at exit.
COVDIR  ?= $(HOME)/stuff/superspider/phase0/cov
COVOBJ  := $(OBJ:.o=.cov.o) cov.cov.o

cov: lemmings-cov

lemmings-cov: $(COVOBJ) FORCE
	$(MAKE) -C $(ROGER) cov COV=$(COVDIR)
	$(CC) $(CFLAGS) -o $@ $(COVOBJ) $(ROGER)/libroger-cov.a $(LIBS)

%.cov.o: %.c $(ROGER)/include/roger_cpu.h $(COVDIR)/cov.h
	$(CC) $(CFLAGS) -DRECOMP_COV $(INC) -I$(COVDIR) -c -o $@ $<

cov.cov.o: $(COVDIR)/cov.c $(COVDIR)/cov.h
	$(CC) $(CFLAGS) -c -o $@ $<

regen:
	python3 gen_c.py
	python3 gen_c.py --img=../extracted/\!LEMMINGS/LemBoot,fffff843-00000000 \
	    --json=../ghidra/lemboot.json --tsvdir=../ghidra/out/lemboot \
	    --prefix=B --tabprefix=recompB --pcbias --out=genboot --files=2 --covtag=B
	python3 gen_c.py --img=../extracted/\!LEMMINGS/musmod2,fffffa43-00000000 \
	    --json=../ghidra/musmod.json --tsvdir=../ghidra/out/musmod \
	    --prefix=M --tabprefix=recompM --base=1800000 --out=genmus --files=2

clean:
	rm -f gen/*.o genboot/*.o genmus/*.o game.o lemmings lemmings-cov *.cov.o gen*/*.cov.o

.PHONY: FORCE cov regen clean
