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

# Code/data analysis: SuperSpider (~/stuff/superspider, no Ghidra), into
# ../superspider/out/, then gen_c.py. Each image's ../superspider/<name>.roots
# adds entry points to the analysis: "make roots" merges the gap entries a
# --trace-gaps run logged (untranslated.log, or LOG=...) into them, so the
# next "make regen" translates them.
SS      ?= $(HOME)/stuff/superspider
SSBIN   := $(SS)/_build/default/bin/main.exe
SSD     := ../superspider
LEMPROG := ../extracted_decompressed/LemProg.bin
LEMBOOT := ../extracted/!LEMMINGS/LemBoot,fffff843-00000000
MUSMOD  := ../extracted/!LEMMINGS/musmod2,fffffa43-00000000
LOG     ?= untranslated.log

# $(call analyse,name,image,base[,--module])
define analyse
	$(SSBIN) s1b "$(2)" $(3) $(4) --roots $(SSD)/$(1).roots -o $(SSD)/out/$(1).ss.json
	python3 $(SS)/phase6/ss_to_spider.py $(SSD)/out/$(1).ss.json "$(2)" $(3) \
	    $(SSD)/out/$(1).json $(SSD)/out/$(1) ../ghidra $(4)
endef

regen:
	cd $(SS) && dune build
	mkdir -p $(SSD)/out
	$(call analyse,lemprog,$(LEMPROG),8000)
	$(call analyse,lemboot,$(LEMBOOT),8000)
	$(call analyse,musmod,$(MUSMOD),1800000,--module)
	rm -rf gen genboot genmus
	python3 gen_c.py --json=$(SSD)/out/lemprog.json --tsvdir=$(SSD)/out/lemprog
	python3 gen_c.py --img="$(LEMBOOT)" --json=$(SSD)/out/lemboot.json --tsvdir=$(SSD)/out/lemboot \
	    --prefix=B --tabprefix=recompB --pcbias --out=genboot --files=2 --covtag=B
	python3 gen_c.py --img="$(MUSMOD)" --json=$(SSD)/out/musmod.json --tsvdir=$(SSD)/out/musmod \
	    --prefix=M --tabprefix=recompM --base=1800000 --out=genmus --files=2

roots:
	python3 $(SS)/tools/gap_roots.py "$(LEMPROG)" 8000 $(SSD)/lemprog.roots $(LOG)
	python3 $(SS)/tools/gap_roots.py "$(LEMBOOT)" 8000 $(SSD)/lemboot.roots $(LOG)
	python3 $(SS)/tools/gap_roots.py "$(MUSMOD)" 1800000 $(SSD)/musmod.roots $(LOG)

# The previous analysis: the spider + Ghidra (../ghidra/run_ghidra_*.sh).
regen-ghidra:
	python3 gen_c.py
	python3 gen_c.py --img="$(LEMBOOT)" \
	    --json=../ghidra/lemboot.json --tsvdir=../ghidra/out/lemboot \
	    --prefix=B --tabprefix=recompB --pcbias --out=genboot --files=2 --covtag=B
	python3 gen_c.py --img="$(MUSMOD)" \
	    --json=../ghidra/musmod.json --tsvdir=../ghidra/out/musmod \
	    --prefix=M --tabprefix=recompM --base=1800000 --out=genmus --files=2

clean:
	rm -f gen/*.o genboot/*.o genmus/*.o game.o lemmings lemmings-cov *.cov.o gen*/*.cov.o

.PHONY: FORCE cov regen regen-ghidra roots clean
