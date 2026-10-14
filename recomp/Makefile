# Static recompilation of Lemmings: LemProg (gen/), LemBoot (genboot/) and
# MusicModule (genmus/), from superspider analyse/gen, and game.c, linked with libroger
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
# ../superspider/out/<name>.json, then superspider gen. Each image's ../superspider/<name>.roots
# adds entry points to the analysis: "make roots" merges the gap entries a
# --trace-gaps run logged (untranslated.log, or LOG=...) into them, so the
# next "make regen" translates them.
SS      ?= $(HOME)/stuff/superspider
SSBIN   := $(SS)/_build/default/bin/main.exe
SSD     := ../superspider
LEMPROG := ../extracted_decompressed/LemProg.bin
LEMBOOT := ../game/!LEMMINGS/LemBoot,fffff843-5e629b4c
MUSMOD  := ../game/!LEMMINGS/musmod2,fffffa43-5842cdf9
LOG     ?= untranslated.log

# $(call analyse,name,image,base[,--module])
define analyse
	$(SSBIN) analyse "$(2)" $(3) $(4) --full --roots $(SSD)/$(1).roots -o $(SSD)/out/$(1).json
endef

regen:
	cd $(SS) && dune build
	mkdir -p $(SSD)/out
	$(call analyse,lemprog,$(LEMPROG),8000)
	$(call analyse,lemboot,$(LEMBOOT),8000)
	$(call analyse,musmod,$(MUSMOD),1800000,--module)
	rm -rf gen genboot genmus
	$(SSBIN) gen "$(LEMPROG)" 8000 $(SSD)/out/lemprog.json --c gen --leaders=dispatch
	$(SSBIN) gen "$(LEMBOOT)" 8000 $(SSD)/out/lemboot.json --c genboot --leaders=dispatch \
	    --prefix=B --tabprefix=recompB --pcbias --files=2 --covtag=B
	$(SSBIN) gen "$(MUSMOD)" 1800000 $(SSD)/out/musmod.json --c genmus --leaders=dispatch \
	    --prefix=M --tabprefix=recompM --files=2

roots:
	python3 $(SS)/tools/gap_roots.py "$(LEMPROG)" 8000 $(SSD)/lemprog.roots $(LOG)
	python3 $(SS)/tools/gap_roots.py "$(LEMBOOT)" 8000 $(SSD)/lemboot.roots $(LOG)
	python3 $(SS)/tools/gap_roots.py "$(MUSMOD)" 1800000 $(SSD)/musmod.roots $(LOG)

clean:
	rm -f gen/*.o genboot/*.o genmus/*.o game.o lemmings lemmings-cov *.cov.o gen*/*.cov.o

.PHONY: FORCE cov regen roots clean
