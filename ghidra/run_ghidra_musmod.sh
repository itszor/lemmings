#!/bin/sh
# Import musmod2 (MusicModule 1.02, a RISC OS relocatable module) into a
# Ghidra project, apply the spider's code/data classification, auto-analyse,
# then decompile. A relocatable module is position-independent, so it's
# analysed (and translated) at the address the runtime "RMLoads" it to:
# MODBASE = &1800000 in recomp/runtime.c.
#
# Offset 0 is the module header (data), so the base isn't seeded ('nobase');
# entry points are seeded explicitly instead (module offsets):
#   header:  init &684, final &9d4, service &4f4, SWI handler &570
#   *commands: MusSongpos &970, MusOFF &99c, MusON &9ac, MusVolume &8f4,
#            MusLoad &89c, MusSamplerate &920, MusBorder &938, MusLaidBack &950
#   Level 1 sound handler block (installed with Sound_Configure at &2e48):
#            fill &2ed0, overrun fixup &2f60, and &2f1c - where each voice
#            generator returns to (the fill pushes it with `add r0,pc,#&c`,
#            the voice pops it with `ldm sp!,{pc}`; spider stops at &2f18's
#            indirect `orrs pc,r0,#2`)
#   voice generators, reached only via `orrs pc,r0,#2` from the fill code
#   (addresses returned by &2434/&2600/&27c4/&2988): &2444 &2608 &27cc &2990
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
G=${GHIDRA:-/home/jules/stuff/ghidra/ghidra_12.1.3_PUBLIC}
IMG="$HERE/../extracted/!LEMMINGS/musmod2,fffffa43-00000000"
B=0x1800000
seeds=""
for off in 0x684 0x9d4 0x4f4 0x570 \
           0x970 0x99c 0x9ac 0x8f4 0x89c 0x920 0x938 0x950 \
           0x2ed0 0x2f60 0x2f1c \
           0x2444 0x2608 0x27cc 0x2990; do
    seeds="$seeds $(printf '0x%x' $((B + off)))"
done
rm -f "$HERE/musmod.json.pickle"
python3 "$HERE/export_ghidra.py" "$IMG" 1800000 "$HERE/musmod.json" nobase $seeds
rm -rf "$HERE/project/MusMod.gpr" "$HERE/project/MusMod.rep"
mkdir -p "$HERE/project" "$HERE/out/musmod"
"$G/support/analyzeHeadless" "$HERE/project" MusMod \
    -import "$IMG" -overwrite \
    -loader BinaryLoader -loader-baseAddr 0x1800000 -loader-blockName module \
    -processor ARM:LE:32:v4 -cspec default \
    -scriptPath "$HERE/scripts" \
    -preScript ApplyRiscOSAnnotations.java "$HERE/musmod.json" \
    -postScript RiscOSPostAnalysis.java "$HERE/musmod.json" "$HERE/out/musmod" musmod \
    2>&1 | tee "$HERE/out/musmod/headless_musmod.log" | grep -E 'INFO .*\.java>|ERROR|WARN.*Script|Exception'
