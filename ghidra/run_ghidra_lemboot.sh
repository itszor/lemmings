#!/bin/sh
# Import LemBoot (RISC OS loader, load &8000) into a Ghidra project, apply the
# spider's code/data classification, auto-analyse, then decompile.
#
# LemBoot is the small (4.5K) loader run by !Run: it RMLoads MemMod/MusMod2,
# then loads and LZ-unpacks LemProg, Krisalis, PSYGNO and DMALOGO in turn
# (see tools/unpack_lemboot.py and the README for how those get pulled out).
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
G=${GHIDRA:-/home/jules/stuff/ghidra/ghidra_12.1.3_PUBLIC}
IMG="$HERE/../extracted/!LEMMINGS/LemBoot,fffff843-00000000"
rm -rf "$HERE/project/LemBoot.gpr" "$HERE/project/LemBoot.rep"
mkdir -p "$HERE/project" "$HERE/out/lemboot"
"$G/support/analyzeHeadless" "$HERE/project" LemBoot \
    -import "$IMG" -overwrite \
    -loader BinaryLoader -loader-baseAddr 0x8000 -loader-blockName absolute \
    -processor ARM:LE:32:v4 -cspec default \
    -scriptPath "$HERE/scripts" \
    -preScript ApplyRiscOSAnnotations.java "$HERE/lemboot.json" \
    -postScript RiscOSPostAnalysis.java "$HERE/lemboot.json" "$HERE/out/lemboot" lemboot \
    2>&1 | tee "$HERE/out/lemboot/headless_lemboot.log" | grep -E 'INFO .*\.java>|ERROR|WARN.*Script|Exception'
