#!/bin/sh
# Import GalacticDan (RISC OS absolute, load &8000) into a Ghidra project,
# apply the spider's code/data classification, auto-analyse, then decompile.
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
G=${GHIDRA:-/home/jules/stuff/ghidra/ghidra_12.1.3_PUBLIC}
IMG="$HERE/../extracted/GalacticDan_8000,ff8"
rm -rf "$HERE/project/GalacticDan.gpr" "$HERE/project/GalacticDan.rep"
mkdir -p "$HERE/project" "$HERE/out"
"$G/support/analyzeHeadless" "$HERE/project" GalacticDan \
    -import "$IMG" -overwrite \
    -loader BinaryLoader -loader-baseAddr 0x8000 -loader-blockName absolute \
    -processor ARM:LE:32:v4 -cspec default \
    -scriptPath "$HERE/scripts" \
    -preScript ApplyRiscOSAnnotations.java "$HERE/galdan.json" \
    -postScript RiscOSPostAnalysis.java "$HERE/galdan.json" "$HERE/out" \
    2>&1 | tee "$HERE/out/headless.log" | grep -E 'INFO .*\.java>|ERROR|WARN.*Script|Exception' 
