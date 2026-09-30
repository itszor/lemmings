#!/bin/sh
# Import the decompressed LemProg (RISC OS absolute, load &8000 - the real
# 147K main game engine, decompressed from the 68K on-disc LemProg via
# tools/unpack_lemboot.py) into a Ghidra project, apply the spider's
# code/data classification, auto-analyse, then decompile.
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
G=${GHIDRA:-/home/jules/stuff/ghidra/ghidra_12.1.3_PUBLIC}
IMG="$HERE/../extracted_decompressed/LemProg.bin"
if [ ! -f "$IMG" ]; then
    python3 "$HERE/../tools/unpack_lemboot.py" LemProg 8aac 8ae8 8000 "$IMG"
fi
rm -rf "$HERE/project/LemProg.gpr" "$HERE/project/LemProg.rep"
mkdir -p "$HERE/project" "$HERE/out/lemprog"
"$G/support/analyzeHeadless" "$HERE/project" LemProg \
    -import "$IMG" -overwrite \
    -loader BinaryLoader -loader-baseAddr 0x8000 -loader-blockName absolute \
    -processor ARM:LE:32:v4 -cspec default \
    -scriptPath "$HERE/scripts" \
    -preScript ApplyRiscOSAnnotations.java "$HERE/lemprog.json" \
    -postScript RiscOSPostAnalysis.java "$HERE/lemprog.json" "$HERE/out/lemprog" \
    2>&1 | tee "$HERE/out/headless_lemprog.log" | grep -E 'INFO .*\.java>|ERROR|WARN.*Script|Exception'
