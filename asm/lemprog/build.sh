#!/bin/sh
# Reassemble lemmings.s and compare with the original image.
set -e
cd "$(dirname "$0")"
arm-none-eabi-as -march=armv2a -o lemmings.o lemmings.s
arm-none-eabi-ld -Ttext=0x8000 -e _start --no-warn-rwx-segments -o lemmings.elf lemmings.o
arm-none-eabi-objcopy -O binary -j .text lemmings.elf "LemProg,00008000"
cmp "LemProg,00008000" "../../extracted_decompressed/LemProg.bin" && echo "IDENTICAL to original"
