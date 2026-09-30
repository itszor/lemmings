#!/bin/sh
# Reassemble lemboot.s and compare with the original image.
set -e
cd "$(dirname "$0")"
arm-none-eabi-as -march=armv2a -o lemboot.o lemboot.s
arm-none-eabi-ld -Ttext=0x8000 -e _start --no-warn-rwx-segments -o lemboot.elf lemboot.o
arm-none-eabi-objcopy -O binary -j .text lemboot.elf "LemBoot,00008000"
cmp "LemBoot,00008000" "../../extracted/!LEMMINGS/LemBoot,fffff843-00000000" && echo "IDENTICAL to original"
