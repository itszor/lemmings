#!/usr/bin/env python3
"""Decompress the files LemBoot loads+unpacks, by actually emulating
LemBoot's own loader/unpacker routine (arm2.py) rather than reimplementing
its LZ-style codec by hand.

LemBoot (RISC OS absolute, load &8000) copies its first &2000 bytes to
&40000 and continues running from there (see the loop at &8010-&802c), which
is what makes it safe for it to then OS_File-load a game file *at* &8000,
overwriting the low copy of itself. So all offsets below are given as
LemBoot-file-relative (i.e. "as disassembled with load address &8000") and
translated to the relocated &40000 copy at run time.

There are two structurally-similar loader call sites in LemBoot, both of
which: set r8 = pointer to a leafname string, set r9 (APCS "sb") = target
load address, then bl a shared "OS_File 255 load, then LZ-unpack" routine.

    LemProg (the main engine): entered directly at &8aac, which sets r9 =
    &8000 itself (a fixed literal in the code).

    Krisalis / PSYGNO / DMALOGO (splash-screen bitmaps, ~32000 bytes each
    once unpacked - confirmed by their post-unpack byte distribution: mostly
    zero with ~100-175 distinct values, i.e. an indexed-colour bitmap, not
    code): entered at &8af0, which reads r9 from a literal pool slot at
    &8a20 that real LemBoot presumably fills in dynamically before each of
    these three calls (we didn't trace that setup - see README). All three
    empirically decompress cleanly when that slot is pre-seeded to &8000
    (i.e. same "load low, use briefly, get overwritten by the next asset"
    pattern as LemProg), so that's what TARGETS below assumes.

Usage: unpack_lemboot.py [leafname ...]   (default: all four known targets)
Decompressed files are written to extracted_decompressed/<leafname>.bin
"""
import os
import struct
import sys

sys.path.insert(0, os.path.join(os.environ.get('SUPERSPIDER', os.path.expanduser('~/stuff/superspider')), 'tools'))
import arm2

HERE = os.path.dirname(os.path.abspath(__file__))
LEMBOOT = os.path.join(HERE, '..', 'game', '!LEMMINGS', 'LemBoot,fffff843-5e629b4c')
ROOT = os.path.join(HERE, '..', 'game', '!LEMMINGS')       # (recipe.json)
OUT_DIR = os.path.join(HERE, '..', 'extracted_decompressed')
RELOC = 0x40000
LOAD_BASE = 0x8000
STACK_TOP = 0x300000
SB_SLOT = 0x8a20  # literal pool slot the Krisalis/PSYGNO/DMALOGO loader reads r9 from

# leafname -> (call_site, return_addr, str_ptr, patch_sb_slot)
TARGETS = {
    'LemProg':  (0x8aac, 0x8ae4, 0x8ae8, False),
    'Krisalis': (0x8af0, 0x8b2c, 0x8c38, True),
    'PSYGNO':   (0x8af0, 0x8b2c, 0x8cd0, True),
    'DMALOGO':  (0x8af0, 0x8b2c, 0x8d5c, True),
}


def resolve(path):
    """Resolve a RISC OS path like '<Lem$Dir>.Lemmings.LemProg' to a host
    path under game/, matching path components case-insensitively and
    ignoring the ',load-exec' suffix adf_extract.py appends."""
    assert path.startswith('<Lem$Dir>.')
    parts = path[len('<Lem$Dir>.'):].split('.')
    cur = ROOT
    for comp in parts:
        found = None
        for name in os.listdir(cur):
            if name.split(',')[0].lower() == comp.lower():
                found = name
                break
        if found is None:
            raise FileNotFoundError(path)
        cur = os.path.join(cur, found)
    return cur


def read_cstr(mem, addr):
    end = addr
    while mem[end] != 0:
        end += 1
    return mem[addr:end].decode('latin1')


def run(call_site, ret_addr, str_ptr, patch_sb_slot):
    lemboot = open(LEMBOOT, 'rb').read()
    m = arm2.ARM(memsize=0x4000000)  # must cover the emulator's 26-bit (64M) address mask
    m.mem[RELOC:RELOC + len(lemboot)] = lemboot

    off = lambda a: RELOC + (a - LOAD_BASE)
    if patch_sb_slot:
        struct.pack_into('<I', m.mem, off(SB_SLOT), LOAD_BASE)

    bounds = [None, None]
    tracking = [False]

    def write_hook(addr, size):
        if not tracking[0] or addr >= STACK_TOP - 0x10000:
            return
        if bounds[0] is None or addr < bounds[0]:
            bounds[0] = addr
        hi = addr + size
        if bounds[1] is None or hi > bounds[1]:
            bounds[1] = hi

    def swi_handler(m, num, pc):
        x = bool(num & 0x20000)
        real = num & ~0x20000
        if real == 0x08 and m.r[0] == 0xFF:  # OS_File, reason 255 (Load)
            path = read_cstr(m.mem, m.r[1])
            fpath = resolve(path)
            data = open(fpath, 'rb').read()
            addr = m.r[2]
            m.mem[addr:addr + len(data)] = data
            m.r[0], m.r[3], m.r[4], m.r[5] = 1, addr, len(data), 0
            tracking[0] = True
            print('  OS_File load %s -> %s (%d bytes) @ %#x' % (path, fpath, len(data), addr),
                  file=sys.stderr)
        else:
            raise Exception('unhandled SWI %x at pc %x' % (num, pc))
        if x:
            m.flags &= ~arm2.V_

    m.write_hook = write_hook
    m.swi_handler = swi_handler

    m.r[8] = off(str_ptr)
    m.r[9] = LOAD_BASE
    m.r[13] = STACK_TOP
    m.r[15] = off(call_site)
    ret = off(ret_addr)

    steps = 0
    while m.r[15] != ret:
        m.step()
        steps += 1
        if steps > 20_000_000:
            raise RuntimeError('step limit exceeded, pc=%#x' % m.r[15])

    if bounds[0] is None:
        raise RuntimeError('nothing decompressed')
    return bytes(m.mem[bounds[0]:bounds[1]])


def main():
    names = sys.argv[1:] or list(TARGETS)
    os.makedirs(OUT_DIR, exist_ok=True)
    for name in names:
        print('%s:' % name, file=sys.stderr)
        data = run(*TARGETS[name])
        out_path = os.path.join(OUT_DIR, name + '.bin')
        open(out_path, 'wb').write(data)
        print('%s: %d bytes -> %s' % (name, len(data), out_path))


if __name__ == '__main__':
    main()
