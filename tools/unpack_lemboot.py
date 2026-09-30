#!/usr/bin/env python3
"""Decompress a file LemBoot loads+unpacks, by actually emulating LemBoot's
own loader/unpacker routine (arm2.py) rather than reimplementing its LZ-style
codec by hand.

LemBoot (RISC OS absolute, load &8000) copies its first &2000 bytes to
&40000 and continues running from there (see the loop at &8010-&802c), which
is what makes it safe for it to then OS_File-load a game file *at* &8000,
overwriting the low copy of itself. So all offsets below are given as
LemBoot-file-relative (i.e. "as disassembled with load address &8000") and
translated to the relocated &40000 copy at run time.

Known loader call sites within LemBoot (leafname string -> call site that
sets r8 = leafname pointer, r9 = load address, then falls into the shared
loader at &8aac):
    LemProg   @ str &8ae8, call site &8aac, load addr &8000
(Krisalis/PSYGNO/DMALOGO look structurally identical around &8c00-&8d60 but
use a different call pattern - not wired up here yet, see README.)

Usage: unpack_lemboot.py <leafname> <call_site_hex> <str_ptr_hex> <load_addr_hex> <out_file>
Example (LemProg):
    unpack_lemboot.py LemProg 8aac 8ae8 8000 lemprog_decompressed.bin
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import arm2

HERE = os.path.dirname(os.path.abspath(__file__))
LEMBOOT = os.path.join(HERE, '..', 'extracted', '!LEMMINGS', 'LemBoot,fffff843-00000000')
ROOT = os.path.join(HERE, '..', 'extracted', '!LEMMINGS')
RELOC = 0x40000
LOAD_BASE = 0x8000
RELOC_COPY_LEN = 0x2000  # bytes 0x8010-0x802c copies this many bytes to 0x40000
STACK_TOP = 0x300000


def resolve(path):
    """Resolve a RISC OS path like '<Lem$Dir>.Lemmings.LemProg' to a host
    path under extracted/, matching path components case-insensitively and
    ignoring the ',load-exec' suffix extract.py appends."""
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


def run(call_site, str_ptr, load_addr):
    lemboot = open(LEMBOOT, 'rb').read()
    m = arm2.ARM(memsize=0x400000)
    m.mem[RELOC:RELOC + len(lemboot)] = lemboot

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
        real = num & 0x1FFFF
        if real == 0x08 and m.r[0] == 0xFF:  # OS_File, reason 255 (Load)
            path = read_cstr(m.mem, m.r[1])
            fpath = resolve(path)
            data = open(fpath, 'rb').read()
            addr = m.r[2]
            m.mem[addr:addr + len(data)] = data
            m.r[0], m.r[3], m.r[4], m.r[5] = 1, addr, len(data), 0
            m.flags &= ~arm2.V_
            tracking[0] = True
            print('OS_File load %s -> %s (%d bytes) @ %#x' % (path, fpath, len(data), addr),
                  file=sys.stderr)
        else:
            raise Exception('unhandled SWI %x at pc %x' % (num, pc))

    m.write_hook = write_hook
    m.swi_handler = swi_handler

    off = lambda a: RELOC + (a - LOAD_BASE)
    m.r[8] = off(str_ptr)
    m.r[9] = load_addr
    m.r[13] = STACK_TOP
    m.r[15] = off(call_site)
    ret = off(call_site + 0x38)  # the loader's fixed epilogue offset (ldm sp!,{pc})

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
    leafname, call_site, str_ptr, load_addr, out_path = sys.argv[1:6]
    data = run(int(call_site, 16), int(str_ptr, 16), int(load_addr, 16))
    open(out_path, 'wb').write(data)
    print('%s: %d bytes -> %s' % (leafname, len(data), out_path))


if __name__ == '__main__':
    main()
