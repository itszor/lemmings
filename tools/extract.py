#!/usr/bin/env python3
"""Extract the ADFS-E disc image into extracted/, preserving the RISC OS
directory tree. Filenames get a ',load-exec' suffix like galactic dan/extracted.

Usage: extract.py [image.adf] [out_dir]
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ADFSlib

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_IMG = os.path.join(HERE, '..', 'Lemmings (1991)(Krisalis).adf')
DEFAULT_OUT = os.path.join(HERE, '..', 'extracted')


def walk(files, path):
    for f in files:
        p = os.path.join(path, f.name)
        if hasattr(f, 'files'):
            os.makedirs(p, exist_ok=True)
            walk(f.files, p)
        else:
            os.makedirs(path, exist_ok=True)
            load = getattr(f, 'load_address', 0) & 0xffffffff
            exe = getattr(f, 'exec_address', 0) & 0xffffffff
            fname = p + ',%08x-%08x' % (load, exe)
            open(fname, 'wb').write(f.data)


def main():
    img = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_IMG
    out = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_OUT
    disc = ADFSlib.ADFSdisc(open(img, 'rb'))
    print('disc_type', disc.disc_type, 'root', disc.root_name)
    walk(disc.files, out)
    print('extracted to', out)


if __name__ == '__main__':
    main()
