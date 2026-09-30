import sys, os, struct
img = open(sys.argv[1],'rb').read(); out = sys.argv[2]
def rd(fmt,o): return struct.unpack_from(fmt,img,o)
def walk(addr, path):
    d = img[addr:addr+0x800]
    assert d[1:5] in (b'Hugo',b'Nick'), (hex(addr), d[:5])
    for i in range(77):
        o = 5 + i*26
        if d[o] == 0: break
        name = bytes(c & 0x7f for c in d[o:o+10]).split(b'\r')[0].split(b'\0')[0].decode('latin1')
        load, exe, ln = struct.unpack_from('<III', d, o+10)
        sec = int.from_bytes(d[o+22:o+25],'little'); attr = d[o+25]
        p = os.path.join(path, name)
        ftype = '%03x' % ((load>>8)&0xfff) if (load>>20)==0xfff else 'L%08x E%08x' % (load,exe)
        print('%-40s %s len=%-7d at=0x%06x attr=%02x' % (p, 'DIR' if attr&8 else ftype, ln, sec*256, attr))
        if attr & 8:
            os.makedirs(os.path.join(out,p), exist_ok=True); walk(sec*256, p)
        else:
            fn = p + (','+ftype if len(ftype)==3 else ',%08x-%08x'%(load,exe))
            open(os.path.join(out,fn),'wb').write(img[sec*256:sec*256+ln])
walk(0x400, '')
