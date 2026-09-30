"""Run the spider over a RISC OS absolute and export its findings as JSON for
the Ghidra ApplyRiscOSAnnotations.java script.

Usage: export_ghidra.py image loadaddr out.json [extra-entry ...]
"""
import sys, os, json, pickle, subprocess, tempfile, collections

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import spider
from spider import Image, Spider, speculate, valid_arm2

OS_SWIS = {
    0x00: 'OS_WriteC', 0x01: 'OS_WriteS', 0x02: 'OS_Write0', 0x03: 'OS_NewLine',
    0x04: 'OS_ReadC', 0x05: 'OS_CLI', 0x06: 'OS_Byte', 0x07: 'OS_Word',
    0x08: 'OS_File', 0x09: 'OS_Args', 0x0A: 'OS_BGet', 0x0B: 'OS_BPut',
    0x0C: 'OS_GBPB', 0x0D: 'OS_Find', 0x0E: 'OS_ReadLine', 0x0F: 'OS_Control',
    0x10: 'OS_GetEnv', 0x11: 'OS_Exit', 0x12: 'OS_SetEnv', 0x13: 'OS_IntOn',
    0x14: 'OS_IntOff', 0x15: 'OS_CallBack', 0x16: 'OS_EnterOS', 0x17: 'OS_BreakPt',
    0x18: 'OS_BreakCtrl', 0x19: 'OS_UnusedSWI', 0x1A: 'OS_UpdateMEMC',
    0x1B: 'OS_SetCallBack', 0x1C: 'OS_Mouse', 0x1D: 'OS_Heap', 0x1E: 'OS_Module',
    0x1F: 'OS_Claim', 0x20: 'OS_Release', 0x21: 'OS_ReadUnsigned',
    0x22: 'OS_GenerateEvent', 0x23: 'OS_ReadVarVal', 0x24: 'OS_SetVarVal',
    0x25: 'OS_GSInit', 0x26: 'OS_GSRead', 0x27: 'OS_GSTrans',
    0x28: 'OS_BinaryToDecimal', 0x29: 'OS_FSControl', 0x2A: 'OS_ChangeDynamicArea',
    0x2B: 'OS_GenerateError', 0x2C: 'OS_ReadEscapeState',
    0x2D: 'OS_EvaluateExpression', 0x2E: 'OS_SpriteOp', 0x2F: 'OS_ReadPalette',
    0x30: 'OS_ServiceCall', 0x31: 'OS_ReadVduVariables', 0x32: 'OS_ReadPoint',
    0x33: 'OS_UpCall', 0x34: 'OS_CallAVector', 0x35: 'OS_ReadModeVariable',
    0x36: 'OS_RemoveCursors', 0x37: 'OS_RestoreCursors',
    0x38: 'OS_SWINumberToString', 0x39: 'OS_SWINumberFromString',
    0x3A: 'OS_ValidateAddress', 0x3B: 'OS_CallAfter', 0x3C: 'OS_CallEvery',
    0x3D: 'OS_RemoveTickerEvent', 0x3E: 'OS_InstallKeyHandler',
    0x3F: 'OS_CheckModeValid', 0x40: 'OS_ChangeEnvironment',
    0x41: 'OS_ClaimScreenMemory', 0x42: 'OS_ReadMonotonicTime',
    0x43: 'OS_SubstituteArgs', 0x44: 'OS_PrettyPrint', 0x45: 'OS_Plot',
    0x46: 'OS_WriteN', 0x47: 'OS_AddToVector', 0x48: 'OS_WriteEnv',
    0x49: 'OS_ReadArgs', 0x4A: 'OS_ReadRAMFsLimits', 0x4B: 'OS_ClaimDeviceVector',
    0x4C: 'OS_ReleaseDeviceVector', 0x4D: 'OS_DelinkApplication',
    0x4E: 'OS_RelinkApplication', 0x4F: 'OS_HeapSort', 0x50: 'OS_ExitAndDie',
    0x51: 'OS_ReadMemMapInfo', 0x52: 'OS_ReadMemMapEntries',
    0x53: 'OS_SetMemMapEntries', 0x54: 'OS_AddCallBack',
    0x55: 'OS_ReadDefaultHandler', 0x56: 'OS_SetECFOrigin', 0x57: 'OS_SerialOp',
    0x58: 'OS_ReadSysInfo', 0x59: 'OS_Confirm', 0x5A: 'OS_ChangedBox',
    0x5B: 'OS_CRC', 0x5C: 'OS_ReadDynamicArea', 0x5D: 'OS_PrintChar',
    0xC0: 'OS_ConvertStandardDateAndTime', 0xC1: 'OS_ConvertDateAndTime',
    0xD0: 'OS_ConvertHex1', 0xD1: 'OS_ConvertHex2', 0xD2: 'OS_ConvertHex4',
    0xD3: 'OS_ConvertHex6', 0xD4: 'OS_ConvertHex8',
    0xD5: 'OS_ConvertCardinal1', 0xD6: 'OS_ConvertCardinal2',
    0xD7: 'OS_ConvertCardinal3', 0xD8: 'OS_ConvertCardinal4',
    0xD9: 'OS_ConvertInteger1', 0xDA: 'OS_ConvertInteger2',
    0xDB: 'OS_ConvertInteger3', 0xDC: 'OS_ConvertInteger4',
    0xDD: 'OS_ConvertBinary1', 0xDE: 'OS_ConvertBinary2',
    0xDF: 'OS_ConvertBinary3', 0xE0: 'OS_ConvertBinary4',
    0xE1: 'OS_ConvertSpacedCardinal1', 0xE2: 'OS_ConvertSpacedCardinal2',
    0xE3: 'OS_ConvertSpacedCardinal3', 0xE4: 'OS_ConvertSpacedCardinal4',
    0xE5: 'OS_ConvertSpacedInteger1', 0xE6: 'OS_ConvertSpacedInteger2',
    0xE7: 'OS_ConvertSpacedInteger3', 0xE8: 'OS_ConvertSpacedInteger4',
    0x40140: 'Sound_Configure', 0x40141: 'Sound_Enable', 0x40142: 'Sound_Stereo',
    0x40143: 'Sound_Speaker', 0x40180: 'Sound_Volume', 0x40181: 'Sound_SoundLog',
    0x40182: 'Sound_LogScale', 0x40183: 'Sound_InstallVoice',
    0x40184: 'Sound_RemoveVoice', 0x40185: 'Sound_AttachVoice',
    0x40186: 'Sound_ControlPacked', 0x40187: 'Sound_Tuning', 0x40188: 'Sound_Pitch',
    0x40189: 'Sound_Control', 0x4018A: 'Sound_AttachNamedVoice',
    0x4018B: 'Sound_ReadControlBlock', 0x4018C: 'Sound_WriteControlBlock',
    0x401C0: 'Sound_QInit', 0x401C1: 'Sound_QSchedule', 0x401C2: 'Sound_QRemove',
    0x401C3: 'Sound_QFree', 0x401C4: 'Sound_QSDispatch', 0x401C5: 'Sound_QTempo',
    0x401C6: 'Sound_QBeat', 0x401C7: 'Sound_QInterface',
}


# number of register inputs (r0..rN-1) for the SWI pseudo-function prototypes
SWI_ARGS = {
    0x00: 1, 0x01: 0, 0x02: 1, 0x03: 0, 0x04: 0, 0x05: 1, 0x06: 3, 0x07: 2, 0x08: 6,
    0x09: 3, 0x0C: 5, 0x0D: 2, 0x0E: 4, 0x11: 3, 0x1C: 0, 0x1D: 4, 0x1E: 4, 0x1F: 3,
    0x20: 3, 0x2B: 1, 0x2C: 0, 0x2E: 8, 0x31: 2, 0x35: 2, 0x36: 0, 0x37: 0, 0x42: 0,
    0x45: 3, 0x46: 2, 0x40140: 5, 0x40141: 1, 0x40142: 2, 0x40143: 1, 0x40180: 1,
    0x40183: 2, 0x40184: 1, 0x40185: 2, 0x40189: 4, 0x4018A: 2,
}
for _n in range(0xD0, 0xE9): SWI_ARGS[_n] = 3


def swi_name(n):
    x = 'X' if n & 0x20000 else ''
    b = n & ~0x20000
    if 0x100 <= b <= 0x1FF:
        c = b - 0x100
        return '%sOS_WriteI+%s' % (x, repr(chr(c)) if 32 <= c < 127 else '&%02X' % c)
    return x + OS_SWIS[b] if b in OS_SWIS else '%sSWI_&%X' % (x, b)


def disasm_words(words):
    """objdump a batch of words -> list of text."""
    if not words:
        return []
    with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as f:
        for w in words:
            f.write(w.to_bytes(4, 'little'))
    out = subprocess.run(['arm-none-eabi-objdump', '-b', 'binary', '-m', 'armv2a', '-D', f.name],
                         capture_output=True, text=True).stdout
    os.unlink(f.name)
    res = []
    for line in out.splitlines():
        p = line.split('\t')
        if len(p) >= 3 and p[0].strip().endswith(':'):
            res.append(' '.join(p[2:]).split('@')[0].strip())
    return res


def duff_entries(img, a):
    """Entry points of the unrolled body following a computed 'add pc,pc,X':
    find the repetition period, then take block starts aligned to the end of
    the repeated run (where 'zero iterations' lands)."""
    s = a + 8
    best = None
    for p in range(1, 33):
        n = 0
        while img.inside(s + 4 * (n + p)) and img.word(s + 4 * n) == img.word(s + 4 * (n + p)):
            n += 1
        if n >= 2 * p and (best is None or n > best[1] + p):
            best = (p, n)
    if best is None:
        return None, []
    p, n = best
    end = s + 4 * (n + p)
    ents = set([a + 4, end])
    e = end
    while e >= s:
        ents.add(e); e -= 4 * p
    return p, sorted(ents)


def textlike(txt):
    """Reject pixel data that happens to be printable: words must be
    Capitalised/lower/UPPER and letters must have a plausible vowel ratio."""
    import re
    t = txt.decode('latin-1')
    words = re.findall(r'[A-Za-z]+', t)
    letters = ''.join(words)
    if len(letters) < 4:
        return False
    if not all(re.fullmatch(r'[A-Z]?[a-z]+|[A-Z]+', w) for w in words):
        return False
    if re.search(r'(.)\1\1\1', t) and not re.search(r'[ =*-]{4}', t) or len(set(letters)) < 3:
        return False
    v = sum(c in 'aeiouAEIOU' for c in letters) / len(letters)
    return 0.2 <= v <= 0.65


def strings_in(img, lo, hi):
    """Printable runs >= 6 chars (allowing \\n \\r) in [lo, hi)."""
    out = []
    a = lo
    while a < hi:
        b = a
        while b < hi and (32 <= img.byte(b) < 127 or img.byte(b) in (10, 13)):
            b += 1
        txt = bytes(img.byte(x) for x in range(a, b))
        letters = sum(chr(c).isalpha() or c in b' \n\r' for c in txt)
        if b - a >= 6 and letters >= 0.8 * len(txt) and textlike(txt):
            term = b < hi and img.byte(b) == 0
            out.append((a, b - a + (1 if term else 0), term))
            a = b + 1
        else:
            a = b + 1 if b == a else b
    return out


def main():
    path, base, outp = sys.argv[1], int(sys.argv[2], 16), sys.argv[3]
    extra = [int(x, 16) for x in sys.argv[4:]]
    img = Image(open(path, 'rb').read(), base)
    cache = outp + '.pickle'
    if os.path.exists(cache) and os.path.getmtime(cache) > os.path.getmtime(spider.__file__):
        sp = pickle.load(open(cache, 'rb'))
        sp.img = img
    else:
        sp = Spider(img)
        sp.add_func(base)
        for x in extra: sp.add_func(x)
        sp.run()
        firm_funcs = set(sp.funcs)
        speculate(sp)
        sp.firm_funcs = firm_funcs
        sp.img = None
        pickle.dump(sp, open(cache, 'wb'))
        sp.img = img

    code = sp.code
    ranges = []
    for a in sorted(code):
        spec = a in sp.spec
        if ranges and ranges[-1][1] == a and ranges[-1][2] == spec:
            ranges[-1][1] = a + 4
        else:
            ranges.append([a, a + 4, spec])

    comments = []   # [addr, kind, text]
    labels = []     # [addr, name]
    # SWI names
    for a in sorted(code):
        w = img.word(a)
        if (w >> 24) & 15 == 0xF:
            comments.append([a, 'EOL', swi_name(w & 0xFFFFFF)])
    # self-modification
    patched = sorted(x for x in sp.writes if x in code)
    vals = []
    for x in patched:
        vs = sorted(sp.var_vals.get(x, ()))
        vals.append(vs)
    flat = [v for vs in vals for v in vs]
    dis = dict(zip(flat, disasm_words(flat)))
    for x, vs in zip(patched, vals):
        txt = 'SELF-MODIFYING CODE: instruction overwritten at run time by store at %08x' % sp.writes[x]
        for v in vs:
            txt += '\n  with %08x  (%s)' % (v, dis.get(v, '?'))
        comments.append([x, 'PLATE', txt])
    for x in sorted(sp.writes):
        if x not in code:
            labels.append([x, 'var_%x' % x])
    for a, var in sp.rtjumps:
        comments.append([a, 'EOL', 'jump through run-time continuation var_%x' % var])
        labels.append([var, 'var_%x' % var])
    # Duff's devices
    duff = []
    for a in sp.duff:
        p, ents = duff_entries(img, a)
        if ents:
            duff.append([a, ents])
            comments.append([a, 'PRE', "Computed jump into unrolled loop body (Duff's device): "
                             '%d-instruction blocks, %d entry points' % (p, len(ents))])
    # funcs
    funcs = []
    for f in sorted(sp.funcs):
        firm = f in sp.firm_funcs
        funcs.append([f, not firm])
    labels.append([base, '_start'])
    # data
    dwords = sorted(x for x in sp.data if x not in code and not sp.data[x].startswith('OS_WriteS'))
    strs = []
    for a in sorted(code):
        w = img.word(a)
        if (w >> 24) & 15 == 0xF and (w & ~0x20000 & 0xFFFFFF) == 1:
            s = a + 4
            e = s
            while img.byte(e): e += 1
            strs.append([s, e - s + 1, True])
    # printable strings in non-code areas
    covered = set()
    for s, l, t in strs:
        covered.update(range(s, s + l))
    lo = None
    for a in range(base, img.end):
        inc = (a & ~3) in code
        if not inc and lo is None: lo = a
        if (inc or a == img.end - 1) and lo is not None:
            for s, l, t in strings_in(img, lo, a if inc else img.end):
                if s not in covered: strs.append([s, l, t])
            lo = None
    strset = set()
    for s, l, t in strs: strset.update(range(s & ~3, s + l, 1))
    dwords = [x for x in dwords if x not in strset]

    # SWI pseudo-functions, OS_WriteS fallthroughs, 26-bit returns
    swis = {}
    fallthrough = []
    overrides = dict(sp.overrides)
    for a in sorted(code):
        w = img.word(a)
        if (w >> 24) & 15 == 0xF:
            n = w & 0xFFFFFF
            b = n & ~0x20000
            nargs = 0 if 0x100 <= b <= 0x1FF else SWI_ARGS.get(b, 4)
            swis[n] = [swi_name(n), nargs, b in (0x11, 0x2B) and not n & 0x20000]
            if b == 1:
                e = a + 4
                while img.byte(e): e += 1
                fallthrough.append([a, (e + 4) & ~3])
        if (w & 0x0FFFFFFF) == 0x01B0F00E:               # movs pc, lr
            overrides[a] = 'RETURN'
    overrides = {a: k for a, k in overrides.items() if a in code}
    const_dwords = [x for x in dwords if x not in sp.writes]

    out = dict(base=base, length=len(img.data), functions=funcs, code_ranges=ranges,
               overrides=sorted([a, k] for a, k in overrides.items()),
               swis=sorted([n] + v for n, v in swis.items()), fallthrough=fallthrough,
               const_dwords=const_dwords,
               dwords=dwords, strings=sorted(strs), comments=comments, labels=labels,
               duff=duff)
    json.dump(out, open(outp, 'w'), indent=0)
    print('functions %d (%d speculative), code ranges %d, overrides %d, dwords %d, strings %d, '
          'comments %d, duff %d, self-modified sites %d' % (
              len(funcs), sum(s for _, s in funcs), len(ranges), len(overrides), len(dwords),
              len(strs), len(comments), len(duff), len(patched)))
    for a, ents in duff:
        print('  duff %08x: %d entries %08x..%08x' % (a, len(ents), ents[0], ents[-1]))


if __name__ == '__main__':
    main()
