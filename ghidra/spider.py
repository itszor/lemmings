"""Recursive-descent code/data separator for 26-bit ARM (ARM2/ARM3) RISC OS
absolute images.  Hand-written-assembly aware:

  * B/BL, conditional fall-through
  * "mov rN, pc ; b X"  (call with link in any register) and
    "mov lr, pc ; mov pc, rX" style indirect calls
  * returns via mov/movs pc, rN, ldm {...,pc}
  * OS_WriteS inline strings, non-returning SWIs
  * add pc,pc,rX,lsl #2 branch tables and ldr pc,[pc,rX,lsl #2] address tables
  * a tiny per-block constant tracker to resolve PC-relative literal loads,
    ADR, "ldr rX,[pc,#];add rX,pc,rX" and "mov pc, rX" with known rX.

Usage: spider.py image loadaddr [extra-entry ...]
"""
import struct, sys, collections

M32 = 0xFFFFFFFF
CONDS = ['eq', 'ne', 'cs', 'cc', 'mi', 'pl', 'vs', 'vc',
         'hi', 'ls', 'ge', 'lt', 'gt', 'le', 'al', 'nv']
NORETURN_SWIS = {0x11, 0x2B}          # OS_Exit, OS_GenerateError (non-X)


def ror(v, s):
    s &= 31
    return ((v >> s) | (v << (32 - s))) & M32 if s else v


class Image:
    def __init__(self, data, base):
        self.data, self.base = data, base
        self.end = base + len(data)

    def inside(self, a):
        return self.base <= a < self.end

    def word(self, a):
        return struct.unpack_from('<I', self.data, a - self.base)[0]

    def byte(self, a):
        return self.data[a - self.base]


def valid_arm2(w):
    """Is this word plausibly an ARM2/ARM3 instruction?  Returns reason or None."""
    cond = w >> 28
    if cond == 0xF:
        return 'NV condition'
    t = (w >> 25) & 7
    if t in (0, 1):
        if t == 0 and (w & 0x90) == 0x90:
            if (w & 0x0FC000F0) == 0x00000090: return None      # MUL/MLA
            if (w & 0x0FB00FF0) == 0x01000090: return None      # SWP (ARM3)
            return 'halfword/long-mul encoding (not ARM2)'
        op, s = (w >> 21) & 15, (w >> 20) & 1
        if 8 <= op <= 11 and not s:
            return 'test op without S (MRS/MSR space)'
        return None
    if t == 3 and (w & 0x10):
        return 'undefined instruction space'
    if t in (6, 7) and (w >> 24) & 15 != 0xF:
        cp = (w >> 8) & 15
        if cp not in (1, 2):
            return 'coprocessor %d' % cp
    return None


class AgeRegs(dict):
    """Register constants that expire after a few instructions, so values
    don't leak across loop heads / merge points we can't see."""
    LIFE = 6

    def __init__(self):
        super().__init__(); self._age = {}

    def tick(self):
        for r in list(self._age):
            self._age[r] -= 1
            if self._age[r] < 0:
                del self._age[r]; dict.pop(self, r, None)

    def __setitem__(self, r, v):
        dict.__setitem__(self, r, v); self._age[r] = self.LIFE

    def pop(self, r, d=None):
        self._age.pop(r, None); return dict.pop(self, r, d)

    def clear(self):
        dict.clear(self); self._age.clear()


class Spider:
    def __init__(self, img):
        self.img = img
        self.code = {}                  # addr -> function entry that reached it
        self.data = {}                  # addr -> reason (literal, string, table)
        self.funcs = set()
        self.calls = collections.defaultdict(set)   # callee -> callers
        self.adr_targets = set()        # PC-relative address materialisations
        self.problems = []
        self.work = []
        self.xtables = []
        self.spec = set()
        self.pc_vars = set()            # inline variables loaded into PC
        self.var_vals = collections.defaultdict(set)  # inline var -> constants stored
        self.overrides = {}             # addr -> Ghidra FlowOverride name
        self.duff = []                  # computed 'add pc,pc,X' sites
        self.rtjumps = []               # jumps through runtime-set inline variables
        self.writes = {}                # addr -> storing insn (inline vars / code patches)

    def add_func(self, a, src=None):
        if not self.img.inside(a) or a & 3:
            self.problems.append((src, 'call to %08x outside image' % a)); return
        if src is not None:
            self.calls[a].add(src)
        if a not in self.funcs:
            self.funcs.add(a)
            self.work.append((a, a))

    def add_data(self, a, n, why):
        for x in range(a & ~3, a + n, 4):
            if self.img.inside(x):
                self.data.setdefault(x, why)

    def run(self):
        while True:
            while self.work:
                a, fn = self.work.pop()
                self.trace(a, fn)
            for var in self.pc_vars:
                for v in self.var_vals.get(var, ()):
                    v &= 0x3FFFFFC
                    if self.img.inside(v) and v not in self.code and v not in self.funcs:
                        self.add_func(v)
            if not self.work:
                return

    def trace(self, a, fn):
        img = self.img
        regs = AgeRegs()        # short-range constant tracker (PC-relative idioms)
        link = None             # register that holds a return address set by "mov rN, pc"
        prev = []
        while True:
            if not img.inside(a):
                self.problems.append((a, 'flowed off image')); return
            if a in self.code:
                return
            if a in self.data:
                self.problems.append((a, 'code flows into data (from func %08x)' % fn))
                return
            w = img.word(a)
            bad = valid_arm2(w)
            if bad:
                self.problems.append((a, 'invalid (%s) reached from func %08x' % (bad, fn)))
                return
            self.code[a] = fn
            regs.tick()
            pc = a + 8
            cond = w >> 28
            always = cond == 14
            t = (w >> 25) & 7
            nxt = a + 4
            linkreg, link = link, None

            if t == 5:                                   # B / BL
                off = w & 0xFFFFFF
                if off & 0x800000: off -= 0x1000000
                tgt = (pc + off * 4) & 0x3FFFFFC
                if w & (1 << 24) or linkreg is not None:  # BL, or mov rN,pc ; b
                    if not w & (1 << 24): self.overrides[a] = 'CALL'
                    self.add_func(tgt, a)
                    regs.clear()
                else:
                    self.work.append((tgt, fn))
                    if always:
                        return
                a = nxt; prev.append(w); continue

            if t == 7 and (w >> 24) & 15 == 0xF:         # SWI
                n = w & 0xFFFFFF
                x = n & ~0x20000
                if x == 0x01:                            # OS_WriteS
                    s = nxt
                    while img.inside(s) and img.byte(s): s += 1
                    s = (s + 4) & ~3
                    self.add_data(nxt, s - nxt, 'OS_WriteS string')
                    a = s; regs.clear(); continue
                if n in NORETURN_SWIS and always:
                    return
                for r in range(4): regs.pop(r, None)
                a = nxt; continue

            if t in (0, 1) and not ((w & 0x0E000090) == 0x90):   # data processing
                op = (w >> 21) & 15
                rn, rd = (w >> 16) & 15, (w >> 12) & 15
                imm = t == 1
                if imm:
                    val2 = ror(w & 0xFF, ((w >> 8) & 15) * 2)
                else:
                    rm = w & 15
                    shifted = (w >> 4) & 0xFF
                    val2 = None
                    if shifted == 0:
                        val2 = pc if rm == 15 else regs.get(rm)
                opn = pc if rn == 15 else regs.get(rn)
                res = None
                if op == 13:  res = val2                             # MOV
                elif op == 4 and opn is not None and val2 is not None: res = (opn + val2) & M32
                elif op == 2 and opn is not None and val2 is not None: res = (opn - val2) & M32
                if op == 13 and not imm and (w & 0xFFF) == 15 and rd != 15:
                    link = rd                            # mov rN, pc
                if op == 4 and imm and rn == 15 and val2 == 0 and rd != 15:
                    link = rd                            # add rN, pc, #0
                if rd == 15 and not (8 <= op <= 11):     # write to PC
                    if op == 4 and rn == 15 and not imm and ((w >> 4) & 0xFF) == 0x10:
                        self.branch_table(a, w & 15, prev, fn)   # add pc,pc,rX,lsl #2
                        if always: return
                    elif op == 4 and rn == 15:
                        self.duff.append(a)              # computed jump into following unrolled code
                    elif res is not None:
                        tgt = res & 0x3FFFFFC
                        if linkreg is not None:
                            self.overrides[a] = 'CALL'; self.add_func(tgt, a)
                        else: self.work.append((tgt, fn))
                        if always and linkreg is None: return
                    elif linkreg is not None:
                        self.overrides[a] = 'CALL'       # indirect call, continue
                    elif always:
                        if op == 13 and not imm and (w & 15) != 14 and not (w >> 4) & 0xFF:
                            self.overrides[a] = 'RETURN'  # mov pc, rN (non-lr link)
                        return                           # return / computed jump
                    a = nxt; prev.append(w); regs.clear(); continue
                if rn == 15 and imm and op in (2, 4) and res is not None:
                    self.adr_targets.add((res, a))
                if not (8 <= op <= 11):
                    if res is not None and always: regs[rd] = res
                    else: regs.pop(rd, None)
                a = nxt; prev.append(w); continue

            if t in (2, 3):                              # LDR/STR
                load = (w >> 20) & 1
                rn, rd = (w >> 16) & 15, (w >> 12) & 15
                up, pre, byte = (w >> 23) & 1, (w >> 24) & 1, (w >> 22) & 1
                base = pc if rn == 15 else regs.get(rn)
                addr = None
                if t == 2 and base is not None and pre:
                    off = w & 0xFFF
                    addr = base + off if up else base - off
                elif t == 3 and base is not None and pre and ((w >> 4) & 0xFF) == 0:
                    idx = regs.get(w & 15)
                    if idx is not None:
                        addr = (base + idx if up else base - idx) & M32
                val = None
                if addr is not None and img.inside(addr):
                    if load: self.add_data(addr, 1 if byte else 4, 'literal @%08x' % a)
                    else:
                        self.writes.setdefault(addr & ~3, a)
                        v = regs.get(rd) if rd != 15 else None
                        if v is not None and not byte:
                            self.var_vals[addr].add(v)
                    if not byte and not addr & 3:
                        val = img.word(addr)
                if addr is not None and load and img.inside(addr):
                    pass
                if load and rd == 15:
                    if (t == 3 and rn == 15 and ((w >> 4) & 0xFF) == 0x10):
                        self.addr_table(a, w & 15, prev, fn)
                        if always: return
                    elif addr is not None and (addr in self.writes or val is None or not img.inside(val & 0x3FFFFFC)):
                        self.pc_vars.add(addr)           # jump via runtime-set variable
                        self.rtjumps.append((a, addr))
                        self.overrides[a] = 'CALL' if linkreg is not None else 'CALL_RETURN'
                        if always and linkreg is None: return
                    elif val is not None:
                        tgt = val & 0x3FFFFFC
                        if linkreg is not None: self.add_func(tgt, a)
                        else: self.work.append((tgt, fn))
                        if always and linkreg is None: return
                    elif linkreg is not None:
                        self.overrides[a] = 'CALL'
                    elif always and linkreg is None:
                        return
                elif load:
                    if val is not None and always: regs[rd] = val
                    else: regs.pop(rd, None)
                if (w >> 21) & 1 or not pre: regs.pop(rn, None)
                a = nxt; prev.append(w); continue

            if t == 4:                                   # LDM/STM
                if (w >> 20) & 1:
                    for r in range(16):
                        if w & (1 << r): regs.pop(r, None)
                    if w & (1 << 15) and always:
                        return
                if (w >> 21) & 1: regs.pop((w >> 16) & 15, None)
                a = nxt; prev.append(w); continue

            # MUL/MLA/SWP/coprocessor
            if t == 0: regs.pop((w >> 16) & 15 if (w & 0x0FC000F0) == 0x90 else (w >> 12) & 15, None)
            a = nxt; prev.append(w)

    def bound(self, prev, rx):
        """Look back for 'cmp rx, #n' to bound a table."""
        for w in reversed(prev[-4:]):
            if (w & 0x0FFF0000) == (0x03500000 | (rx << 16)):
                return ror(w & 0xFF, ((w >> 8) & 15) * 2)
        return None

    def branch_table(self, a, rx, prev, fn):
        n = self.bound(prev, rx)
        e = a + 8
        cnt = 0
        while self.img.inside(e) and (n is None or cnt < n + 1):
            w = self.img.word(e)
            if n is None and (w >> 24) != 0xEA:
                break
            self.work.append((e, fn))
            e += 4; cnt += 1
        self.xtables.append((a, 'branch', cnt))

    def addr_table(self, a, rx, prev, fn):
        n = self.bound(prev, rx)
        e = a + 8
        cnt = 0
        while self.img.inside(e) and (n is None or cnt < n + 1):
            v = self.img.word(e)
            if not self.img.inside(v) or v & 3:
                break
            self.add_data(e, 4, 'jump table')
            self.work.append((v, fn))
            e += 4; cnt += 1
        self.xtables.append((a, 'address', cnt))


def main():
    path, base = sys.argv[1], int(sys.argv[2], 16)
    img = Image(open(path, 'rb').read(), base)
    sp = Spider(img)
    sp.add_func(base)
    for x in [v for v in sys.argv[3:] if not v.startswith('--')]:
        sp.add_func(int(x, 16))
    sp.run()
    firm = len(sp.code)
    if '--no-spec' not in sys.argv:
        acc = speculate(sp)
        print('speculative entries accepted: %d (adding %d insns to %d firm)' % (len(acc), len(sp.spec), firm))

    # Classify every word.
    kinds = []
    for a in range(base, img.end & ~3, 4):
        kinds.append('c' if a in sp.spec else 'C' if a in sp.code else 'D' if a in sp.data or a in sp.writes else '?')
    cnt = collections.Counter(kinds)
    tot = len(kinds)
    print('image %08x-%08x, %d words' % (base, img.end, tot))
    for k, name in (('C', 'code (reached)'), ('c', 'code (speculative)'), ('D', 'data (referenced)'), ('?', 'unknown')):
        print('  %-18s %6d words  %5.1f%%' % (name, cnt[k], 100.0 * cnt[k] / tot))
    print('functions found: %d   jump tables: %d' % (len(sp.funcs), len(sp.xtables)))
    print('problems: %d' % len(sp.problems))
    for p in sp.problems[:30]:
        print('   ', '%08x' % p[0] if p[0] is not None else '--------', p[1])

    # Region map
    regions = []
    for i, k in enumerate(kinds):
        a = base + 4 * i
        if regions and regions[-1][2] == k and regions[-1][1] == a:
            regions[-1][1] = a + 4
        else:
            regions.append([a, a + 4, k])
    with open('regions.txt', 'w') as f:
        for s, e, k in regions:
            f.write('%08x-%08x %s %d\n' % (s, e, k, (e - s) // 4))

    # Unknown gaps: how many look like code?
    unk = [(s, e) for s, e, k in regions if k == '?']
    def plausible(s, e):
        ws = [img.word(x) for x in range(s, e, 4)]
        return sum(valid_arm2(w) is None and (w >> 28) == 14 for w in ws) / len(ws)
    big = sorted(unk, key=lambda r: r[0] - r[1])[:25]
    print('\nlargest unknown gaps (fraction of words that are valid AL-cond insns):')
    for s, e in sorted(big):
        print('  %08x-%08x %6d bytes  %.2f' % (s, e, e - s, plausible(s, e)))

    with open('funcs.txt', 'w') as f:
        for fa in sorted(sp.funcs):
            size = sum(1 for v in sp.code.values() if v == fa)
            f.write('%08x  insns=%-5d callers=%s\n' % (fa, size,
                    ' '.join('%08x' % c for c in sorted(sp.calls[fa])[:8])))
    with open('adr.txt', 'w') as f:
        for v, a in sorted(sp.adr_targets):
            k = 'C' if v in sp.code else 'D' if v in sp.data else '?' if img.inside(v) else 'ext'
            f.write('%08x -> %08x %s\n' % (a, v, k))



def speculate(sp):
    """Try each unknown gap word as a function entry; keep the trace only if it
    produces no problems (invalid insns, flowing into data/off image)."""
    from collections import ChainMap
    img = sp.img
    accepted = []
    base_code, base_data = sp.code, sp.data
    changed = True
    while changed:
        changed = False
        a = img.base
        while a < img.end - 3:
            if a in base_code or a in base_data:
                a += 4; continue
            sp.code, sp.data = ChainMap({}, base_code), ChainMap({}, base_data)
            nprob, funcs, adr = len(sp.problems), set(sp.funcs), set(sp.adr_targets)
            calls = {k: set(v) for k, v in sp.calls.items()}
            ntab = len(sp.xtables)
            saved = (dict(sp.writes), set(sp.pc_vars), {k: set(v) for k, v in sp.var_vals.items()})
            sp.add_func(a)
            sp.run()
            new = sp.code.maps[0]
            al = sum((img.word(x) >> 28) == 14 for x in new)
            if len(sp.problems) > nprob or len(new) < 8 or al < 0.6 * len(new):
                del sp.problems[nprob:]; del sp.xtables[ntab:]
                sp.funcs, sp.adr_targets = funcs, adr
                sp.writes, sp.pc_vars = saved[0], saved[1]
                sp.var_vals = collections.defaultdict(set, saved[2])
                sp.calls = collections.defaultdict(set, calls)
                sp.work = []
                a += 4
                continue
            base_code.update(new); base_data.update(sp.data.maps[0])
            sp.spec.update(new)
            accepted.append(a)
            changed = True
            a += 4
    sp.code, sp.data = base_code, base_data
    return accepted


if __name__ == '__main__':
    main()
