"""Static recompiler: translate the ARM2 code to C, one instruction at a
time, using the macros in libroger's roger_cpu.h. Ported from galactic dan/recomp/gen_c.py
(https://github... n/a - sibling project); the translation logic itself
(Recomp class) is unmodified, only load_analysis()/main()'s hardcoded paths
were parametrized so this can target any of our images, not just LemProg.

Code/data classification, labels, call/return overrides, Duff's-device entry
points and self-modification sites all come from the earlier analysis
(ghidra/gen_asm.py + <name>.json + the spider pickle).

Usage: gen_c.py [--img=path] [--json=path] [--tsvdir=path] [--dyn=path,...]
                [--loops] [--files=N] [--prefix=F] [--tabprefix=recomp]
                [--pcbias] [--out=dir] [--base=hex]
    --base: load address the image is translated for (default 8000). A RISC
    OS relocatable module is position-independent, so it's translated at the
    address the runtime loads it to (see recomp/runtime.c, MODBASE).
    --pcbias: emit PC-derived values relative to the runtime's pc_bias
    (for an image that relocates itself and runs from the copy - LemBoot).
    Defaults target LemProg (extracted_decompressed/LemProg.bin,
    ghidra/lemprog.json, ghidra/out/lemprog).
"""
import sys, os, re, json, pickle, collections

HERE = os.path.dirname(os.path.abspath(__file__))
GH = os.path.join(HERE, '..', 'ghidra')
sys.path.insert(0, GH)
import spider                                   # noqa: F401 (unpickling)
import gen_asm
from export_ghidra import duff_entries

M32 = 0xFFFFFFFF
COVTAG = ''                     # --covtag=C: the coverage recorder's name for this image
BASE = 0x8000                   # image load address; --base= overrides (e.g. a module's RMA address)
CONDS = ['EQ', 'NE', 'CS', 'CC', 'MI', 'PL', 'VS', 'VC', 'HI', 'LS', 'GE', 'LT', 'GT', 'LE', 'AL', 'NV']
DPOPS = ['AND', 'EOR', 'SUB', 'RSB', 'ADD', 'ADC', 'SBC', 'RSC',
         'TST', 'TEQ', 'CMP', 'CMN', 'ORR', 'MOV', 'BIC', 'MVN']
LOGICAL = {0, 1, 8, 9, 12, 13, 14, 15}


def ror(v, s):
    s &= 31
    return ((v >> s) | (v << (32 - s))) & M32 if s else v


def h(v):
    return '0x%xu' % (v & M32)


def load_analysis(img_path, json_path, tsvdir, dyn):
    img = open(img_path, 'rb').read()
    j = json.load(open(json_path))
    sp = pickle.load(open(json_path + '.pickle', 'rb'))
    names = {}
    for line in open(os.path.join(tsvdir, 'functions.tsv')).read().splitlines()[1:]:
        e = int(line.split('\t')[0], 16)
        if e < 0x10000000:
            names[e] = 'sub_%x' % e
    def word_at(x):
        return int.from_bytes(img[x - BASE:x - BASE + 4], 'little')

    extra = set()
    strs = [(a, a + l) for a, l, t in j['strings']]
    go = os.path.join(tsvdir, 'ghidra_only_code.txt')
    if os.path.exists(go):
        for line in open(go):
            s, e = (int(x, 16) for x in line.split('-'))
            words = range(s & ~3, e + 1, 4)
            if all(spider.valid_arm2(word_at(x)) is None
                   for x in words) and not any(a < e + 1 and s < b for a, b in strs):
                extra.update(words)

    # A "ghidra-only" acceptance can land on a lone 'stmdb sp!, {pc}' (this
    # codebase's other call idiom besides the register-load thunks: push a
    # fake return address, then an inert NV filler word, then the real
    # branch - see spider.py's matching fix in trace()'s LDM/STM handling).
    # Unlike code spider actually traced, this single-word acceptance never
    # goes through that logic, so the branch two words later is never
    # pulled in as code at all - extend it here the same way.
    for a in list(extra):
        if word_at(a) & 0x0FFFFFFF == 0x092D8000:  # <cond> stmdb sp!, {pc}
            if word_at(a + 4) >> 28 == 0xF and (word_at(a + 8) >> 25) & 7 == 5:
                extra.add(a + 8)
                # a+12 is where control resumes once the callee eventually
                # pops the address we just pushed (ARM2 quirk: an STM that
                # stores PC stores a+12, not a+4/a+8) - there is no static
                # path to it at all (the branch at a+8 doesn't fall through),
                # so it's only discoverable by understanding this idiom.
                if spider.valid_arm2(word_at(a + 12)) is None:
                    extra.add(a + 12)

    g = gen_asm.Gen(img, BASE, j, sp, names, extra)
    g.dyn = dyn
    g.notes = {}
    g.pads = {}
    g.inst_fallback = set()
    import contextlib, io
    with contextlib.redirect_stdout(io.StringIO()):
        g.assign_labels()
    return img, j, sp, g


class Recomp:
    def __init__(self, img_path, json_path, tsvdir, dyn=(), loops=False, prefix='F', tabprefix='recomp',
                 pcbias=False):
        self.pcbias = pcbias              # see pc() below
        self.prefix = prefix              # function symbol prefix (F_xxxx); lets two
        self.tabprefix = tabprefix        # translated images (e.g. LemBoot + LemProg,
                                           # both loaded at &8000) coexist in one binary
                                           # without colliding on C symbol names.
        self.img, self.j, self.sp, self.g = load_analysis(img_path, json_path, tsvdir, list(dyn))
        self.end = BASE + len(self.img)
        self.code = set(self.g.code)
        self.loops = loops
        self.overrides = {a: k for a, k in self.sp.overrides.items() if a in self.code}
        for a in self.code:                                  # movs pc, lr and friends
            if (self.word(a) & 0x0FFFFFFF) == 0x01B0F00E:
                self.overrides.setdefault(a, 'RETURN')
        self.fallthrough = {a: b for a, b in self.j['fallthrough']}      # OS_WriteS
        self.duff = {a: ents for a, ents in self.j['duff'] if a in self.code}
        self.smc = self.find_smc()
        self.partition()
        self.find_leaders()
        self.stats = collections.Counter()
        self.duffloops = self.plan_duff_loops() if loops else {}

    def word(self, a):
        return int.from_bytes(self.img[a - BASE:a - BASE + 4], 'little')

    # ---------------------------------------------------------------- analysis
    def find_smc(self):
        """Self-modified instruction sites and the alternative words written."""
        smc = {}
        for a, kind, text in self.j['comments']:
            if kind == 'PLATE' and text.startswith('SELF-MODIFYING') and a in self.code:
                smc[a] = [int(v, 16) for v in re.findall(r'with ([0-9a-f]{8})', text)]
        return smc

    def partition(self):
        """Each instruction belongs to exactly one C function: the spider's
        owning function entry; stragglers join their predecessor."""
        own = {}
        for a in sorted(self.code):
            o = self.sp.code.get(a)
            if o is None:
                o = own.get(a - 4, a)
            own[a] = o
        self.owner = own
        self.funcs = collections.defaultdict(list)
        for a, o in own.items():
            self.funcs[o].append(a)
        for o in self.funcs:
            self.funcs[o].sort()

    def branch_target(self, a, w):
        off = w & 0xFFFFFF
        if off & 0x800000:
            off -= 0x1000000
        return (a + 8 + off * 4) & 0x3FFFFFC

    def is_literal_thunk(self, tgt):
        """See spider.literal_thunk: 'bic lr,lr,#0xfc000003 ; ldr rX,[lr],#4 ;
        mov pc,lr'. A 'bl' to one of these consumes one literal word right
        after the call site and resumes at call site + 8, not + 4."""
        return (BASE <= tgt < self.end - 8 and self.word(tgt) == 0xE3CEE3FF
                and self.word(tgt + 8) == 0xE1A0F00E)

    def call_return_site(self, a, w, tgt):
        return a + 8 if (w & (1 << 24)) and self.is_literal_thunk(tgt) else a + 4

    def natural_next(self, a, w):
        """Where control genuinely continues after instruction a, for the
        generic 'falls out of this function' trailer in emit_function(). For
        a literal-thunk call this is a+8 (the literal at a+4 is data, not
        the next instruction); same for a bare 'stmdb sp!, {pc}' (the other
        push-fake-return-address idiom - see load_analysis()'s matching
        extension) - everywhere else it's the usual a+4."""
        if (w >> 25) & 7 == 5 and w & (1 << 24):
            return self.call_return_site(a, w, self.branch_target(a, w))
        if w & 0x0FFFFFFF == 0x092D8000:
            return a + 8
        return a + 4

    def find_leaders(self):
        # Every classified-code address is independently dispatchable, not
        # just ones with a statically-known incoming branch: all state lives
        # in R[]/MEM (no local C variables carry meaning across
        # instructions, except inside a Duff loop - plan_duff_loops() below
        # discards those from this set once it turns them into a real loop),
        # so this matches real ARM2 semantics, where any address can be
        # jumped to. Needed for e.g. &19388/&2a3a0: real code with no static
        # caller anywhere (found only by running --trace-gaps), most likely
        # a level-object/skill dispatch table built at runtime.
        L = set(self.code)
        for a in self.code:
            w = self.word(a)
            if a in self.g.labels:
                L.add(a)
            t = (w >> 25) & 7
            if t == 5:
                tgt = self.branch_target(a, w)
                L.add(tgt)
                if w & (1 << 24) or self.overrides.get(a) == 'CALL':
                    L.add(self.call_return_site(a, w, tgt))        # return site
            if self.overrides.get(a) == 'CALL':
                L.add(a + 4)
            if t == 1 and ((w >> 16) & 15) == 15 and ((w >> 21) & 15) in (2, 4):
                v = ror(w & 0xFF, ((w >> 8) & 15) * 2)     # ADR: code addresses taken
                L.add((a + 8 + v if (w >> 21) & 15 == 4 else a + 8 - v) & M32)
        for a, b in self.fallthrough.items():
            L.add(b)
        for a, ents in self.duff.items():
            L.update(ents)
        for f in self.j['functions']:
            L.add(f[0])
        L.update(self.g.names)
        L.update(o for o in self.funcs)
        self.leaders = {a for a in L if a in self.code}

    def plan_duff_loops(self):
        """Replace unrolled bodies entered by computed 'add pc,pc,X' with loops.
        Requires identical, position-independent blocks and no other entries."""
        plans = {}
        other = set(self.leaders)
        for a, ents in self.duff.items():
            other -= set(ents)
        # labels that exist only because a data offset points there (e.g. a table
        # base 256 bytes before a table that follows the plotter) are not entries
        other -= {t for (t, b, u) in self.g.offset_words.values()}
        for a, ents in self.duff.items():
            w = self.word(a)
            p, _ = duff_entries(self.g, a)
            if p is None or w >> 28 != 14:
                continue
            end = max(ents)
            step = 4 * p
            b0 = end
            while b0 - step >= a + 4:
                b0 -= step
            tmpl = [self.word(b0 + 4 * k) for k in range(p)]
            fn = self.owner[a]
            ok = all(self.word(x) == tmpl[((x - b0) // 4) % p] and x in self.code
                     and self.owner[x] == fn for x in range(b0, end, 4))
            # position independence: same C at two different addresses
            ok = ok and all(self.translate(fn, b0 + 4 * k, tmpl[k]) ==
                            self.translate(fn, b0 + 4 * k + 0x1000, tmpl[k]) for k in range(p))
            ok = ok and not any(x in other for x in range(a + 8, end))
            if not ok:
                print('Duff site %x: kept as switch' % a)
                continue
            plans[a] = dict(b0=b0, end=end, p=p, n=(end - b0) // step, prefix=a + 4 if a + 4 < b0 else None)
            for x in range(a + 8, end):
                self.leaders.discard(x)
            self.leaders.discard(b0)
            if plans[a]['prefix'] is None:
                self.leaders.discard(a + 4)
        return plans

    # ---------------------------------------------------------------- operands
    def pc(self, v):
        """A PC-derived value (PC as an operand, a link address, a jump
        target). With --pcbias the image may really be running from a copy
        of itself somewhere else (LemBoot relocates to &40000 and runs from
        there), so everything the program can *observe* about its own PC -
        and so every PC-relative data access - is offset by the runtime's
        pc_bias. Function entry/dispatch still uses the unbiased address;
        call_addr() maps biased targets back."""
        return '(%s + pc_bias)' % h(v) if self.pcbias else h(v)

    def regv(self, n, a, pcoff, full):
        if n == 15:
            p = (a + pcoff) & 0x3FFFFFC
            return '(%s | PSR())' % self.pc(p) if full else self.pc(p)
        return 'R[%d]' % n

    def op2(self, a, w):
        """(value expr, carry-out expr, regshift) for a data-processing operand 2."""
        if w & (1 << 25):
            rot = ((w >> 8) & 15) * 2
            v = ror(w & 0xFF, rot)
            return h(v), (str(v >> 31) if rot else 'CF'), False
        rm, typ = w & 15, (w >> 5) & 3
        if w & 0x10:
            rs = (w >> 8) & 15
            rmv = self.regv(rm, a, 12, True)
            amt = '(%s & 0xFF)' % self.regv(rs, a, 8, True)
            return 'SHR(%s, %d, %s)' % (rmv, typ, amt), 'SHRC(%s, %d, %s)' % (rmv, typ, amt), True
        return self.imm_shift(self.regv(rm, a, 8, True), typ, (w >> 7) & 31) + (False,)

    @staticmethod
    def imm_shift(v, typ, amt):
        if typ == 0:
            if amt == 0:
                return v, 'CF'
            return 'SH_LSL(%s, %d)' % (v, amt), 'CY_LSL(%s, %d)' % (v, amt)
        if typ in (1, 2):
            n = amt or 32
            k = 'LSR' if typ == 1 else 'ASR'
            return 'SH_%s(%s, %d)' % (k, v, n), 'CY_%s(%s, %d)' % (k, v, n)
        if amt == 0:
            return 'SH_RRX(%s)' % v, 'CY_RRX(%s)' % v
        return 'SH_ROR(%s, %d)' % (v, amt), 'CY_ROR(%s, %d)' % (v, amt)

    # ---------------------------------------------------------------- control flow
    def call_code(self, t, ret):
        if t in self.code and t in self.leaders:
            return 'CALL(%s_%x, %s, %s);' % (self.prefix, self.owner[t], h(t), self.pc(ret))
        return 'npc = %s; CALLI(%s);' % (self.pc(t), self.pc(ret))

    def jump_code(self, fn, t):
        if t in self.code and self.owner.get(t) == fn and t in self.leaders:
            return 'goto L_%x;' % t
        return 'JUMP(%s);' % self.pc(t)

    def after_pc_write(self, fn, a):
        """npc has been set by an instruction at a (not a branch)."""
        ov = self.overrides.get(a)
        if ov == 'CALL':
            return 'CALLI(%s);' % self.pc(a + 4)
        if a in self.duff:
            return self.duff_dispatch(fn, a)
        return 'LEAVE();'

    def duff_dispatch(self, fn, a):
        if a in self.duffloops:
            d = self.duffloops[a]
            self.stats['duffloop'] += 1
            out = '{ uint32_t _t = npc%s; ' % (' - pc_bias' if self.pcbias else '')
            if d['prefix'] is not None:
                out += 'if (_t == %s) goto L_%x; ' % (h(d['prefix']), d['prefix'])
            out += ('if (_t >= %s && _t <= %s && (%s - _t) %% %d == 0) { _dn = (%s - _t) / %d; goto D_%x; } '
                    'LEAVE(); }' % (h(d['b0']), h(d['end']), h(d['end']), 4 * d['p'], h(d['end']),
                                    4 * d['p'], a))
            return out
        ents = [e for e in self.duff[a] if self.owner.get(e) == fn and e in self.leaders]
        self.stats['duff'] += 1
        return 'switch (npc%s) { %s default: LEAVE(); }' % (' - pc_bias' if self.pcbias else '', ' '.join(
            'case %s: goto L_%x;' % (h(e), e) for e in ents))

    # ---------------------------------------------------------------- translation
    def translate(self, fn, a, w):
        """C statements for instruction word w at address a (no prologue)."""
        cond = w >> 28
        if cond == 15:
            return []                                        # NV: never executes
        body = self.body(fn, a, w)
        if cond == 14 or not body:
            return body
        return ['if (C_%s) {' % CONDS[cond]] + ['    ' + l for l in body] + ['}']

    def body(self, fn, a, w):
        t = (w >> 25) & 7
        if t in (0, 1) and (w & 0x0FC000F0) == 0x90:
            return self.mul(a, w)
        if t in (0, 1) and (w & 0x0FB00FF0) == 0x01000090:
            return ['interp_exec(%s, %s);' % (self.pc(a), h(w))]  # SWP (rare)
        if t in (0, 1):
            return self.dataproc(fn, a, w)
        if t in (2, 3):
            if t == 3 and w & 0x10:
                return ['undefined_insn(%s, %s); LEAVE();' % (h(a), h(w))]
            return self.ldrstr(fn, a, w)
        if t == 4:
            return self.ldmstm(fn, a, w)
        if t == 5:
            tgt = self.branch_target(a, w)
            if w & (1 << 24):
                # R[14] is always call site + 4 (real ARM semantics; the
                # literal-thunk idiom itself depends on this) - only the
                # *expected return site* for the CALL() macro differs.
                return ['R[14] = %s | PSR();' % self.pc(a + 4), self.call_code(tgt, self.call_return_site(a, w, tgt))]
            if self.overrides.get(a) == 'CALL':
                return [self.call_code(tgt, a + 4)]
            return [self.jump_code(fn, tgt)]
        if t == 7 and (w >> 24) & 1:
            n = w & 0xFFFFFF
            out = ['SWI(%s, %s);' % (h(n), self.pc(a + 4))]
            if (n & ~0x20000) == 1 and a in self.fallthrough:
                out.append(self.jump_code(fn, self.fallthrough[a]))
            return out
        return ['undefined_insn(%s, %s); LEAVE();' % (h(a), h(w))]

    def mul(self, a, w):
        rd, rn, rs, rm = (w >> 16) & 15, (w >> 12) & 15, (w >> 8) & 15, w & 15
        s = 'S' if w & (1 << 20) else ''
        if w & (1 << 21):
            return ['MLA%s(%d, %d, %d, %d);' % (s, rd, rm, rs, rn)]
        return ['MUL%s(%d, %d, %d);' % (s, rd, rm, rs)]

    def dataproc(self, fn, a, w):
        op, s = (w >> 21) & 15, (w >> 20) & 1
        rn, rd = (w >> 16) & 15, (w >> 12) & 15
        b, c, regshift = self.op2(a, w)
        av = self.regv(rn, a, 12 if regshift else 8, False)
        name = DPOPS[op]
        if 8 <= op <= 11:
            if rd == 15:                                     # TEQP & co: PSR from result
                # ARM2: R15 as Rn reads as the bare address (PSR bits
                # zero) - only as Rm does it include the PSR. That's what
                # makes `TEQP PC,#0` mean "back to USR mode, flags clear"
                # (LemBoot &87fc, after OS_EnterOS). An earlier version
                # read the full PC+PSR here; harmless while processor
                # modes weren't modelled, wrong now that they are.
                e = {8: '%s & %s', 9: '%s ^ %s', 10: '%s - %s', 11: '%s + %s'}[op] % (av, b)
                return ['SETPSR(%s);' % e]
            if op in (8, 9):
                return ['DP_%s(%s, %s, %s);' % (name, av, b, c)]
            return ['DP_%s(%s, %s);' % (name, av, b)]
        if rd == 15:
            e = {0: '{a} & {b}', 1: '{a} ^ {b}', 2: '{a} - {b}', 3: '{b} - {a}', 4: '{a} + {b}',
                 5: '{a} + {b} + CF', 6: '{a} + ~{b} + CF', 7: '{b} + ~{a} + CF', 12: '{a} | {b}',
                 13: '{b}', 14: '{a} & ~{b}', 15: '~{b}'}[op].format(a=av, b=b)
            return ['SETPC(%s, %d);' % (e, s), self.after_pc_write(fn, a)]
        if op in (13, 15):
            args = [str(rd), b] + ([c] if s else [])
        elif op in LOGICAL:
            args = [str(rd), av, b] + ([c] if s else [])
        else:
            args = [str(rd), av, b]
        return ['DP_%s%s(%s);' % (name, 'S' if s else '', ', '.join(args))]

    def ldrstr(self, fn, a, w):
        p, u, bb, wbit, l = [(w >> k) & 1 for k in (24, 23, 22, 21, 20)]
        rn, rd = (w >> 16) & 15, (w >> 12) & 15
        if w & (1 << 25):
            off = self.imm_shift(self.regv(w & 15, a, 8, True), (w >> 5) & 3, (w >> 7) & 31)[0]
        else:
            off = h(w & 0xFFF)
        base = self.regv(rn, a, 8, False)
        wb = rn if ((not p or wbit) and rn != 15) else -1
        if l:
            if rd == 15:
                return ['LDRPC_(%s, %s, %d, %d, %d);' % (base, off, p, u, wb),
                        self.after_pc_write(fn, a)]
            return ['LDR_(%d, %s, %s, %d, %d, %d, %d);' % (rd, base, off, p, u, bb, wb)]
        val = '(%s | PSR())' % self.pc(a + 12) if rd == 15 else 'R[%d]' % rd
        return ['STR_(%s, %s, %s, %d, %d, %d, %d);' % (val, base, off, p, u, bb, wb)]

    def ldmstm(self, fn, a, w):
        p, u, s, wbit, l = [(w >> k) & 1 for k in (24, 23, 22, 21, 20)]
        rn = (w >> 16) & 15
        regs = [k for k in range(16) if w & (1 << k)]
        n = len(regs)
        base = 'R[%d]' % rn if rn != 15 else self.pc(a + 8)
        if u:
            start = '%s + %d' % (base, 4 if p else 0)
            wbv = '%s + %d' % (base, 4 * n)
        else:
            start = '%s - %d' % (base, 4 * n - (0 if p else 4))
            wbv = '%s - %d' % (base, 4 * n)
        wbs = 'R[%d] = %s; ' % (rn, wbv) if wbit and rn != 15 else ''
        if l:
            parts = ['LDM_BEGIN(%s) %s' % (start, wbs)]
            for k in regs:
                parts.append('LDM_PC(%d)' % s if k == 15 else 'LDM_R(%d)' % k)
            out = [' '.join(parts) + ' XFER_END;']
            if 15 in regs:
                out.append(self.after_pc_write(fn, a))
            return out
        parts = ['STM_BEGIN(%s)' % start]
        for k in regs:
            parts.append('STM_V(%s)' % ('(%s | PSR())' % self.pc(a + 12) if k == 15 else 'R[%d]' % k))
        return [' '.join(parts) + ' %sXFER_END;' % wbs]

    # ---------------------------------------------------------------- emission
    def emit_function(self, fn):
        addrs = self.funcs[fn]
        entries = [x for x in addrs if x in self.leaders]
        out = ['void %s_%x(uint32_t e)' % (self.prefix, fn), '{', '    switch (e) {']
        for x in entries:
            out.append('    case %s: goto L_%x;' % (h(x), x))
        out.append('    default: bad_entry(%s, e); return;' % h(fn))
        out.append('    }')
        own = set(addrs)
        loops = {d['b0']: (a, d) for a, d in self.duffloops.items() if self.owner[a] == fn}
        if loops:
            out.insert(2, '    uint32_t _dn;')
        skip_to = None
        for x in addrs:
            if skip_to is not None and x < skip_to:
                continue
            if x in loops:
                a, d = loops[x]
                if d['prefix'] is not None:
                    out.append('    _dn = %d;' % d['n'])            # prefix falls into a full run
                out.append('D_%x:' % a)
                out.append('    while (_dn--) {   /* %d x %d-instruction block, unrolled at %x-%x */' % (
                    d['n'], d['p'], d['b0'], d['end']))
                for k in range(d['p']):
                    y = d['b0'] + 4 * k
                    out.append('        I(%s);' % h(y))
                    out += ['        ' + l for l in self.translate(fn, y, self.word(y))]
                    self.stats['insns'] += 1
                out.append('    }')
                skip_to = d['end']
                if d['end'] in self.leaders:
                    out.append('L_%x:' % d['end'])
                    # fall through into the instruction at end
                w_end = d['end']
                if w_end in own:
                    out.append('    I(%s);' % h(w_end))
                    out += ['    ' + l for l in self.translate(fn, w_end, self.word(w_end))]
                    self.stats['insns'] += 1
                    if w_end + 4 not in own:
                        out.append('    JUMP(%s);' % self.pc(w_end + 4))
                    skip_to = w_end + 4
                continue
            if x in self.leaders:
                out.append('L_%x:' % x)
            w = self.word(x)
            out.append('    I(%s);' % h(x))
            self.stats['insns'] += 1
            if x in self.smc:
                out += ['    ' + l for l in self.smc_switch(fn, x, w)]
            else:
                out += ['    ' + l for l in self.translate(fn, x, w)]
            nxt = self.natural_next(x, w)
            if nxt not in own:
                out.append('    JUMP(%s);' % self.pc(nxt))        # falls out of this function
        out.append('}')
        return out

    def smc_switch(self, fn, a, w):
        self.stats['smc'] += 1
        forms = [w] + [v for v in self.smc[a] if v != w]
        out = ['switch (*(uint32_t *)(MEM + %s)) {' % self.pc(a)]
        for v in forms:
            out.append('case %s:' % h(v))
            out += ['    ' + l for l in self.translate(fn, a, v)]
            out.append('    break;')
        out.append('default:   /* instruction form not seen during analysis */')
        out.append('    if (interp_exec(%s, *(uint32_t *)(MEM + %s))) LEAVE();' % (self.pc(a), self.pc(a)))
        out.append('}')
        return out

    def write(self, outdir, nfiles):
        fns = sorted(self.funcs)
        hdr = ['/* generated by gen_c.py */', '#include "roger_cpu.h"', '']
        hdr += ['void %s_%x(uint32_t);' % (self.prefix, f) for f in fns]
        open(os.path.join(outdir, 'gen.h'), 'w').write('\n'.join(hdr) + '\n')
        chunks = [fns[i::nfiles] for i in range(nfiles)]
        for i, ch in enumerate(chunks):
            out = ['/* generated by gen_c.py - do not edit */', '#include "gen.h"', '']
            for f in sorted(ch):
                out += self.emit_function(f)
                out.append('')
            open(os.path.join(outdir, 'code%02d.c' % i), 'w').write('\n'.join(out) + '\n')
        # entry table and code bitmap
        tab = ['/* generated by gen_c.py */', '#include "gen.h"',
               'const struct roger_entry %s_entries[] = {' % self.tabprefix]
        ents = sorted(self.leaders)
        tab += ['    {%s, %s_%x},' % (h(a), self.prefix, self.owner[a]) for a in ents]
        tab.append('};')
        tab.append('const unsigned %s_nentries = %d;' % (self.tabprefix, len(ents)))
        nwords = (self.end - BASE) // 4
        bits = bytearray((nwords + 7) // 8)
        skip = set(self.smc) | set(self.sp.writes)
        for a in self.code:
            if a not in skip:
                k = (a - BASE) // 4
                bits[k // 8] |= 1 << (k % 8)
        tab.append('const uint8_t %s_codemap[] = {' % self.tabprefix)
        for i in range(0, len(bits), 16):
            tab.append('    ' + ', '.join('%d' % b for b in bits[i:i + 16]) + ',')
        tab.append('};')
        tab.append('const uint32_t %s_img_base = %s;' % (self.tabprefix, h(BASE)))
        tab.append('const uint32_t %s_img_end = %s;' % (self.tabprefix, h(self.end)))
        tab.append('const struct roger_image %s_image = {%s, %s, %s_entries, %d, %s_codemap, %s};' % (
            self.tabprefix, h(BASE), h(self.end), self.tabprefix, len(ents), self.tabprefix,
            "'%s'" % COVTAG if COVTAG else '0'))
        open(os.path.join(outdir, 'entries.c'), 'w').write('\n'.join(tab) + '\n')
        print('functions %d, instructions %d, entry points %d, SMC sites %d, Duff jumps %d (%d as loops), files %d' % (
            len(fns), self.stats['insns'], len(ents), self.stats['smc'], self.stats['duff'] + self.stats['duffloop'],
            self.stats['duffloop'], nfiles))


def main():
    opts = dict(x[2:].split('=', 1) if '=' in x else (x[2:], '1') for x in sys.argv[1:])
    global BASE, COVTAG
    BASE = int(opts.get('base', '8000'), 16)
    COVTAG = opts.get('covtag', '')
    img_path = opts.get('img', os.path.join(HERE, '..', 'extracted_decompressed', 'LemProg.bin'))
    json_path = opts.get('json', os.path.join(GH, 'lemprog.json'))
    tsvdir = opts.get('tsvdir', os.path.join(GH, 'out', 'lemprog'))
    dyn = [d for d in opts.get('dyn', '').split(',') if d]
    r = Recomp(img_path, json_path, tsvdir, dyn, loops='loops' in opts,
               prefix=opts.get('prefix', 'F'), tabprefix=opts.get('tabprefix', 'recomp'),
               pcbias='pcbias' in opts)
    out = opts.get('out', os.path.join(HERE, 'gen'))
    os.makedirs(out, exist_ok=True)
    r.write(out, int(opts.get('files', 16)))


if __name__ == '__main__':
    main()
