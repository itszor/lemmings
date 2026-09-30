"""Generate reassemblable GNU as source for a RISC OS absolute from the
spider's classification (galdan.json + its .pickle) and Ghidra's function
names (out/functions.tsv), then verify it rebuilds byte-identically.

Usage: gen_asm.py image loadaddr galdan.json outdir
"""
import sys, os, re, json, pickle, subprocess, collections

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import spider                      # noqa: F401  (needed to unpickle)
from export_ghidra import swi_name

M32 = 0xFFFFFFFF
WS_TOP = 0xA8000          # top of the 640K wimpslot: workspace lives above the image
TOOLS = 'arm-none-eabi-'


def objdump(path, base):
    out = subprocess.run([TOOLS + 'objdump', '-z', '-b', 'binary', '-m', 'armv2a', '-D',
                          '--adjust-vma=0x%x' % base, path],
                         capture_output=True, text=True, check=True).stdout
    dis = {}
    for line in out.splitlines():
        m = re.match(r'\s*([0-9a-f]+):\s+([0-9a-f]{8})\s+(.*)$', line)
        if m:
            dis[int(m.group(1), 16)] = m.group(3).strip()
    return dis


class Gen:
    def __init__(self, img, base, j, sp, names, extra_code):
        self.img, self.base, self.j, self.sp = img, base, j, sp
        self.end = base + len(img)
        self.code = set(sp.code) | extra_code
        self.spec_all = set(sp.spec) | extra_code    # carveable: speculative or Ghidra-only
        self.carved = []
        self.names = names
        self.labels = {}                  # addr -> name
        self.inst_fallback = set()        # addrs forced to .inst
        self.offset_words = {}            # literal addr -> (target, use insn addr)
        self.swis = {}
        self.pads = {}                    # addr -> bytes of filler inserted before it
        self.dyn = []                     # run-time fact files (provtrack.py)
        self.notes = {}                   # addr -> comment (asm/notes.json)

    def word(self, a):
        return int.from_bytes(self.img[a - self.base:a - self.base + 4], 'little')

    def inside(self, a):
        return self.base <= a < self.end

    # ---- label assignment -------------------------------------------------
    def label(self, a, kind='L'):
        if a not in self.labels:
            self.labels[a] = '%s_%x' % (kind, a)
        return self.labels[a]

    def find_offset_words(self):
        """ldr rX,[pc,#lit] ... add rY,pc,rX | ldr/str rY,[pc,rX]  =>  lit is
        (target - (use+8)); emit it symbolically."""
        for a in sorted(self.code):
            w = self.word(a)
            if (w & 0x0F7F0000) != 0x051F0000 or w >> 28 != 14:    # ldr rX,[pc,#+-imm]
                continue
            rx = (w >> 12) & 15
            off = w & 0xFFF
            lit = a + 8 + (off if w & (1 << 23) else -off)
            if not self.inside(lit) or lit in self.code or lit & 3:
                continue
            v = self.word(lit)
            for u in range(a + 4, a + 28, 4):
                if u not in self.code:
                    break
                x = self.word(u)
                use = False
                # add rY, pc, rX  (no shift)
                if (x & 0x0FEF0FF0) == 0x008F0000 and (x & 15) == rx:
                    use = True
                # ldr/str{b} rY, [pc, rX]  (pre-indexed, up, no shift, no writeback)
                elif (x & 0x0FAF0FF0) == 0x078F0000 and (x & 15) == rx:
                    use = True
                if use:
                    t = (u + 8 + v) & M32
                    if (self.inside(t) or self.end <= t < WS_TOP) and lit not in self.offset_words:
                        self.offset_words[lit] = (t, u + 8, u)
                    break
                # stop if rX is redefined or flow leaves straight-line code
                t3 = (x >> 25) & 7
                if t3 == 5 or (x >> 24) & 15 == 0xF:
                    break
                if t3 in (0, 1, 2, 3) and ((x >> 12) & 15) == rx:
                    break
                if t3 == 4 and (x >> 20) & 1 and x & (1 << rx):
                    break

    def ref(self, tgt, kind):
        """Symbolic reference; an address inside an instruction word becomes
        label+n (e.g. string-1 pointers for pre-increment loops)."""
        if tgt & 3 and (tgt & ~3) in self.code:
            return '%s+%d' % (self.label(tgt & ~3, 'L'), tgt & 3)
        return self.label(tgt, kind)

    def assign_labels(self):
        for a, n in self.names.items():
            self.labels[a] = n
        for a in self.sp.writes:
            if a not in self.code:
                self.label(a, 'var')
        for s, l, t in self.j['strings']:
            self.label(s, 'str')
        self.labels[self.base] = '_start'
        self.find_offset_words()
        self.add_dynamic_facts()
        self.static_tables()
        self.extend_tables()
        for lit, (t, b, u) in self.offset_words.items():
            if not (t & 3 and (t & ~3) in self.code):
                self.label(t, 'ws' if t >= self.end else 'd' if t not in self.code else 'L')
            if u is not None and b == u + 8:
                self.label(u, 'L')
            else:
                self.label(b, 'ws' if b >= self.end else 'd' if b not in self.code else 'L')

    def carve_spec(self, x):
        """A run-time data fact landed in speculative code: remove the
        surrounding data-looking (condition EQ) words from the code set."""
        spec = self.spec_all
        lo = x
        while lo - 4 in self.code and lo - 4 in spec and self.word(lo - 4) >> 28 == 0:
            lo -= 4
        hi = x
        while hi in self.code and hi in spec and self.word(hi) >> 28 == 0:
            hi += 4
        hi = max(hi, x + 4)                     # the table word itself always goes
        for a in range(lo, hi, 4):
            self.code.discard(a)
            if self.names.get(a, '').startswith('spec_'):
                del self.names[a]
                self.labels.pop(a, None)
                if hi in self.code and hi not in self.names:
                    self.names[hi] = self.labels[hi] = 'spec_%x' % hi
        self.carved.append((lo, hi))

    # ---- tables of PC-relative offsets ------------------------------------------
    def target_kind(self, t):
        if t in self.code and not t & 3:
            return 'C'
        if self.inside(t):
            return 'i' if t not in self.code else None
        if self.end <= t < WS_TOP:
            return 'w'
        return None

    def add_table_word(self, x, b, why):
        """x holds (target - b).  Returns False if x can't be a table word."""
        if x & 3 or not self.inside(x) or x in self.offset_words:
            return False
        if any(s <= x < s + l for s, l in self.str_ranges):
            return False
        t = (b + self.word(x)) & M32
        if self.target_kind(t) is None:
            return False
        if x in self.code:
            # only reclaim speculative code for words that look like offsets
            if x in self.spec_all and x not in self.firm_code() and self.word(x) >> 28 in (0, 15):
                self.carve_spec(x)
            if x in self.code:
                return False
        self.offset_words[x] = (t, b, b - 8 if b - 8 in self.code else None)
        self.table_words[why] = self.table_words.get(why, 0) + 1
        return True

    def firm_code(self):
        if not hasattr(self, '_firm'):
            self._firm = set(self.sp.code) - set(self.sp.spec)
        return self._firm

    def static_tables(self):
        """ldr rX,[rT,rI,lsl #s]{!} with rT a known PC-derived address, followed by
        a PC-relative use of rX: the table at rT holds offsets.  Bounded by a mask
        on rI when there is one, else by target plausibility."""
        self.table_words = {}
        self.table_rejects = {}
        code = sorted(self.code)
        for u in code:
            w = self.word(u)
            if (w & 0x0FEF0FF0) == 0x008F0000:        # add rY, pc, rX (rY may be pc)
                rx = w & 15
            elif (w & 0x0FAF0FF0) == 0x078F0000:      # ldr/str rY, [pc, rX]
                rx = w & 15
            else:
                continue
            # the load defining rx, then the table base register's value
            ld = None
            for a in range(u - 4, u - 24, -4):
                if a not in self.code: break
                y = self.word(a)
                if (y & 0x0E100000) == 0x06100000 and ((y >> 12) & 15) == rx and not (y >> 22) & 1 \
                        and (y >> 24) & 1 and (y & 0xF90) == 0 or \
                        ((y & 0x0E100000) == 0x06100000 and ((y >> 12) & 15) == rx and not (y >> 22) & 1
                         and (y >> 24) & 1 and ((y >> 5) & 3) == 0 and not y & 0x10):
                    ld = a; break
                if ((y >> 12) & 15) == rx or (y >> 25) & 7 == 5:
                    break
            if ld is None:
                continue
            y = self.word(ld)
            rt, ri, sh = (y >> 16) & 15, y & 15, (y >> 7) & 31
            if rt == 15 or ri == 15:
                continue
            tbase = self.const_before(ld, rt)
            if tbase is None:
                continue
            count = self.index_bound(ld, ri)
            stride = 1 << sh
            if sh == 0:                      # index is a byte offset into a word table
                stride = 4
                if count: count = (count + 3) // 4
            k = 0
            rejected = []
            while count is None or k < count:
                if not self.add_table_word(tbase + k * stride, u + 8, 'static %x' % u):
                    if count is not None and k < count:
                        rejected.append(tbase + k * stride)
                    break
                k += 1
                if k > 256: break
            if rejected:
                self.table_rejects[u] = (tbase, stride, count, rejected)

    def const_before(self, at, r):
        """Value of register r just before 'at' if set by adr or ldr-lit + add pc."""
        for a in range(at - 4, at - 32, -4):
            if a not in self.code: return None
            y = self.word(a)
            if ((y >> 12) & 15) != r:
                if (y >> 25) & 7 == 5: return None
                continue
            if (y & 0x0FEF0000) in (0x028F0000, 0x024F0000):   # adr: add/sub r, pc, #imm
                imm, rot = y & 0xFF, ((y >> 8) & 15) * 2
                v = ((imm >> rot) | (imm << (32 - rot))) & M32 if rot else imm
                return (a + 8 + v if (y >> 21) & 15 == 4 else a + 8 - v) & M32
            if (y & 0x0FEF0FF0) == 0x008F0000 and (y & 15) == r:  # add r, pc, r
                for b in range(a - 4, a - 16, -4):
                    z = self.word(b)
                    if (z & 0x0F7F0000) == 0x051F0000 and ((z >> 12) & 15) == r:
                        off = z & 0xFFF
                        lit = b + 8 + (off if z & (1 << 23) else -off)
                        return (a + 8 + self.word(lit)) & M32
                return None
            return None
        return None

    def index_bound(self, at, r):
        for a in range(at - 4, at - 32, -4):
            if a not in self.code: return None
            y = self.word(a)
            if ((y >> 12) & 15) == r and (y & 0x0FE00000) == 0x02000000:       # and r, r, #m
                return (y & 0xFF) + 1 if not (y >> 8) & 15 else None
            if ((y >> 12) & 15) == r and (y & 0x0FE00000) == 0x03C00000:       # bic r, r, #m
                m = y & 0xFF if not (y >> 8) & 15 else None
                return (~m & 0xFF) + 1 if m is not None else None
            if (y & 0x0FF00000) == 0x03500000 and ((y >> 16) & 15) == r:       # cmp r, #n
                return None
            if ((y >> 12) & 15) == r:
                return None
        return None

    def extend_tables(self):
        """Grow run-time-observed tables to neighbouring words whose targets
        (same base) are of the same kind as the observed ones."""
        groups = {}
        for x, (t, b, u) in list(self.offset_words.items()):
            if x in self.dyn_words:
                groups.setdefault(b, []).append(x)
        for b, xs in groups.items():
            if len(xs) < 2 and not any(self.table_like(x) for x in xs):
                continue
            kinds = {self.target_kind(self.offset_words[x][0]) for x in xs}
            if len(kinds) != 1:
                continue
            kind = kinds.pop()
            for x in xs:
                for step in (4, -4):
                    y = x + step
                    while self.inside(y) and y not in self.offset_words:
                        t = (b + self.word(y)) & M32
                        if self.target_kind(t) != kind or (kind == 'C' and not self.is_entry(t)):
                            break
                        if not self.add_table_word(y, b, 'extend %x' % b):
                            break
                        y += step

    def table_like(self, x):
        return False

    def is_entry(self, t):
        return t in self.code

    def add_dynamic_facts(self):
        """Offset words observed at run time (asm/provtrack.py)."""
        self.dyn_added = 0
        self.dyn_words = set()
        self.str_ranges = [(s, l) for s, l, t in self.j['strings']]
        for path in self.dyn:
            d = json.load(open(path))
            for x, (t, b, use) in d['offsets'].items():
                x, t, b, use = int(x, 16), int(t, 16), int(b, 16), int(use, 16)
                if x in self.code and x in self.spec_all:
                    self.carve_spec(x)
                if x in self.code or x & 3:
                    print('dynamic offset word %x is in code / unaligned - skipped' % x)
                    continue
                if x in self.offset_words:
                    t0, b0, _ = self.offset_words[x]
                    assert (t0 - b0) & M32 == (t - b) & M32, hex(x)
                    continue
                self.offset_words[x] = (t, b, use if b == use + 8 else None)
                self.dyn_words.add(x)
                self.dyn_added += 1

    # ---- instruction rendering --------------------------------------------
    def render_insn(self, a, text):
        w = self.word(a)
        if a in self.inst_fallback or '<UNDEFINED>' in text or 'illegal' in text \
                or (w >> 28) == 0xF:
            return '.inst\t0x%08x' % w, text
        orig = text
        text = text.split('\t@')[0].split(' @ ')[0].strip() if '@' in text else text
        t3 = (w >> 25) & 7
        # branches
        if t3 == 5:
            off = w & 0xFFFFFF
            if off & 0x800000:
                off -= 0x1000000
            tgt = (a + 8 + off * 4) & 0x3FFFFFC
            if self.inside(tgt):
                mn = text.split()[0]
                return '%s\t%s' % (mn, self.label(tgt)), None
            return '.inst\t0x%08x' % w, orig
        # SWI
        if t3 == 7 and (w >> 24) & 15 == 0xF:
            n = w & 0xFFFFFF
            name = re.sub(r'[^A-Za-z0-9_]', '_', swi_name(n))
            self.swis[name] = n
            mn = text.split()[0].replace('svc', 'swi')
            return '%s\t%s' % (mn, name), None
        # PC-relative immediate ldr/str
        if t3 == 2 and ((w >> 16) & 15) == 15 and (w >> 24) & 1 and not (w >> 21) & 1:
            off = w & 0xFFF
            tgt = a + 8 + (off if w & (1 << 23) else -off)
            if self.inside(tgt):
                m = re.match(r'(\S+)\s+(\w+),', text)
                kind = 'var' if tgt in self.sp.writes and tgt not in self.code else \
                       ('L' if tgt in self.code else 'd')
                return '%s\t%s, %s' % (m.group(1), m.group(2), self.ref(tgt, kind)), None
        # ADR: add/sub rX, pc, #imm
        if t3 == 1 and ((w >> 16) & 15) == 15 and ((w >> 21) & 15) in (2, 4) \
                and not (w >> 20) & 1 and ((w >> 12) & 15) != 15:
            imm = w & 0xFF
            rot = ((w >> 8) & 15) * 2
            v = ((imm >> rot) | (imm << (32 - rot))) & M32 if rot else imm
            tgt = (a + 8 + v if (w >> 21) & 15 == 4 else a + 8 - v) & M32
            if self.inside(tgt):
                cond = ['eq', 'ne', 'cs', 'cc', 'mi', 'pl', 'vs', 'vc',
                        'hi', 'ls', 'ge', 'lt', 'gt', 'le', '', 'nv'][w >> 28]
                kind = 'L' if tgt in self.code else 'd'
                return 'adr%s\t%s, %s' % (cond, 'r%d' % ((w >> 12) & 15), self.ref(tgt, kind)), None
        # stack aliases: be explicit so the assembler can't pick str/ldr forms
        m = re.match(r'(push|pop)(\w*)\s+(\{.*\})', text)
        if m:
            text = '%s%s\tsp!, %s' % ('stmdb' if m.group(1) == 'push' else 'ldmia',
                                      m.group(2), m.group(3))
        return text.replace('svc', 'swi'), None

    # ---- data rendering ----------------------------------------------------
    @staticmethod
    def asc(bs):
        out = []
        for c in bs:
            if c == 34: out.append('\\"')
            elif c == 92: out.append('\\\\')
            elif 32 <= c < 127: out.append(chr(c))
            else: out.append('\\%03o' % c)
        return '"' + ''.join(out) + '"'

    def emit_data(self, lo, hi, out, strings, pad=False):
        if pad:
            out.append('\t.fill\t%d, 4, 0xe7ffdefe\t@ relocation-test padding' % (self.pads[lo] // 4))
        a = lo
        while a < hi:
            if a != lo and a in self.pads:
                return self.emit_data(a, hi, out, strings, pad=True)
            if a in self.labels and a != lo or (a == lo and a in self.labels):
                out.append('%s:' % self.labels[a])
            nxt = min([x for x in self.labels if a < x < hi] + [x for x in self.pads if a < x < hi] + [hi])
            if a in strings:
                e = min(a + strings[a], nxt)
                bs = self.img[a - self.base:e - self.base]
                if bs.endswith(b'\0') and b'\0' not in bs[:-1]:
                    out.append('\t.asciz\t%s' % self.asc(bs[:-1]))
                else:
                    out.append('\t.ascii\t%s' % self.asc(bs))
                a = e
                continue
            # up to next string start, label or end
            stop = min([s for s in strings if a < s < nxt] +
                       [o for o in self.offset_words if a < o < nxt] + [nxt])
            while a < stop:
                if a & 3 or stop - a < 4:
                    n = min(stop - a, 4 - (a & 3) if a & 3 else stop - a)
                    out.append('\t.byte\t' + ', '.join('0x%02x' % b for b in self.img[a - self.base:a - self.base + n]))
                    a += n
                    continue
                if a in self.offset_words:
                    t, b, u = self.offset_words[a]
                    tl = self.ref(t, 'd')
                    if u is not None and b == u + 8:
                        out.append('\t.word\t%s - (%s + 8)\t@ PC-relative offset used at %x' % (
                            tl, self.labels[u], u))
                    else:
                        out.append('\t.word\t%s - %s\t@ offset relative to %x' % (tl, self.labels[b], b))
                    a += 4
                    continue
                n = 0
                ws = []
                while a + 4 <= stop and n < 8 and a not in self.offset_words:
                    ws.append('0x%08x' % self.word(a)); a += 4; n += 1
                    if a in strings or a in self.labels:
                        break
                out.append('\t.word\t' + ', '.join(ws))

    # ---- whole file ----------------------------------------------------------
    def generate(self, dis):
        j = self.j
        comments = collections.defaultdict(list)
        for a, kind, text in j['comments']:
            if kind != 'EOL' or 'continuation' in text:
                comments[a].append((kind, text))
        for a, text in self.notes.items():
            comments[a].append(('PRE', text))
        spec = set(a for a, s in j['functions'] if s)
        strings = {s: l for s, l, t in j['strings'] if s not in self.code}
        for x in sorted(self.code):          # pre-pass: create every label first
            self.render_insn(x, dis.get(x, ''))
        body = []
        a = self.base
        while a < self.end:
            if a in self.pads:
                body.append('\t.fill\t%d, 4, 0xe7ffdefe\t@ relocation-test padding' % (self.pads[a] // 4))
            if a in self.code and a + 4 <= self.end:
                for kind, text in comments.get(a, ()):
                    body.append('')
                    for ln in text.split('\n'):
                        body.append('\t@ ' + ln)
                if a in self.labels:
                    if a in self.names or a == self.base:
                        body.append('')
                        body.append('@ ' + '-' * 70)
                        if a in spec:
                            body.append('@ (found by speculative tracing - not reached from _start)')
                    body.append('%s:' % self.labels[a])
                src, why = self.render_insn(a, dis.get(a, ''))
                note = '%x' % a
                if why:
                    note += '  ' + why
                body.append('\t%-40s@ %s' % (src, note))
                a += 4
            else:
                e = a
                while e < self.end and not (e in self.code and not e & 3) and \
                        not (e in self.pads and e != a):
                    e += 1
                body.append('')
                self.emit_data(a, e, body, strings)
                a = e
        head = ['@ Galactic Dan - RISC OS absolute (load/exec &%X)' % self.base,
                '@ Generated by gen_asm.py from spider + Ghidra analysis.',
                '@ Build: see build.sh (GNU as, -march=armv2a); must reproduce the original byte-for-byte.',
                '',
                '\t.syntax unified',
                '\t.arch\tarmv2a',
                '\t.arm',
                '\t.text',
                '\t.global _start',
                '']
        for name, n in sorted(self.swis.items(), key=lambda kv: kv[1]):
            head.append('\t.equ\t%-32s 0x%x' % (name + ',', n))
        tail = ['', '\t.balign\t4', '_image_end:', '',
                '@ Workspace above the image, addressed PC-relatively by the code.',
                '@ Defined relative to _image_end so it moves if the code changes size.']
        for a in sorted(x for x in self.labels if x >= self.end):
            tail.append('\t.set\t%-24s _image_end + 0x%x' % (self.labels[a] + ',', a - self.end))
        return '\n'.join(head + body + tail) + '\n'


def build(outdir):
    r = subprocess.run(['sh', os.path.join(outdir, 'build.sh')], capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr


def main():
    args = [x for x in sys.argv[1:] if not x.startswith('--')]
    opts = dict(x[2:].split('=', 1) for x in sys.argv[1:] if x.startswith('--'))
    path, base, jpath, outdir = args[0], int(args[1], 16), args[2], args[3]
    pads = {}
    for p in filter(None, opts.get('pad', '').split(',')):
        a, n = p.split(':')
        pads[int(a, 16)] = int(n, 16)
    os.makedirs(outdir, exist_ok=True)
    img = open(path, 'rb').read()
    j = json.load(open(jpath))
    sp = pickle.load(open(jpath + '.pickle', 'rb'))
    names = {}
    tsv = os.path.join(HERE, 'out', 'functions.tsv')
    if os.path.exists(tsv):
        for line in open(tsv).read().splitlines()[1:]:
            e, n = line.split('\t')[:2]
            e = int(e, 16)
            if e < 0x10000000:
                # Ghidra thunks inherit their target's name and it makes functions
                # at some switch cases (caseD_*): keep only address-derived names.
                names[e] = n if n in ('sub_%x' % e, 'spec_%x' % e, '_start') else 'sub_%x' % e
    extra = set()
    go = os.path.join(HERE, 'out', 'ghidra_only_code.txt')
    if os.path.exists(go):
        for line in open(go):
            s, e = (int(x, 16) for x in line.split('-'))
            words = range(s & ~3, e + 1, 4)
            strs = [(a, a + l) for a, l, t in j['strings']]
            ok = all(spider.valid_arm2(int.from_bytes(img[x - base:x - base + 4], 'little')) is None
                     for x in words) and not any(a < e + 1 and s < b for a, b in strs)
            print('ghidra-only code %x-%x: %s' % (s, e, 'accepted' if ok else 'rejected (invalid insn or string)'))
            if ok:
                extra.update(words)
    dis = objdump(path, base)

    with open(os.path.join(outdir, 'build.sh'), 'w') as f:
        f.write('''#!/bin/sh
# Reassemble galdan.s and compare with the original image.
set -e
cd "$(dirname "$0")"
%(t)sas -march=armv2a -o galdan.o galdan.s
%(t)sld -Ttext=0x%(b)x -e _start --no-warn-rwx-segments -o galdan.elf galdan.o
%(t)sobjcopy -O binary -j .text galdan.elf GalacticDan,ff8
cmp GalacticDan,ff8 "%(img)s" && echo "IDENTICAL to original"
''' % dict(t=TOOLS, b=base, img=os.path.relpath(os.path.abspath(path), os.path.abspath(outdir))))

    fallback = set()
    for it in range(10):
        g = Gen(img, base, j, sp, names, extra)
        g.inst_fallback = fallback
        g.pads = pads
        g.dyn = [p for p in opts.get('dyn', '').split(',') if p]
        g.notes = {int(k, 16): v for k, v in json.load(open(opts['notes'])).items()} if 'notes' in opts else {}
        g.assign_labels()
        src = g.generate(dis)
        open(os.path.join(outdir, 'galdan.s'), 'w').write(src)
        rc, log = build(outdir)
        if pads:
            print('padded build:', 'ok' if os.path.exists(os.path.join(outdir, 'GalacticDan,ff8')) else 'FAILED')
            print('\n'.join(l for l in log.splitlines() if 'Error' in l)[:3000])
            break
        if 'IDENTICAL' in log:
            print('iteration %d: identical; %d instructions emitted as .inst' % (it, len(fallback)))
            break
        # assembler errors: map line numbers back to addresses
        lines = src.split('\n')
        bad = set()
        for m in re.finditer(r'galdan\.s:(\d+): Error', log):
            ln = lines[int(m.group(1)) - 1]
            mm = re.search(r'@ ([0-9a-f]+)', ln)
            if mm: bad.add(int(mm.group(1), 16))
        if not bad and os.path.exists(os.path.join(outdir, 'GalacticDan,ff8')):
            new = open(os.path.join(outdir, 'GalacticDan,ff8'), 'rb').read()
            if len(new) != len(img):
                print('length mismatch', len(new), len(img)); print(log[-2000:]); break
            for off in range(0, len(img), 4):
                if new[off:off + 4] != img[off:off + 4]:
                    bad.add(base + off)
        bad -= fallback
        if not bad:
            print('stuck:'); print(log[-3000:]); break
        if it == 0: print("\n".join(l for l in log.splitlines() if "Error" in l)[:1500])
        print('iteration %d: %d mismatches, e.g. %s' % (it, len(bad),
              ', '.join('%x' % b for b in sorted(bad)[:8])))
        fallback |= {b for b in bad if b in g.code}
        if not (bad & g.code):
            print('mismatch in data:', ['%x' % b for b in sorted(bad)[:20]]); print(log[-2000:]); break
    st = collections.Counter()
    print('source lines: %d, labels: %d, SWI names: %d, symbolic offsets: %d (%d from run-time facts)' % (
        src.count('\n'), len(g.labels), len(g.swis), len(g.offset_words), g.dyn_added))
    for k, n in sorted(g.table_words.items()):
        print('  table words from %s: %d' % (k, n))
    for u, (tb, st, cnt, rej) in sorted(g.table_rejects.items()):
        print('  table at %x (use %x, stride %d, %s entries): rejected %s' % (
            tb, u, st, cnt, ' '.join('%x=%08x' % (x, g.word(x)) for x in rej[:8])))
    lo = sum(h - l for l, h in g.carved) // 4
    print('speculative/Ghidra-only code words reclassified as table data: %d' % lo)


if __name__ == '__main__':
    main()
