"""Minimal ARM2 (26-bit PC) emulator for peeling RISC OS loaders."""
import struct

M32 = 0xFFFFFFFF
N_, Z_, C_, V_ = 1 << 31, 1 << 30, 1 << 29, 1 << 28


def ror(v, s):
    s &= 31
    return ((v >> s) | (v << (32 - s))) & M32 if s else v


class Stop(Exception):
    pass


class ARM:
    def __init__(self, memsize=0x1000000):
        self.mem = bytearray(memsize)
        self.r = [0] * 16          # r[15] = PC (address only)
        self.flags = 0             # NZCV in top bits
        self.mode = 0              # 0 = USR (26-bit mode bits); IF flags kept 0
        self.swi_handler = None
        self.steps = 0
        self.trace = False
        self.write_hook = None

    # ---- memory ----
    def rw(self, a):
        a &= 0x3FFFFFF
        v = struct.unpack_from('<I', self.mem, a & ~3)[0]
        return ror(v, (a & 3) * 8)

    def ww(self, a, v):
        a &= 0x3FFFFFC
        if self.write_hook: self.write_hook(a, 4)
        struct.pack_into('<I', self.mem, a, v & M32)

    def rb(self, a):
        return self.mem[a & 0x3FFFFFF]

    def wb(self, a, v):
        a &= 0x3FFFFFF
        if self.write_hook: self.write_hook(a, 1)
        self.mem[a] = v & 0xFF

    def r15full(self):
        return (self.r[15] & 0x3FFFFFC) | self.flags | self.mode

    def cond(self, c):
        f = self.flags
        n, z, cc, v = bool(f & N_), bool(f & Z_), bool(f & C_), bool(f & V_)
        return [z, not z, cc, not cc, n, not n, v, not v, cc and not z, (not cc) or z,
                n == v, n != v, (not z) and n == v, z or n != v, True, False][c]

    def shift(self, v, typ, amt, carry, imm):
        # returns (value, carry_out)
        if typ == 0:  # LSL
            if amt == 0: return v, carry
            if amt < 32: return (v << amt) & M32, (v >> (32 - amt)) & 1
            if amt == 32: return 0, v & 1
            return 0, 0
        if typ == 1:  # LSR
            if amt == 0 and imm: amt = 32
            if amt == 0: return v, carry
            if amt < 32: return v >> amt, (v >> (amt - 1)) & 1
            if amt == 32: return 0, v >> 31
            return 0, 0
        if typ == 2:  # ASR
            if amt == 0 and imm: amt = 32
            if amt == 0: return v, carry
            if amt >= 32:
                b = v >> 31
                return (M32 if b else 0), b
            sv = v - (1 << 32) if v & 0x80000000 else v
            return (sv >> amt) & M32, (v >> (amt - 1)) & 1
        # ROR / RRX
        if amt == 0 and imm:
            return ((carry << 31) | (v >> 1)), v & 1
        if amt == 0: return v, carry
        amt &= 31
        if amt == 0: return v, v >> 31
        return ror(v, amt), (v >> (amt - 1)) & 1

    def reg_op(self, i, carry, for_rn=False):
        rm = i & 15
        typ = (i >> 5) & 3
        if i & 0x10:  # register shift
            amt = self.getr(i >> 8 & 15) & 0xFF
            v = self.getr(rm, 12)
            return self.shift(v, typ, amt, carry, False)
        v = self.getr(rm, 8)
        return self.shift(v, typ, (i >> 7) & 31, carry, True)

    def getr(self, n, pcoff=8, full=True):
        if n == 15:
            pc = (self.r[15] + pcoff) & 0x3FFFFFC
            return (pc | self.flags | self.mode) if full else pc
        return self.r[n]

    def setpc(self, v, restore_psr):
        self.r[15] = v & 0x3FFFFFC
        if restore_psr:
            self.flags = v & 0xF0000000
            # ignore I/F and mode changes

    def step(self):
        pc = self.r[15]
        i = self.rw(pc)
        self.steps += 1
        if self.trace: self.trace(self, pc, i)
        self.r[15] = (pc + 4) & 0x3FFFFFC
        if not self.cond(i >> 28):
            return
        # save pc for R15 reads during execution
        self.r[15] = pc
        op = (i >> 25) & 7
        nextpc = (pc + 4) & 0x3FFFFFC
        self.r[15] = pc
        if op in (0, 1) and (i & 0x0FC000F0) == 0x00000090:  # MUL/MLA
            rd, rn, rs, rm = i >> 16 & 15, i >> 12 & 15, i >> 8 & 15, i & 15
            v = (self.r[rm] * self.r[rs]) & M32
            if i & (1 << 21): v = (v + self.r[rn]) & M32
            self.r[rd] = v
            if i & (1 << 20):
                self.flags = (self.flags & ~(N_ | Z_)) | (v & N_) | (Z_ if v == 0 else 0)
            self.r[15] = nextpc
        elif op in (0, 1) and (i & 0x0FB00FF0) == 0x01000090:  # SWP
            rn, rd, rm = i >> 16 & 15, i >> 12 & 15, i & 15
            a = self.r[rn]
            if i & (1 << 22):
                t = self.rb(a); self.wb(a, self.r[rm])
            else:
                t = self.rw(a); self.ww(a, self.r[rm])
            self.r[rd] = t
            self.r[15] = nextpc
        elif op in (0, 1):
            self.r[15] = pc
            self.dataproc(i, nextpc)
        elif op in (2, 3):
            self.r[15] = pc
            self.ldrstr(i, nextpc)
        elif op == 4:
            self.r[15] = pc
            self.ldmstm(i, nextpc)
        elif op == 5:
            off = i & 0xFFFFFF
            if off & 0x800000: off -= 0x1000000
            if i & (1 << 24):
                self.r[14] = nextpc | self.flags | self.mode
            self.r[15] = (pc + 8 + off * 4) & 0x3FFFFFC
        elif op == 7 and (i >> 24) & 1:
            self.r[15] = nextpc
            self.swi_handler(self, i & 0xFFFFFF, pc)
        else:
            raise Stop('undefined/coproc instruction %08x at %08x' % (i, pc))

    def dataproc(self, i, nextpc):
        opc = (i >> 21) & 15
        s = (i >> 20) & 1
        rn = (i >> 16) & 15
        rd = (i >> 12) & 15
        carry = 1 if self.flags & C_ else 0
        if i & (1 << 25):
            rot = ((i >> 8) & 15) * 2
            op2 = ror(i & 0xFF, rot)
            sc = (op2 >> 31) if rot else carry
        else:
            op2, sc = self.reg_op(i, carry)
        regshift = (not i & (1 << 25)) and (i & 0x10)
        a = self.getr(rn, 12 if regshift else 8, full=False)
        c, v = carry, 1 if self.flags & V_ else 0
        logical = True
        if opc == 0: res = a & op2
        elif opc == 1: res = a ^ op2
        elif opc == 2: res, logical = self.sub(a, op2, 1), False
        elif opc == 3: res, logical = self.sub(op2, a, 1), False
        elif opc == 4: res, logical = self.add(a, op2, 0), False
        elif opc == 5: res, logical = self.add(a, op2, carry), False
        elif opc == 6: res, logical = self.sub(a, op2, carry), False
        elif opc == 7: res, logical = self.sub(op2, a, carry), False
        elif opc == 8: res = a & op2
        elif opc == 9: res = a ^ op2
        elif opc == 10: res, logical = self.sub(a, op2, 1), False
        elif opc == 11: res, logical = self.add(a, op2, 0), False
        elif opc == 12: res = a | op2
        elif opc == 13: res = op2
        elif opc == 14: res = a & ~op2 & M32
        else: res = ~op2 & M32
        if logical:
            c = sc
        else:
            res, c, v = res
        if s and rd != 15 or (s and 8 <= opc <= 11):
            if 8 <= opc <= 11 and rd == 15:
                # TEQP etc: set PSR directly from result
                self.flags = res & 0xF0000000
            else:
                self.flags = (res & N_) | (Z_ if res == 0 else 0) | (C_ if c else 0) | (V_ if v else 0)
        if 8 <= opc <= 11:
            self.r[15] = nextpc
            return
        if rd == 15:
            self.setpc(res, s)
        else:
            self.r[rd] = res
            self.r[15] = nextpc

    def add(self, a, b, cin):
        t = a + b + cin
        res = t & M32
        v = ((a ^ res) & (b ^ res)) >> 31
        return res, t >> 32, v

    def sub(self, a, b, cin):
        # a - b - (1-cin)
        return self.add(a, (~b) & M32, cin)

    def ldrstr(self, i, nextpc):
        p, u, b, w, l = [(i >> k) & 1 for k in (24, 23, 22, 21, 20)]
        rn, rd = (i >> 16) & 15, (i >> 12) & 15
        if i & (1 << 25):
            off, _ = self.reg_op(i, 1 if self.flags & C_ else 0)
        else:
            off = i & 0xFFF
        base = self.getr(rn, 8, full=False)
        addr = (base + off if u else base - off) & M32
        ea = addr if p else base
        self.r[15] = nextpc
        if l:
            val = self.rb(ea) if b else self.rw(ea)
        else:
            val = self.getr(rd, 12) if rd == 15 else self.r[rd]
            if rd == 15: val = ((self.r[15] - 4 + 12) & 0x3FFFFFC) | self.flags | self.mode
            if b: self.wb(ea, val)
            else: self.ww(ea, val)
        if (not p or w) and rn != 15:
            self.r[rn] = addr
        if l:
            if rd == 15: self.setpc(val, False)
            else: self.r[rd] = val

    def ldmstm(self, i, nextpc):
        p, u, s, w, l = [(i >> k) & 1 for k in (24, 23, 22, 21, 20)]
        rn = (i >> 16) & 15
        regs = [k for k in range(16) if i & (1 << k)]
        n = len(regs)
        base = self.r[rn] if rn != 15 else (self.r[15] + 8)
        if u:
            start = base + (4 if p else 0)
            wbv = base + 4 * n
        else:
            start = base - 4 * n + (0 if p else 4)
            wbv = base - 4 * n
        pc = self.r[15]
        self.r[15] = nextpc
        a = start & M32
        if l:
            if w and rn != 15: self.r[rn] = wbv & M32
            for k in regs:
                v = self.rw(a)
                if k == 15: self.setpc(v, s)
                else: self.r[k] = v
                a += 4
        else:
            for k in regs:
                v = ((pc + 12) & 0x3FFFFFC) | self.flags | self.mode if k == 15 else self.r[k]
                self.ww(a, v)
                a += 4
            if w and rn != 15: self.r[rn] = wbv & M32
