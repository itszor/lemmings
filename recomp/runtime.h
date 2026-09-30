/* Static recompilation runtime for 26-bit ARM (ARM2/ARM3) RISC OS code.
 *
 * Emulated state lives in globals: R[] (R[15] unused by compiled code), the
 * four flags as 0/1 words, and MEM.  Compiled functions are
 *     void F_xxxx(uint32_t entry)
 * and communicate control flow through `npc`: any PC write that is not a
 * statically-resolved in-function branch stores the target in npc and
 * returns.  Callers check npc against their expected return address and
 * otherwise return as well, so control unwinds to the flat dispatcher
 * (run_until) without growing the C stack.
 *
 * Semantics follow tools/arm2.py exactly (it is the reference oracle).
 */
#ifndef RUNTIME_H
#define RUNTIME_H
#include <stdint.h>

typedef void (*fn_t)(uint32_t);

extern uint32_t R[16];
extern uint32_t NF, ZF, CF, VF;
extern uint8_t *MEM;
extern uint32_t npc;
extern uint64_t icount, irq_next;
extern const uint8_t *codemap;          /* 1 bit per word of the image: compiled code */
extern uint32_t img_end;

void irq_point(void);                    /* interrupts / instruction limit */
void swi(uint32_t n, uint32_t nextpc);   /* OS stubs */
void call_addr(uint32_t a);              /* one dispatch step: compiled fn or interpreter */
int  interp_exec(uint32_t a, uint32_t w);/* execute one (self-modified) word; 1 = pc changed */
void smc_write(uint32_t a);              /* store hit compiled code */
void bad_entry(uint32_t fn, uint32_t e);
void undefined_insn(uint32_t a, uint32_t w);

/* ---- instruction prologue: count, and service interrupts at exact counts ---- */
#ifdef RECOMP_TRACE
void trace_insn(uint32_t a);
#define I(a)  do { if (icount >= irq_next) irq_point(); trace_insn(a); icount++; } while (0)
#else
#define I(a)  do { if (icount >= irq_next) irq_point(); icount++; } while (0)
#endif

/* ---- flags ------------------------------------------------------------------ */
#define PSR()      ((NF << 31) | (ZF << 30) | (CF << 29) | (VF << 28))
#define SETNZ(r)   do { NF = (r) >> 31; ZF = (r) == 0; } while (0)
#define SETPSR(v)  do { uint32_t _p = (v); NF = _p >> 31; ZF = (_p >> 30) & 1; \
                        CF = (_p >> 29) & 1; VF = (_p >> 28) & 1; } while (0)

static inline uint32_t add_c(uint32_t a, uint32_t b, uint32_t cin)
{
    uint64_t t = (uint64_t)a + b + cin;
    uint32_t r = (uint32_t)t;
    CF = (uint32_t)(t >> 32);
    VF = ((a ^ r) & (b ^ r)) >> 31;
    SETNZ(r);
    return r;
}

/* ---- conditions (index = condition field) ------------------------------------ */
#define C_EQ  (ZF)
#define C_NE  (!ZF)
#define C_CS  (CF)
#define C_CC  (!CF)
#define C_MI  (NF)
#define C_PL  (!NF)
#define C_VS  (VF)
#define C_VC  (!VF)
#define C_HI  (CF && !ZF)
#define C_LS  (!CF || ZF)
#define C_GE  (NF == VF)
#define C_LT  (NF != VF)
#define C_GT  (!ZF && NF == VF)
#define C_LE  (ZF || NF != VF)

/* ---- memory (ARM2: unaligned word loads rotate; word stores align) ----------- */
static inline uint32_t RD32(uint32_t a)
{
    a &= 0x3FFFFFF;
    uint32_t w = *(uint32_t *)(MEM + (a & ~3u));
    uint32_t s = (a & 3) * 8;
    return s ? (w >> s) | (w << (32 - s)) : w;
}
static inline uint32_t RD8(uint32_t a) { return MEM[a & 0x3FFFFFF]; }
#define CODECHK(a) do { if ((a) < img_end && (a) >= 0x8000 && \
        (codemap[((a) - 0x8000) >> 5] >> ((((a) - 0x8000) >> 2) & 7) & 1)) smc_write(a); } while (0)
static inline void WR32(uint32_t a, uint32_t v)
{
    a &= 0x3FFFFFC;
    CODECHK(a);
    *(uint32_t *)(MEM + a) = v;
}
static inline void WR8(uint32_t a, uint32_t v)
{
    a &= 0x3FFFFFF;
    CODECHK(a & ~3u);
    MEM[a] = (uint8_t)v;
}

/* ---- barrel shifter ------------------------------------------------------------
 * Immediate shifts are normalised by the generator (amount 1..32, RRX), so:
 *   SH_xxx(v, n)  shifted value         CY_xxx(v, n)  shifter carry-out        */
#define SH_LSL(v, n)  ((uint32_t)(v) << (n))                        /* n 1..31 */
#define CY_LSL(v, n)  (((uint32_t)(v) >> (32 - (n))) & 1)
#define SH_LSR(v, n)  ((n) == 32 ? 0u : (uint32_t)(v) >> (n))        /* n 1..32 */
#define CY_LSR(v, n)  (((uint32_t)(v) >> ((n) - 1)) & 1)
#define SH_ASR(v, n)  ((n) == 32 ? (uint32_t)((int32_t)(v) >> 31) : (uint32_t)((int32_t)(v) >> (n)))
#define CY_ASR(v, n)  (((uint32_t)(v) >> ((n) == 32 ? 31 : (n) - 1)) & 1)
#define SH_ROR(v, n)  (((uint32_t)(v) >> (n)) | ((uint32_t)(v) << (32 - (n))))   /* n 1..31 */
#define CY_ROR(v, n)  (((uint32_t)(v) >> ((n) - 1)) & 1)
#define SH_RRX(v)     ((CF << 31) | ((uint32_t)(v) >> 1))
#define CY_RRX(v)     ((uint32_t)(v) & 1)

/* register-specified shift: typ 0..3, amt = Rs & 0xFF (arm2.py shift(), imm=False) */
static inline uint32_t shr_val(uint32_t v, int typ, uint32_t amt, uint32_t *cy)
{
    uint32_t c = CF;
    if (amt == 0) { if (cy) *cy = c; return v; }
    switch (typ) {
    case 0:
        if (amt < 32) { c = (v >> (32 - amt)) & 1; v <<= amt; }
        else if (amt == 32) { c = v & 1; v = 0; } else { c = 0; v = 0; }
        break;
    case 1:
        if (amt < 32) { c = (v >> (amt - 1)) & 1; v >>= amt; }
        else if (amt == 32) { c = v >> 31; v = 0; } else { c = 0; v = 0; }
        break;
    case 2:
        if (amt >= 32) { c = v >> 31; v = c ? 0xFFFFFFFFu : 0; }
        else { c = (v >> (amt - 1)) & 1; v = (uint32_t)((int32_t)v >> amt); }
        break;
    default:
        amt &= 31;
        if (amt == 0) c = v >> 31;
        else { c = (v >> (amt - 1)) & 1; v = (v >> amt) | (v << (32 - amt)); }
    }
    if (cy) *cy = c;
    return v;
}
#define SHR(v, typ, amt)  shr_val((v), (typ), (amt), 0)
static inline uint32_t SHRC(uint32_t v, int typ, uint32_t amt) { uint32_t c; shr_val(v, typ, amt, &c); return c; }

/* ---- data processing -------------------------------------------------------------
 * a = Rn value, b = operand-2 value, c = shifter carry-out (logical S forms).
 * The generator evaluates nothing twice: each macro captures its operands.   */
#define LOGIC(d, e)       do { R[d] = (e); } while (0)
#define LOGICS(d, e, c)   do { uint32_t _c = (c), _r = (e); R[d] = _r; SETNZ(_r); CF = _c; } while (0)
#define TESTS(e, c)       do { uint32_t _c = (c), _r = (e); SETNZ(_r); CF = _c; } while (0)
#define DP_AND(d, a, b)      LOGIC(d, (a) & (b))
#define DP_EOR(d, a, b)      LOGIC(d, (a) ^ (b))
#define DP_ORR(d, a, b)      LOGIC(d, (a) | (b))
#define DP_BIC(d, a, b)      LOGIC(d, (a) & ~(b))
#define DP_MOV(d, b)         LOGIC(d, (b))
#define DP_MVN(d, b)         LOGIC(d, ~(b))
#define DP_ANDS(d, a, b, c)  LOGICS(d, (a) & (b), c)
#define DP_EORS(d, a, b, c)  LOGICS(d, (a) ^ (b), c)
#define DP_ORRS(d, a, b, c)  LOGICS(d, (a) | (b), c)
#define DP_BICS(d, a, b, c)  LOGICS(d, (a) & ~(b), c)
#define DP_MOVS(d, b, c)     LOGICS(d, (b), c)
#define DP_MVNS(d, b, c)     LOGICS(d, ~(b), c)
#define DP_TST(a, b, c)      TESTS((a) & (b), c)
#define DP_TEQ(a, b, c)      TESTS((a) ^ (b), c)
#define DP_ADD(d, a, b)      LOGIC(d, (a) + (b))
#define DP_SUB(d, a, b)      LOGIC(d, (a) - (b))
#define DP_RSB(d, a, b)      LOGIC(d, (b) - (a))
#define DP_ADC(d, a, b)      LOGIC(d, (a) + (b) + CF)
#define DP_SBC(d, a, b)      LOGIC(d, (a) + ~(b) + CF)
#define DP_RSC(d, a, b)      LOGIC(d, (b) + ~(a) + CF)
#define DP_ADDS(d, a, b)     do { uint32_t _a = (a), _b = (b); R[d] = add_c(_a, _b, 0); } while (0)
#define DP_SUBS(d, a, b)     do { uint32_t _a = (a), _b = (b); R[d] = add_c(_a, ~_b, 1); } while (0)
#define DP_RSBS(d, a, b)     do { uint32_t _a = (a), _b = (b); R[d] = add_c(_b, ~_a, 1); } while (0)
#define DP_ADCS(d, a, b)     do { uint32_t _a = (a), _b = (b); R[d] = add_c(_a, _b, CF); } while (0)
#define DP_SBCS(d, a, b)     do { uint32_t _a = (a), _b = (b); R[d] = add_c(_a, ~_b, CF); } while (0)
#define DP_RSCS(d, a, b)     do { uint32_t _a = (a), _b = (b); R[d] = add_c(_b, ~_a, CF); } while (0)
#define DP_CMP(a, b)         do { uint32_t _a = (a), _b = (b); add_c(_a, ~_b, 1); } while (0)
#define DP_CMN(a, b)         do { uint32_t _a = (a), _b = (b); add_c(_a, _b, 0); } while (0)

/* multiply: N,Z only when S (C,V unchanged, as arm2.py) */
#define MUL(d, m, s)        do { R[d] = R[m] * R[s]; } while (0)
#define MULS(d, m, s)       do { uint32_t _r = R[m] * R[s]; R[d] = _r; SETNZ(_r); } while (0)
#define MLA(d, m, s, n)     do { R[d] = R[m] * R[s] + R[n]; } while (0)
#define MLAS(d, m, s, n)    do { uint32_t _r = R[m] * R[s] + R[n]; R[d] = _r; SETNZ(_r); } while (0)

/* ---- single data transfer -----------------------------------------------------
 * base/off are values; P,U,W,B constants; wb = register to write back or -1. */
#define LDR_(rd, base, off, P, U, B, wb) do { uint32_t _b = (base), _o = (off); \
        uint32_t _a = (U) ? _b + _o : _b - _o; uint32_t _e = (P) ? _a : _b;          \
        uint32_t _v = (B) ? RD8(_e) : RD32(_e);                                       \
        if ((wb) >= 0) R[(wb) & 15] = _a;                                             \
        R[rd] = _v; } while (0)
#define LDRPC_(base, off, P, U, wb) do { uint32_t _b = (base), _o = (off);           \
        uint32_t _a = (U) ? _b + _o : _b - _o; uint32_t _e = (P) ? _a : _b;          \
        uint32_t _v = RD32(_e);                                                       \
        if ((wb) >= 0) R[(wb) & 15] = _a;                                             \
        npc = _v & 0x3FFFFFC; } while (0)
#define STR_(val, base, off, P, U, B, wb) do { uint32_t _b = (base), _o = (off);     \
        uint32_t _a = (U) ? _b + _o : _b - _o; uint32_t _e = (P) ? _a : _b;          \
        uint32_t _v = (val);                                                          \
        if (B) WR8(_e, _v); else WR32(_e, _v);                                        \
        if ((wb) >= 0) R[(wb) & 15] = _a; } while (0)

/* ---- block transfer: generator unrolls the register list ---------------------- */
#define LDM_BEGIN(start)  do { uint32_t _m = (start);
#define LDM_R(k)          R[k] = RD32(_m); _m += 4;
#define LDM_PC(s)         { uint32_t _v = RD32(_m); _m += 4; npc = _v & 0x3FFFFFC; if (s) SETPSR(_v); }
#define STM_BEGIN(start)  do { uint32_t _m = (start);
#define STM_V(v)          WR32(_m, (v)); _m += 4;
#define XFER_END          } while (0)

/* ---- control flow ------------------------------------------------------------------ */
#define SETPC(v, s)   do { uint32_t _v = (v); npc = _v & 0x3FFFFFC; if (s) SETPSR(_v); } while (0)
#define JUMP(t)       do { npc = (t); return; } while (0)
#define LEAVE()       return
/* direct call of a compiled function; resume only if it came back to `ret` */
#define CALL(f, t, ret)  do { f(t); if (npc != (ret)) return; } while (0)
#define CALLI(ret)       do { call_addr(npc); if (npc != (ret)) return; } while (0)
#define SWI(n, next)     swi((n), (next))

#endif
