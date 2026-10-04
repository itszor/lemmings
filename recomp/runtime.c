/* Runtime for the statically recompiled Lemmings (LemProg): state,
 * dispatcher, interrupt injection, fallback interpreter and RISC OS stubs.
 *
 * Ported from ../../galactic dan/recomp/runtime.c (sibling project, same
 * ARM2/RISC OS static-recompilation approach). The dispatcher and ARM2
 * interpreter (call_addr/run_until/exec_word and friends) are unmodified -
 * they're CPU semantics, not game-specific. What's NOT yet adapted for
 * Lemmings, and currently placeholder/best-guess:
 *   - screen mode / vduvar() constants (galactic dan's MODE 13 values kept
 *     as a starting guess - unconfirmed for Lemmings)
 *   - the MusicModule2 custom SWI chunk (&41C40-&41C4B) - musmod2_swi()
 *     below just logs and returns; LemProg's own sound module was never
 *     translated (nor need be: we only need to know what its SWIs *do*)
 *   - no --script scenario data yet (galactic dan's title/menu click
 *     timings obviously don't apply)
 * Everything else (OS_File, OS_Byte, OS_Word, OS_Claim/Release, vectors,
 * the interpreter) is standard RISC OS behaviour and should already be
 * correct, per the SWI list ghidra/lemprog.json actually recorded LemProg
 * using.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdarg.h>
#include <dirent.h>
#include <sys/stat.h>
#include <time.h>
#include <signal.h>
#include <pthread.h>
#include <unistd.h>
#include "runtime.h"
#include "os.h"

#define MEMSIZE      0x4000000u
#define SCREEN       (0x1C00000u - 0x80000u)
#define RETURN_TO_OS 0x3FFFFF0u
#define HANDLER_RET  0x3FFFFE0u
#define TICK_STEPS   20000
#define VSYNC_STEPS  40000
#define SPLIT_FLYBACK 56        /* see hw_irq_frame() */
#define LOAD         0x8000u

uint32_t R[16];
uint32_t NF, ZF, CF, VF;
uint8_t *MEM;
uint32_t npc;
uint32_t pc_bias;
uint64_t icount, irq_next;
const uint8_t *codemap;
uint32_t img_base = 0x8000, img_end;

/* Processor modes (26-bit ARM): R13/R14 are banked per mode, R8-R12 too in
 * FIQ. The games only ever run in USR mode; the module runs in SVC mode
 * (SWIs, init) and its sound fill in IRQ mode - and switches between them
 * itself with TEQP, relying on the banking (e.g. musmod2 &2d30: IRQ -> SVC
 * around an OS_Word, whose SWI corrupts R14_svc but not R14_irq). */
uint32_t MODEBITS;
static uint32_t bank_r13[4], bank_r14[4], bank_fiq[5], bank_r8[5];
void set_psr_mode(uint32_t m)
{
    uint32_t from = MODEBITS & 3, to = m & 3;
    if (from != to) {
        bank_r13[from] = R[13]; bank_r14[from] = R[14];
        if (from == 1) { memcpy(bank_fiq, R + 8, sizeof bank_fiq); memcpy(R + 8, bank_r8, sizeof bank_r8); }
        if (to == 1) { memcpy(bank_r8, R + 8, sizeof bank_r8); memcpy(R + 8, bank_fiq, sizeof bank_fiq); }
        R[13] = bank_r13[to]; R[14] = bank_r14[to];
    }
    MODEBITS = m & 0x0C000003;
}

/* generated: LemProg (the main engine) */
extern const struct entry { uint32_t a; fn_t f; } recomp_entries[];
extern const unsigned recomp_nentries;
extern const uint8_t recomp_codemap[];
extern const uint32_t recomp_img_end;

/* generated: LemBoot (the loader/splash-logo program - see --boot) */
extern const struct entry recompB_entries[];
extern const unsigned recompB_nentries;
extern const uint8_t recompB_codemap[];
extern const uint32_t recompB_img_end;

/* generated: musmod2 (MusicModule 1.02, RMLoaded by !Run) - see module_call() */
extern const struct entry recompM_entries[];
extern const unsigned recompM_nentries;
extern const uint8_t recompM_codemap[];
extern const uint32_t recompM_img_base, recompM_img_end;

static fn_t *entry_tab;                 /* direct-mapped: (a - LOAD) >> 2 */
/* LemBoot and LemProg are separate programs that both load at &8000 (RISC
 * OS's standard Absolute load address) at different times - LemBoot loads
 * and decompresses each asset (splash logos, then the real engine) to
 * &8000 in turn, chain-loading into whichever one is freshly there. Our
 * translated code for each lives in a disjoint symbol namespace (gen_c.py
 * --prefix), and the active {entry_tab, codemap, img_end} triple is swapped
 * swapped in call_addr() at the exact moment of the real chain-load. */
static fn_t *entry_tab_boot, *entry_tab_game;
static const uint8_t *codemap_boot, *codemap_game;
static uint32_t img_end_boot, img_end_game;
static uint32_t events_enabled;         /* OS_Byte 14/13: enable/disable event N */
static int boot_mode;                   /* 1 while running LemBoot's own code */
static int boot_loaded_lemprog;         /* set by os_file() when it just served LemProg */
static const char *appdir = "../extracted/!LEMMINGS";
static uint64_t limit = 20000000;
static int in_handler;
static uint64_t next_tick = TICK_STEPS, next_vsync = VSYNC_STEPS;
static uint32_t bank, display_bank, monotonic, voices = 1;
static struct { uint32_t code, ws; int set; } vectors[0x20];
static FILE *evlog;
static uint8_t vdu[1 << 20];
static size_t nvdu;
static uint64_t interp_count, smc_count;
static const char *outprefix = "recomp";
static int interactive, full_os, interp_only;                 /* SDL window, real time / VDU+sprite drivers */
static uint64_t next_tick_ns, next_vsync_ns, t0_ns;
static volatile uint64_t last_service_ns;   /* watchdog: last time rt_service() ran a vsync */
static int last_buttons;
/* --script=ms:action[:args],...  actions: click:x:y (OS units), tap:px:py (a host
   click at screen pixel px,py, through the real SDL event path), poke:addr:value (write a
   memory word - e.g. poke:0x19d44:5 on the title screen starts at level 6), release, buttons:mask,
   move:dx:dy, key:inkey (held 200ms), type:ascii, shot, quit                         */
#define MAXSCRIPT 8192
static struct { uint64_t ms; char act[8]; int a, b; } script[MAXSCRIPT];
static int nscript, script_i, shots;
static uint64_t key_release_ms[129];

static void parse_script(const char *p)
{
    while (*p && nscript < MAXSCRIPT) {
        int n = 0;
        script[nscript].ms = strtoull(p, (char **)&p, 10);
        if (*p == ':') p++;
        while (*p && *p != ':' && *p != ',' && n < 7) script[nscript].act[n++] = *p++;
        script[nscript].act[n] = 0;
        if (*p == ':') { p++; script[nscript].a = strtol(p, (char **)&p, 0); }
        if (*p == ':') { p++; script[nscript].b = strtol(p, (char **)&p, 0); }
        if (*p == ',') p++;
        nscript++;
    }
}

static void run_script(void)
{
    uint64_t ms = (display_ticks_ns() - t0_ns) / 1000000;
    for (int k = 0; k < 129; k++)
        if (key_release_ms[k] && ms >= key_release_ms[k]) { key_down[k - 1] = 0; key_release_ms[k] = 0; }
    while (script_i < nscript && ms >= script[script_i].ms) {
        const char *a = script[script_i].act;
        int x = script[script_i].a, y = script[script_i].b;
        if (!strcmp(a, "click")) { mouse_x = x; mouse_y = y; mouse_buttons = 4; }
        else if (!strcmp(a, "tap")) display_inject_tap(x, y);
        else if (!strcmp(a, "poke")) WR32((uint32_t)x, (uint32_t)y);
        else if (!strcmp(a, "release")) mouse_buttons = 0;
        else if (!strcmp(a, "buttons")) mouse_buttons = x;
        else if (!strcmp(a, "move")) { mouse_x += x; mouse_y += y; }
        else if (!strcmp(a, "esc")) escape_pressed = 1;
        else if (!strcmp(a, "key") && x >= 1 && x <= 128) { key_down[x - 1] = 1; key_release_ms[x] = ms + 200; }
        else if (!strcmp(a, "type")) key_buffer_put(x);
        else if (!strcmp(a, "shot")) screenshot_requested = 1;
        else if (!strcmp(a, "quit")) quit_requested = 1;
        script_i++;
    }
}
#define CS_NS 10000000ull

/* TEMP: PC histogram after a threshold, to see what LemProg is doing once
 * it stops making OS_File progress (see README) - printed from finish(). */
/* Open-addressed with a bounded probe: once more distinct PCs have run than
 * the table holds (LemProg alone has ~9900 translated instructions, plus the
 * module), an unbounded probe for a new PC never terminates - which froze the
 * whole game a while into busier levels (e.g. Fun 6). Now a PC that can't
 * find a slot within PCHIST_PROBE just isn't counted. */
#define PCHIST 65536
#define PCHIST_PROBE 32
static struct { uint32_t a; uint64_t n; } pchist[PCHIST];
uint32_t g_cur_pc;                      /* TEMP: for watch_write() below */
void dbg_hook(uint32_t a)
{
    g_cur_pc = a;
    if (icount < 700000) return;
    unsigned h = (a >> 2) % PCHIST;
    for (int k = 0; k < PCHIST_PROBE; k++, h = (h + 1) % PCHIST)
        if (!pchist[h].n || pchist[h].a == a) { pchist[h].a = a; pchist[h].n++; return; }
}
/* TEMP: log the first few distinct-pc writes into [lo,hi) from anywhere,
 * with the pc that did it - see README. Currently watching SCREEN itself,
 * to find out what's drawing the "scrambled" static image reported there
 * (was &83e0-&8468, the spec_852c tables - that investigation is done). */
void watch_write(uint32_t addr, uint32_t val)
{
    /* TEMP: hook for watching writes; currently unused (last used to
     * confirm LemProg never programs MEMC directly - it flips screen
     * banks via OS_Word 22 instead). */
    (void)addr; (void)val;
}
static void dump_pchist(void)
{
    for (int pass = 0; pass < 15; pass++) {
        uint32_t besta = 0; uint64_t bestn = 0; int besti = -1;
        for (int k = 0; k < PCHIST; k++)
            if (pchist[k].n > bestn) { bestn = pchist[k].n; besta = pchist[k].a; besti = k; }
        if (besti < 0) break;
        fprintf(stderr, "pchist #%d: %08x x%llu\n", pass, besta, (unsigned long long)bestn);
        pchist[besti].n = 0;
    }
}

/* ---------------------------------------------------------------- MusicModule2
 * !Run RMLoads musmod2 (MusicModule 1.02, 1990: a 4-channel tracker player
 * that also plays the sound effects). We "RMLoad" it ourselves: copy it into
 * an emulated RMA at MODBASE, run its init, route its SWI chunk (&41C40) to
 * its SWI handler, and emulate the OS Sound system's DMA side for it.
 *
 * A relocatable module is position-independent, so it's translated at the
 * address we load it to (gen_c.py --base, see ghidra/run_ghidra_musmod.sh)
 * and dispatched like any other image: module_call() swaps in its tables
 * and address range for the duration of one call and restores them
 * afterwards, so it can be entered from LemProg, LemBoot, or interrupt
 * context alike. Module code runs in the processor mode the OS would use -
 * SVC for init and SWIs, IRQ for the sound fill - with banked R13/R14 (see
 * set_psr_mode()), and returns to the caller's mode via R14's PSR bits. */
#define MODBASE      0x01800000u          /* our RMA: module image... */
#define RMA_HEAP     (MODBASE + 0x10000u) /* ...then OS_Module 6 claims */
#define DMA_BUF      0x017F0000u          /* two sound DMA buffers, &2000 each */
#define SVC_STACK    0x017F8000u          /* R13_svc / R13_irq stack tops */
#define IRQ_STACK    0x017FC000u
#define MOD_PRIVATE  0x017FFFFCu          /* the module's private word */
#define MODE_SVC     3u
#define MODE_IRQ     (2u | 0x08000000u)   /* IRQ mode, IRQs disabled */
static int in_module;
static uint32_t mod_size, rma_next = RMA_HEAP;
static void finish(const char *why) __attribute__((noreturn));
static long load_file(const char *path, uint32_t addr);
static fn_t *entry_tab_mod;
static const uint8_t *codemap_mod;
static uint32_t img_end_mod;
static fn_t *build_tab(const struct entry *ents, unsigned n, uint32_t base, uint32_t end);

/* Run module code at addr in processor mode `mode` with R14 = r14, until it
 * returns to HANDLER_RET. */
static void module_call(uint32_t addr, uint32_t mode, uint32_t r14)
{
    fn_t *st = entry_tab; const uint8_t *sc = codemap;
    uint32_t sbase = img_base, se = img_end, snpc = npc, smode = MODEBITS;
    int sh = in_handler, sm = in_module;
    entry_tab = entry_tab_mod; codemap = codemap_mod; img_base = MODBASE; img_end = img_end_mod;
    in_handler = in_module = 1;               /* no nested interrupts while in module code */
    set_psr_mode(mode);
    R[14] = r14;
    npc = addr;
    uint64_t i0 = icount;
    while (npc != HANDLER_RET) {
        if (npc == RETURN_TO_OS) finish("returned to OS");
        if (icount - i0 > 50000000) {
            fprintf(stderr, "module_call(%08x): bailing out after 50M instructions, pc=%08x\n", addr, npc);
            break;
        }
        call_addr(npc);
    }
    set_psr_mode(smode);                      /* usually already done by movs pc,lr */
    entry_tab = st; codemap = sc; img_base = sbase; img_end = se; npc = snpc;
    in_handler = sh; in_module = sm;
}

static void module_load(const char *path)
{
    long n = load_file(path, MODBASE);
    if (n <= 0) { fprintf(stderr, "musmod2: cannot load %s - no music\n", path); return; }
    mod_size = (uint32_t)n;
    img_end_mod = recompM_img_end;
    if (recompM_img_base != MODBASE || MODBASE + mod_size != img_end_mod)
        fprintf(stderr, "warning: musmod2 differs from its compiled image (base %08x)\n", recompM_img_base);
    entry_tab_mod = build_tab(recompM_entries, recompM_nentries, MODBASE, img_end_mod);
    codemap_mod = recompM_codemap;
    WR32(MOD_PRIVATE, 0);
    uint32_t saved[16], sf[4] = {NF, ZF, CF, VF};
    memcpy(saved, R, sizeof R);
    R[10] = 0; R[11] = 0; R[12] = MOD_PRIVATE;   /* init: env string, instantiation, private word */
    VF = 0;
    module_call(MODBASE + RD32(MODBASE + 4), MODE_SVC, HANDLER_RET | MODEBITS);
    if (VF) fprintf(stderr, "musmod2: init returned an error\n");
    memcpy(R, saved, sizeof R);
    NF = sf[0]; ZF = sf[1]; CF = sf[2]; VF = sf[3];
}

/* SWI in the module's chunk: entered in SVC mode with R11 = offset in chunk,
 * R12 = private word, R14_svc = return address + the caller's PSR, which the
 * handler's movs/orrs pc,lr restores (with V set on error). R0-R9 are in/out;
 * the kernel preserves R10-R12 for the caller. */
static void module_swi(uint32_t b, int x)
{
    if (!mod_size) return;
    uint32_t r10 = R[10], r11 = R[11], r12 = R[12];
    R[11] = b & 0x3F; R[12] = MOD_PRIVATE;
    if ((MODEBITS & 3) == 0) bank_r13[3] = SVC_STACK;   /* a SWI from USR mode starts on an empty SVC stack */
    module_call(MODBASE + RD32(MODBASE + 0x20), MODE_SVC, HANDLER_RET | (PSR() & ~0x10000000u));
    R[10] = r10; R[11] = r11; R[12] = r12;
    if (VF && !x) fprintf(stderr, "musmod2: SWI &%x returned an error: %s\n", b, (char *)MEM + ((R[0] + 4) & 0x3FFFFFF));
}

/* ---------------------------------------------------------------- Sound DMA
 * The OS Sound system's lowest level, as a Level 1 handler sees it: every
 * buffer period (samples x period us) the DMA interrupt calls the installed
 * handler's fill code (word 0 of the handler block given to Sound_Configure)
 * with R12 = buffer start, R10 = buffer end, R11 = number of channels
 * (samples interleaved, stride R11), R9 = the handler block. The bytes are
 * VIDC 8-bit logarithmic samples, one per channel per frame, panned by
 * Sound_Stereo. We run that fill in step with emulated time
 * (sound_dma_advance(), called every centisecond tick) and convert each
 * buffer to 16-bit stereo for sound.c (SDL stream or --wav). */
#define DEFAULT_LEVEL1 0x03800100u        /* stands in for the OS's own handler: silence */
static uint32_t snd_nchan = 1, snd_samples = 208, snd_period = 48, snd_level1 = DEFAULT_LEVEL1, snd_level2,
                snd_enabled = 2;
static int snd_pan[8];
static uint64_t snd_acc_us;
static int snd_buf;
static int16_t snd_linear[128];

static void sound_dma_fill(void)
{
    uint32_t len = snd_nchan * snd_samples, buf = DMA_BUF + (snd_buf ^= 1) * 0x2000;
    if (len > 0x2000) len = 0x2000;
    if (snd_level1 != DEFAULT_LEVEL1 && mod_size && snd_enabled == 2) {
        uint32_t saved[16], sf[4] = {NF, ZF, CF, VF};
        memcpy(saved, R, sizeof R);
        R[9] = snd_level1; R[10] = buf + len; R[11] = snd_nchan; R[12] = buf;
        bank_r13[2] = IRQ_STACK;               /* each interrupt starts on an empty IRQ stack */
        module_call(RD32(snd_level1), MODE_IRQ, HANDLER_RET | MODE_IRQ);
        memcpy(R, saved, sizeof R);
        NF = sf[0]; ZF = sf[1]; CF = sf[2]; VF = sf[3];
    } else memset(MEM + buf, 0, len);
    if (!snd_linear[127])
        for (int m = 0; m < 128; m++)                       /* VIDC log: 3-bit chord, 4-bit step */
            snd_linear[m] = (int16_t)((((2 * (m & 15) + 33) << (m >> 4)) - 33) * 4);
    static int16_t out[2 * 2048];
    uint32_t frames = len / snd_nchan;
    if (frames > 2048) frames = 2048;
    for (uint32_t f = 0; f < frames; f++) {
        int l = 0, r = 0;
        for (uint32_t c = 0; c < snd_nchan; c++) {
            uint8_t b = MEM[buf + f * snd_nchan + c];
            int v = snd_linear[b >> 1];
            if (b & 1) v = -v;
            int pan = snd_pan[c];
            l += v * (pan <= 0 ? 127 : 127 - pan) / 127;
            r += v * (pan >= 0 ? 127 : 127 + pan) / 127;
        }
        l /= (int)snd_nchan; r /= (int)snd_nchan;   /* VIDC time-multiplexes channels: each gets 1/nchan */
        out[2 * f] = (int16_t)(l > 32767 ? 32767 : l < -32768 ? -32768 : l);
        out[2 * f + 1] = (int16_t)(r > 32767 ? 32767 : r < -32768 ? -32768 : r);
    }
    sound_out(out, (int)frames, (int)(1000000 / snd_period));
}

/* Advance the sound DMA clock by `us` of emulated time. */
static void sound_dma_advance(uint32_t us)
{
    uint64_t buf_us = (uint64_t)snd_samples * snd_period;
    if (!buf_us) return;
    snd_acc_us += us;
    while (snd_acc_us >= buf_us) { snd_acc_us -= buf_us; sound_dma_fill(); }
}

static int sound_swi_impl(uint32_t b)
{
    switch (b) {
    case 0x40140: {                          /* Sound_Configure */
        uint32_t old[5] = {snd_nchan, snd_samples, snd_period, snd_level1, snd_level2};
        if (R[0]) { uint32_t n = 1; while (n < R[0] && n < 8) n <<= 1; snd_nchan = n; }
        if (R[1]) snd_samples = R[1];
        if (R[2]) snd_period = R[2];
        if (R[3]) snd_level1 = R[3];
        if (R[4]) snd_level2 = R[4];
        for (int k = 0; k < 5; k++) R[k] = old[k];
        return 1;
    }
    case 0x40141: {                          /* Sound_Enable: 0 read, 1 off, 2 on */
        uint32_t old = snd_enabled;
        if (R[0] == 1 || R[0] == 2) snd_enabled = R[0];
        R[0] = old;
        return 1;
    }
    case 0x40142: {                          /* Sound_Stereo: R0 channel 1-8, R1 position */
        int c = (int)(R[0] - 1) & 7, old = snd_pan[c];
        int32_t p = (int32_t)R[1];
        if (p != -128) snd_pan[c] = p < -127 ? -127 : p > 127 ? 127 : p;
        R[1] = (uint32_t)old;
        return 1;
    }
    }
    return 0;
}

/* spec_852c (the VIDC palette-load routine) has zero static/traced callers
 * (confirmed both in ghidra/out/lemprog/functions.tsv and by instrumenting
 * every instruction: never reached in 100M instructions). Its install code
 * (&2a688-&2a6e4) writes into absolute low workspace &100, not through
 * OS_Claim/Event_V like &2a70c - almost certainly a lower-level, direct
 * hardware-IRQ dispatch slot the kernel itself reads that we don't emulate.
 * Rather than reverse-engineer that kernel internal, call it ourselves.
 *
 * LemBoot installs its own, address-different analogue the same way (see
 * &87d0-&8804). hw_irq_frame() below calls whichever handler is currently
 * installed at &100 (LemProg's real entry is &8530: install code is at
 * &84f4, and &852c is the saved chain word). */
static void run_until(uint32_t stop);
static void finish(const char *why) __attribute__((noreturn));
static void call_hw_handler(uint32_t addr, uint32_t ioc14, uint32_t ioc24)
{
    if (!(img_base <= addr && addr < img_end && entry_tab[(addr - img_base) >> 2])) return;
    WR32(0x3200014, ioc14);
    WR32(0x3200024, ioc24);
    uint32_t saved[16], sf[4] = {NF, ZF, CF, VF}, snpc = npc;
    memcpy(saved, R, sizeof R);
    R[14] = HANDLER_RET;
    npc = addr;
    in_handler = 1;
    /* irq_point() (where --limit/instruction-count safety normally lives)
     * early-returns while in_handler, so a genuine infinite loop inside a
     * synthetically-called handler would otherwise hang forever and
     * nothing would stop it. Bound it defensively instead. */
    uint64_t hw_i0 = icount;
    while (npc != HANDLER_RET) {
        if (npc == RETURN_TO_OS) finish("returned to OS");
        if (icount - hw_i0 > 5000000) {
            fprintf(stderr, "call_hw_handler(%08x): bailing out after 5M instructions, pc=%08x\n",
                    addr, npc);
            break;
        }
        call_addr(npc);
    }
    in_handler = 0;
    memcpy(R, saved, sizeof R);
    NF = sf[0]; ZF = sf[1]; CF = sf[2]; VF = sf[3];
    npc = snpc;
}

/* One frame's worth of the direct hardware-IRQ handler that LemBoot
 * (&87d0) and LemProg (&84f4) each install by writing its address into
 * low workspace &100 - a kernel dispatch slot we don't otherwise emulate -
 * after saving the old value as their own chain word. Call whatever is
 * installed there, as the kernel would: LemProg's is &8530 (the word at
 * &852c is its saved chain pointer, not code - calling &852c used to send
 * it through the interpreter once the chain held a real address, e.g.
 * LemBoot's handler on a --boot run); LemBoot's is &4080c (its relocated
 * copy - see pc_bias).
 *
 * The handlers are written for two interrupt sources: IOC IRQ A bit 3
 * (vsync/flyback) builds and pushes the top palette, and - LemProg only -
 * programs IOC timer 1 (latch at &3200050/54) to fire part way down the
 * frame, where bit 6 (timer 1) pushes a second palette for the rest of
 * the screen (the panel). We call both once per frame and hand the
 * display the first palette plus the line the timer would fire at. */
uint32_t vidc_palette_top[16];
int palette_split;
static void hw_irq_frame(void)
{
    uint32_t a = RD32(0x100);
    if (!a) return;
    if (boot_mode && a >= 0x40000 && a < 0x40000 + (img_end_boot - LOAD)) a -= 0x38000;
    MEM[0x3200050] = MEM[0x3200054] = 0;
    call_hw_handler(a, 0x8, 0);
    uint32_t latch = MEM[0x3200050] | MEM[0x3200054] << 8;
    memcpy(vidc_palette_top, vidc_palette, sizeof vidc_palette_top);
    call_hw_handler(a, 0x40, 0);       /* always: it also clears &852c's re-entry gate (&85fc) */
    if (!latch) { palette_split = 0; return; }
    /* IOC timers count at 2MHz; a line is 64us (128 ticks), and the
     * flyback interrupt arrives SPLIT_FLYBACK lines before line 0. */
    int line = (int)((latch + 1) / 128) - SPLIT_FLYBACK;
    palette_split = line < 0 ? 0 : line > 256 ? 256 : line;
    static uint32_t last_latch;
    if (latch != last_latch) {
        last_latch = latch;
        fprintf(stderr, "palette split: timer latch %#x -> line %d (icount %llu)\n",
                latch, palette_split, (unsigned long long)icount);
    }
}

uint32_t os_write_bank_addr(void) { return SCREEN + bank * 0xA000; }
uint32_t os_screen_base(void) { return SCREEN; }

/* Direct VIDC register writes (physical &3400000): LemProg bypasses the OS
 * VDU driver entirely for the palette (confirmed: a 16-word table gets
 * loaded into registers 0-15 from an interrupt handler at &852c, for a
 * mid-screen "copper" style panel/game palette split - see README). VIDC's
 * write format is value | (register << 26); registers 0-15 are the 16
 * palette entries (4 bits each of B,G,R, i.e. 4bpp/16-colour, matching the
 * Amiga original), higher register numbers are screen timing (border/
 * sync/etc - not yet decoded, just logged for now). */
uint32_t vidc_palette[16] = {0};        /* 0x0BGR per entry; display.c reads this */
static int vidc_seen[64];
void vidc_write(uint32_t v)
{
    unsigned reg = v >> 26;
    uint32_t val = v & 0x3FFFFFF;
    if (reg < 16) vidc_palette[reg] = val;
    if (val != 0 || vidc_seen[reg] < 8) {
        vidc_seen[reg]++;
        FILE *f = fopen("vidc.log", "a");
        if (f) { fprintf(f, "%llu: VIDC reg %u = %#x (raw %#x)\n",
                          (unsigned long long)icount, reg, val, v); fclose(f); }
    }
}

/* scenario: no fixed click/key timings for Lemmings yet (galactic dan's were
 * tuned to its title screen); headless (--limit=N) runs are keyboard/mouse-
 * silent until we have real ones, or use --script for ad hoc input. */
static struct { uint64_t step; uint32_t x, y, b; } clicks[1];
static unsigned nclicks, click_i;
static struct { int inkey; uint64_t from, to; } keys[1];
static unsigned nkeys;

static void finish(const char *why) __attribute__((noreturn));
static void run_until(uint32_t stop);
static int hostpath(const char *name, char *out);
static long load_file(const char *path, uint32_t addr);

/* ---------------------------------------------------------------- logging */
static void ev(const char *name, const char *fmt, ...)
{
    fprintf(evlog, "%llu %s", (unsigned long long)icount, name);
    va_list ap;
    va_start(ap, fmt);
    for (const char *p = fmt; *p; p++) {
        if (*p == 'i') fprintf(evlog, " %x", va_arg(ap, unsigned));
        else if (*p == 's') {                  /* bytes: pointer + length */
            const uint8_t *s = va_arg(ap, const uint8_t *);
            int n = va_arg(ap, int);
            fputc(' ', evlog);
            for (int k = 0; k < n; k++) fprintf(evlog, "%02x", s[k]);
            if (n == 0) fputc('-', evlog);
        }
    }
    va_end(ap);
    fputc('\n', evlog);
}
/* Just enough of the VDU queue to follow VDU 22 (mode changes): !Run
 * selects MODE 12, then LemBoot and LemProg each select MODE 9 (320x256,
 * 4bpp: 160 bytes/row) - showing mode 9 memory at 640px wide draws every
 * image twice side by side at half height. */
static int screen_mode = 12;
static void vdu_put(uint8_t c)
{
    static const uint8_t nparams[32] = {0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                                        0,1,2,5,0,0,1,9,8,5,0,0,4,4,0,2};
    static uint8_t q[10]; static int qn, qwant;
    if (nvdu < sizeof vdu) vdu[nvdu++] = c;
    if (full_os) vdu_write(c);
    if (qwant) {
        q[qn++] = c;
        if (qn == qwant) {
            if (q[0] == 22) screen_mode = q[1] & 0x7F;
            qn = qwant = 0;
        }
    } else if (c < 32 && nparams[c]) {
        q[0] = c; qn = 1; qwant = 1 + nparams[c];
    }
}
static int screen_width(void) { return screen_mode == 9 ? 320 : 640; }

/* ---------------------------------------------------------------- dispatch */
static void interp_step(void);
static int trace_gaps;                  /* --trace-gaps: see below */

/* Unlike galactic dan's runtime (which falls back to a full ARM2
 * interpreter for any address with no compiled entry, and only reports
 * coverage gaps at exit via RECOMP_ISTAT), the default here is to log and
 * stop immediately: finding out about a gap right when we hit it - not some
 * arbitrary time later - is what drives what gets translated next. The
 * interpreter (exec_word/interp_step/interp_exec) is kept for two things:
 * self-modified instructions whose *current* form wasn't one seen during
 * analysis (gen_c.py's smc_switch), and, only with --trace-gaps, pushing
 * through an untranslated *address* (as opposed to instruction form) too -
 * a one-shot diagnostic mode for mapping out several gaps in a single run
 * (e.g. addresses reached only via a computed/indirect jump, which have no
 * static caller to point at) instead of rebuilding after each one. It logs
 * every distinct gap address the first time it's hit, then keeps
 * interpreting exactly like galactic dan's runtime always does. */
static void log_untranslated_branch(uint32_t a)
{
    FILE *f = fopen("untranslated.log", "a");
    if (f) {
        fprintf(f, "%llu: branch to untranslated address %08x (LR=%08x, from pc=%08x)\n",
                (unsigned long long)icount, a, R[14], g_cur_pc);
        fclose(f);
    }
    fprintf(stderr, "branch to untranslated address %08x (icount %llu, LR=%08x, from pc=%08x) - see untranslated.log\n",
            a, (unsigned long long)icount, R[14], g_cur_pc);
}

static int seen_gap(uint32_t a)
{
    static uint32_t seen[4096]; static int n;
    for (int k = 0; k < n; k++) if (seen[k] == a) return 1;
    if (n < 4096) seen[n++] = a;
    return 0;
}

void call_addr(uint32_t a)
{
    if (a == RETURN_TO_OS) finish("returned to OS");
    /* The boot_mode redirects below (relocated-copy remap, post-unpack
     * vector-area walk) are specifically for LemBoot's own main _start
     * flow - they must not apply inside a synthetic call_hw_handler()
     * call (e.g. LemBoot's own &880c, same unpatched-&100-chain-return
     * idiom as LemProg's &852c), or a chain-vector return to a low
     * address gets misrouted into LemBoot's real _start and loops
     * forever instead of ending the call. The generic "in_handler and
     * nothing resolves" catch-all below handles those cases instead. */
    if (!in_module && boot_mode && a >= 0x40000 && a < 0x40000 + (img_end_boot - LOAD)) {
        /* LemBoot copies its first &2000 bytes from &8000 to &40000 and
         * continues running from there (see the loop at &8010-&802c) -
         * real hardware needs this so it can safely OS_File-load the next
         * asset *at* &8000, overwriting the low copy of itself, while
         * still running loader logic from the safe high copy. Our
         * compiled functions don't read instructions from MEM at all
         * (they're pre-translated, dispatched purely by address), so they
         * never go stale when &8000 gets overwritten - we can just keep
         * dispatching to the original (&8000-based) compiled function for
         * any jump into the relocated copy, sidestepping the relocation
         * trick entirely.
         *
         * Dispatch only, though: from here on the *program* really is
         * running at &40000, and everything it can observe about its own
         * PC must say so - PC-relative data (flags, palette tables, the
         * saved &100 chain), literal-thunk reads via R14, link addresses.
         * LemBoot is translated with --pcbias, so all of that is emitted
         * relative to pc_bias; set it here. Without this the program's
         * absolute pointers (e.g. the &407c8 literal at &8a2c, the &40744/
         * &406c4 palette tables) and its PC-relative accesses to the same
         * variables (&87c8 etc.) disagree, and the PC-relative side reads
         * the low copy, which the next asset load overwrites anyway. This
         * also applies inside call_hw_handler(): &880c is the relocated
         * handler too. */
        pc_bias = 0x38000;
        a -= 0x38000;
        npc = a;
    }
    if (!in_handler && boot_mode && a < LOAD) {
        /* LemBoot's post-unpack "return" from the shared loader (&8aac et
         * al) goes through the real hardware vector area (&0-&34) via a
         * push-pc/pop-pc trick, relying on however the kernel's vectors
         * are really set up there - we don't emulate that, but direct
         * arm2.py emulation confirms it's a harmless pass-through that
         * always ends up jumping to &8000 (the just-loaded program), so
         * just go straight there instead of treating it as a gap. */
        npc = LOAD;
        return;
    }
    if (boot_mode && boot_loaded_lemprog && a == LOAD) {
        entry_tab = entry_tab_game; codemap = codemap_game; img_end = img_end_game;
        boot_mode = 0; boot_loaded_lemprog = 0; pc_bias = 0;
        fprintf(stderr, "chain-load: LemBoot -> LemProg at icount %llu\n", (unsigned long long)icount);
    }
    fn_t f = (!interp_only && a >= img_base && a < img_end) ? entry_tab[(a - img_base) >> 2] : 0;
    if (f) { f(a); return; }
    if (a == HANDLER_RET) return;
    if (in_module) {
        /* Module code should be fully translated - a gap here is a real
         * one, so report it (once per address), then end this call rather
         * than taking the whole game down with it. */
        if (!seen_gap(a)) log_untranslated_branch(a);
        npc = HANDLER_RET;
        return;
    }
    if (in_handler) {
        /* A synthetic call_hw_handler() call landed somewhere we can't
         * resolve. On real hardware these routines run as asynchronous
         * IRQ handlers that can interrupt *anything*, including another
         * asset's own decompression loop mid-write - we're injecting the
         * call ourselves outside the game's real timing, so we can't
         * assume the chain-vector/table data it reads is always sane at
         * the moment we chose to call it (confirmed: a stale &100-chain
         * read landed mid-write in a decompression target once already).
         * Safest is to just end this one invocation and try again next
         * vsync, rather than crash the whole emulation over it. */
        npc = HANDLER_RET;
        return;
    }
    if (trace_gaps) {
        if (!seen_gap(a)) log_untranslated_branch(a);
        interp_step();
        return;
    }
    log_untranslated_branch(a);
    finish("branch to untranslated code");
}

static void run_until(uint32_t stop)
{
    while (npc != stop) {
        if (npc == RETURN_TO_OS) finish("returned to OS");
        call_addr(npc);
    }
}

void bad_entry(uint32_t fn, uint32_t e)
{
    fprintf(stderr, "bad entry %08x into F_%x\n", e, fn);
    finish("bad entry");
}
void undefined_insn(uint32_t a, uint32_t w)
{
    fprintf(stderr, "undefined/coproc instruction %08x at %08x\n", w, a);
    finish("undefined instruction");
}
void smc_write(uint32_t a)
{
    static uint32_t seen[64]; static int ns;
    for (int k = 0; k < ns; k++) if (seen[k] == a) return;
    if (ns < 64) seen[ns++] = a;
    smc_count++;
    fprintf(stderr, "note: store to compiled code at %08x (icount %llu)\n", a,
            (unsigned long long)icount);
}

/* ---------------------------------------------------------------- interrupts */
static void recompute_irq(void)
{
    uint64_t n = next_tick < next_vsync ? next_tick : next_vsync;
    if (click_i < nclicks && clicks[click_i].step < n) n = clicks[click_i].step;
    if (limit < n) n = limit;
    irq_next = n;
}

static void call_vector(unsigned vec, int nregs, const uint32_t *regs)
{
    /* Events only reach EventV once enabled with OS_Byte 14. LemProg only
     * enables event 4 (vsync) - its handler (&2a70c) doesn't check the
     * event number, so dispatching our mouse event (10) too counted every
     * click as an extra frame tick. */
    if (vec == 0x10 && !(events_enabled & (1u << (regs[0] & 31)))) return;
    if (vec >= 0x20 || !vectors[vec].set) return;
    uint32_t saved[16], sf[4] = {NF, ZF, CF, VF}, snpc = npc;
    memcpy(saved, R, sizeof R);
    for (int k = 0; k < nregs; k++) R[k] = regs[k];
    R[12] = vectors[vec].ws;
    R[14] = HANDLER_RET;
    npc = vectors[vec].code;
    in_handler = 1;
    run_until(HANDLER_RET);
    in_handler = 0;
    memcpy(R, saved, sizeof R);
    NF = sf[0]; ZF = sf[1]; CF = sf[2]; VF = sf[3];
    npc = snpc;
}

/* OS_Word 22's display-hardware offset (block type bit 1): how LemProg
 * flips between its two screen banks (offsets 0 and &A000). */
static uint32_t display_off;
static const uint8_t *displayed(void)
{
    return MEM + SCREEN + display_off + display_bank * 0xA000;
}

/* Run a loader-stage program (e.g. !TitlePic) with the interpreter before
   the game: it overlaps the game's addresses, so nothing compiled is used. */
static void run_loader_program(const char *name)
{
    char path[2048];
    if (!hostpath(name, path)) return;
    long n = load_file(path, LOAD);
    if (n <= 0) return;
    uint32_t saved[16];
    memcpy(saved, R, sizeof R);
    R[13] = 0xA8000; R[14] = RETURN_TO_OS; R[12] = 0;
    npc = LOAD;
    interp_only = 1;
    run_until(RETURN_TO_OS);
    interp_only = 0;
    memset(MEM + LOAD, 0, n);
    memcpy(R, saved, sizeof R);
    NF = ZF = CF = VF = 0;
}

static void rt_service(int vsync_now)
{
    uint64_t now = display_ticks_ns();
    if (now > next_tick_ns + 20 * CS_NS) next_tick_ns = now;       /* don't burst after stalls */
    if (now > next_vsync_ns + 20 * CS_NS) next_vsync_ns = now;
    while (now >= next_tick_ns) {
        next_tick_ns += CS_NS;
        sound_dma_advance(10000);                /* 1 cs of sound DMA - see sound_dma_fill() */
        call_vector(0x1C, 0, 0);
    }
    if (vsync_now || now >= next_vsync_ns) {
        next_vsync_ns += 2 * CS_NS;
        display_poll();
        if (nscript) run_script();
        if (quit_requested) finish("window closed");
        last_service_ns = now;
        monotonic += 2;
        hw_irq_frame();
        /* &84e8/&84ec are LemProg's fade-in/fade-out requests (the exact
         * analogue of LemBoot's &87c4/&87c8): set to &ff by the game, which
         * then busy-waits; &8650/&86ac step the fade once per &852c call
         * and clear the flag themselves when it's complete. They used to
         * be cleared here every vsync, which cut every fade off after one
         * step - hence the dim, 3-register palette in the README. */
        uint32_t r[2] = {4, 0};
        call_vector(0x10, 2, r);
        if (mouse_buttons != last_buttons) {
            last_buttons = mouse_buttons;
            ev("mouse", "iii", mouse_x, mouse_y, mouse_buttons);
            uint32_t m[5] = {10, mouse_x, mouse_y, mouse_buttons, monotonic};
            call_vector(0x10, 5, m);
        }
        /* Present last: on real hardware, what the game does at flyback -
         * the palette push (hw_irq_frame), the bank flip and pointer redraw
         * (its vsync event, &2a70c) - shows in the frame scanned out right
         * after it. Presenting first made all of that a frame (20ms) late. */
        if (screenshot_requested) {
            char fn[64];
            snprintf(fn, sizeof fn, "screenshot-%d.bmp", ++shots);
            display_screenshot(displayed(), screen_width(), fn);
            fprintf(stderr, "saved %s\n", fn);
            screenshot_requested = 0;
        }
        display_present(displayed(), screen_width());
    }
}

static void wait_vsync(void)
{
    uint64_t now = display_ticks_ns();
    if (now < next_vsync_ns) display_sleep_ns(next_vsync_ns - now);
    rt_service(1);
}

void irq_point(void)
{
    if (in_handler) return;
    if (interactive) {
        rt_service(0);
        irq_next = icount + 20000;
        return;
    }
    if (icount >= limit) finish("instruction limit");
    if (icount >= next_tick) {
        next_tick += TICK_STEPS;
        sound_dma_advance(10000);                /* 1 cs of sound DMA - see sound_dma_fill() */
        call_vector(0x1C, 0, 0);
    }
    if (icount >= next_vsync) {
        next_vsync += VSYNC_STEPS;
        monotonic += 2;
        hw_irq_frame();
        uint32_t r[2] = {4, 0};
        call_vector(0x10, 2, r);
    }
    if (click_i < nclicks && icount >= clicks[click_i].step) {
        uint32_t x = clicks[click_i].x, y = clicks[click_i].y, b = clicks[click_i].b;
        click_i++;
        ev("mouse", "iii", x, y, b);
        uint32_t r[5] = {10, x, y, b, monotonic};
        call_vector(0x10, 5, r);
    }
    recompute_irq();
}

/* ---------------------------------------------------------------- OS stubs */
static int pressed(int inkey)
{
    if (interactive) return inkey >= 1 && inkey <= 128 && key_down[inkey - 1];
    for (unsigned k = 0; k < nkeys; k++)
        if (keys[k].inkey == inkey && keys[k].from <= icount && icount < keys[k].to) return 1;
    return 0;
}

static int cstr(uint32_t a, char *out, int term_ctrl)
{
    int n = 0;
    while (1) {
        uint8_t c = MEM[a];
        if (c == 0 || (term_ctrl && (c == 10 || c == 13))) break;
        out[n++] = c; a++;
        if (n > 1024) break;
    }
    out[n] = 0;
    return n;
}

static int hostpath(const char *name, char *out)
{
    const char *n = name;
    while (*n == ' ') n++;
    const char *pre[] = {"Disc1:", "Disc2:", "<Obey$Dir>.", "<Lem$Dir>."};
    for (int k = 0; k < 4; k++)
        if (!strncmp(n, pre[k], strlen(pre[k]))) n += strlen(pre[k]);
    strcpy(out, appdir);
    char part[256];
    while (*n) {
        int l = 0;
        while (*n && *n != '.') part[l++] = *n++;
        part[l] = 0;
        if (*n == '.') n++;
        for (int k = 0; k < l; k++) if (part[k] == '/') part[k] = '.';
        DIR *d = opendir(out);
        if (!d) return 0;
        struct dirent *e;
        int hit = 0;
        while ((e = readdir(d))) {
            char base[256];
            strcpy(base, e->d_name);
            char *comma = strchr(base, ',');
            if (comma) *comma = 0;
            if (!strcasecmp(base, part)) { strcat(out, "/"); strcat(out, e->d_name); hit = 1; break; }
        }
        closedir(d);
        if (!hit) return 0;
    }
    return 1;
}

static long load_file(const char *path, uint32_t addr)
{
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    long n = fread(MEM + addr, 1, MEMSIZE - addr, f);
    fclose(f);
    return n;
}

static uint32_t vduvar(uint32_t v)
{
    /* Lemmings values: RISC OS MODE 9 (320x256, 4bpp/16-colour, 160
     * bytes/row, &A000 per screen). !Run selects MODE 12 first, but both
     * LemBoot and LemProg then emit VDU 22,9 themselves, and LemProg's
     * double-buffering flips OS_Word 22's display offset between 0 and
     * &A000 - see README. The &14000 seen in the screen zero-fill loop and
     * MemMod's dynamic-area resize is the *total* screen memory: two
     * mode-9 banks. */
    switch (v) {
    case 148: return SCREEN + bank * 0xA000;
    case 149: return SCREEN + (full_os ? display_bank : bank) * 0xA000;
    case 150: return 0x14000;                  /* TotalScreenSize: two banks */
    case 7: return 0xA000;                     /* ScreenSize: 320*256/2 (4bpp) */
    case 1: case 11: return 319;               /* ScrRCol / width - 1 */
    case 2: case 12: return 255;               /* ScrBRow / height - 1 */
    case 3: return 15;                         /* NColour - 1 (16 colours) */
    case 4: return 2;                          /* XEig: MODE 9 is 320px wide */
    case 5: return 2;                          /* YEig: 256px tall */
    case 6: return 160;                        /* LineLength: 320px * 4bpp / 8 */
    case 9: return 2;                          /* Log2BPP: log2(4bpp) */
    default: return 0;
    }
}

static uint32_t swi_pc;
/* OS_Word 21,1 mouse bounding box (left, bottom, right, top; inclusive, OS
 * units). LemProg uses it to keep its software pointer inside one palette
 * region of a split screen - e.g. rows 80-174 on the level briefing screen,
 * below the map preview's palette split at line 76 (&199a4). */
static int mbox[4] = {0, 0, 1279, 1023};
static int clamp_i(int v, int lo, int hi) { return v < lo ? lo : v > hi ? hi : v; }
static int swi_x;         /* set by swi(): was this call X-flagged (error-checking)? */
static void os_byte(void)
{
    uint32_t op = R[0] & 0xFF;
    if (op == 129) {
        if (R[2] == 0xFF && R[1] >= 0x80) {
            int k = 256 - R[1];
            R[1] = R[2] = pressed(k) ? 0xFF : 0;
        } else if (interactive) {
            uint64_t until = display_ticks_ns() + (uint64_t)((R[2] & 0x7F) << 8 | R[1]) * CS_NS;
            for (;;) {
                if (escape_pressed) { R[1] = 0; R[2] = 27; return; }
                int c = key_buffer_get();
                if (c >= 0) { R[1] = c; R[2] = 0; return; }
                if (display_ticks_ns() >= until) { R[1] = 0; R[2] = 0xFF; return; }
                display_sleep_ns(CS_NS);
                rt_service(0);
            }
        } else {
            R[1] = 0; R[2] = 0xFF;
            for (unsigned k = 0; k < nkeys; k++)
                if (keys[k].from <= icount && icount < keys[k].to && keys[k].inkey == 99) {
                    R[1] = 32; R[2] = 0;
                }
        }
        return;
    }
    if (op == 121) {
        if (R[1] & 0x80) R[1] = pressed((R[1] ^ 0x80) + 1) ? 0xFF : 0;
        else R[1] = 0xFF;
        return;
    }
    if (op == 112 || op == 113) {
        uint32_t b = (R[1] >= 1 ? R[1] - 1 : 0) & 1;
        if (op == 112) bank = b; else display_bank = b;
        ev("OS_Byte", "ii", op, R[1]);
        return;
    }
    if (op == 13 || op == 14) {                       /* disable / enable event */
        uint32_t m = 1u << (R[1] & 31);
        R[1] = (events_enabled & m) ? 1 : 0;             /* old state */
        if (op == 14) events_enabled |= m; else events_enabled &= ~m;
        return;
    }
    if (op == 19) { if (interactive) wait_vsync(); else monotonic++; return; }
    if (interactive && op >= 124 && op <= 126) {       /* clear / set / acknowledge Escape */
        if (op == 126 && escape_pressed) key_buffer_flush();   /* escape side effect */
        if (op != 125) { if (escape_pressed) ev("escape_cleared", "ii", op, swi_pc - 4); escape_pressed = 0; }
        else escape_pressed = 1;
        R[1] = op == 126 ? 0xFF : R[1];
        return;
    }
    if (op == 135) { R[2] = 13; return; }
    /* OS_Byte 15 (flush all / current input buffer), 21 (flush buffer r1; 0 = keyboard) */
    if (interactive && (op == 15 || (op == 21 && R[1] == 0))) key_buffer_flush();
    ev("OS_Byte", "iii", op, R[1], R[2]);
}

static void os_file(void)
{
    uint32_t op = R[0] & 0xFF;
    char name[1100], path[2048];
    int n = cstr(R[1], name, 1);
    ev("OS_File", "is", op, name, n);
    int ok = hostpath(name, path);
    if (op == 255 || op == 12 || op == 14 || op == 16) {
        if (!ok) {
            /* X-flagged (error-checking) callers are explicitly written to
             * handle this (e.g. LemBoot's &8b4c loader: `bvs retry`) - a
             * real RISC OS error return (V set) lets that logic do
             * whatever it would for a genuinely missing/not-yet-named
             * file, instead of us crashing the whole emulation over what
             * the game itself treats as a recoverable condition. */
            if (swi_x) { VF = 1; return; }
            fprintf(stderr, "file not found %s (pc=%08x r1=%08x icount=%llu)\n",
                    name, g_cur_pc, R[1], (unsigned long long)icount);
            finish("file not found");
        }
        if (R[3] & 0xFF) finish("load at file address unsupported");
        long len = load_file(path, R[2]);
        R[4] = (uint32_t)len; R[0] = 1;
        if (boot_mode) {
            const char *leaf = strrchr(name, '.');
            leaf = leaf ? leaf + 1 : name;
            if (!strcasecmp(leaf, "LemProg")) boot_loaded_lemprog = 1;
        }
        return;
    }
    if (op == 5 || op == 17 || op == 13 || op == 15) {
        if (!ok) { R[0] = 0; return; }
        struct stat st;
        stat(path, &st);
        /* Load/exec addresses come from the extracted file's ",load-exec"
         * suffix (the disc's real catalogue values) - MusicModule's Load
         * checks the load address for filetype &CC5 (TeqMusic). */
        uint32_t load = 0xFFFFFD00, exec = 0;
        const char *comma = strrchr(path, ',');
        if (comma && !strchr(comma, '/')) sscanf(comma + 1, "%x-%x", &load, &exec);
        R[0] = 1; R[2] = load; R[3] = exec; R[4] = (uint32_t)st.st_size; R[5] = 3;
        return;
    }
    finish("OS_File op unsupported");
}

static void sprite_op(void)
{
    uint32_t op = R[0] & 0xFF;
    ev("OS_SpriteOp", "iii", R[0], R[1], R[2]);
    if (full_os && sprite_op_full()) return;
    if (op == 10 || op == 11) {
        char name[1100], path[2048];
        cstr(R[2], name, 1);
        if (!hostpath(name, path)) finish("sprite file not found");
        if (op == 10) load_file(path, R[1] + 4);
    }
}

/* MusicModule2's own SWI chunk (&41C40-&41C4B). We don't know its ABI yet
 * (musmod2 itself was never translated - LemProg only calls it), so this
 * just logs and returns success with registers unchanged. Sound is
 * therefore silent until this is filled in properly; that's an accepted
 * gap for now, not a crash. */
static void musmod2_swi(uint32_t b)
{
    char name[24];
    sprintf(name, "MusMod2_%x", b);
    ev(name, "iiii", R[0], R[1], R[2], R[3]);
}

static void convert(uint32_t b)
{
    uint32_t v = R[0], buf = R[1], size = R[2];
    char s[64];
    if (b <= 0xD4) {
        int digits = b == 0xD0 ? 1 : b == 0xD1 ? 2 : b == 0xD2 ? 4 : b == 0xD3 ? 6 : 8;
        uint64_t m = (digits == 8) ? 0xFFFFFFFFull : ((1ull << (4 * digits)) - 1);
        sprintf(s, "%0*llX", digits, (unsigned long long)(v & m));
    } else {
        int k = (b - 0xD5) % 4;
        if (k < 3) v &= (1u << (8 * (k + 1))) - 1;
        if (b >= 0xE1) {                         /* spaced: groups of three */
            char t[32]; int n = sprintf(t, "%u", v), o = 0;
            for (int i = 0; i < n; i++) {
                s[o++] = t[i];
                if ((n - 1 - i) % 3 == 0 && i != n - 1) s[o++] = ' ';
            }
            s[o] = 0;
        } else sprintf(s, "%u", v);
    }
    int l = strlen(s);
    memcpy(MEM + buf, s, l + 1);
    R[0] = buf; R[1] = buf + l; R[2] = size - l - 1;
}

void swi(uint32_t n, uint32_t nextpc)
{
    uint32_t x = n & 0x20000, b = n & ~0x20000u;
    VF = 0;
    swi_pc = nextpc;
    /* A SWI loads R14_svc with the return address - visible to the caller
     * only if it's itself in SVC mode (why module code stacks R14 first). */
    if ((MODEBITS & 3) == 3) R[14] = nextpc | PSR(); else bank_r14[3] = nextpc | PSR();
    swi_x = (n & 0x20000) != 0;
    if (b >= 0x100 && b <= 0x1FF) { vdu_put(b - 0x100); return; }
    switch (b) {
    case 0: vdu_put(R[0]); return;
    case 1: {                                    /* OS_WriteS */
        char s[1100]; int l = cstr(nextpc, s, 0);
        for (int k = 0; k < l; k++) vdu_put(s[k]);
        npc = (nextpc + l + 4) & ~3u;
        return;
    }
    case 2: { char s[1100]; int l = cstr(R[0], s, 0);
              for (int k = 0; k < l; k++) vdu_put(s[k]); R[0] += l + 1; return; }
    case 3: vdu_put('\n'); vdu_put('\r'); return;
    case 0x46: for (uint32_t k = 0; k < R[1]; k++) vdu_put(MEM[R[0] + k]); return;
    case 0x45: vdu_put(25); vdu_put(R[0]); vdu_put(R[1]); vdu_put(R[1] >> 8);
               vdu_put(R[2]); vdu_put(R[2] >> 8); return;
    case 0x36: case 0x37: return;
    case 6: os_byte(); return;
    case 7: {
        uint8_t *blk = MEM + R[1];
        if (interactive && R[0] == 21 && blk[0] == 3)       /* set mouse position */
            display_set_mouse(clamp_i((int16_t)(blk[1] | blk[2] << 8), mbox[0], mbox[2]),
                              clamp_i((int16_t)(blk[3] | blk[4] << 8), mbox[1], mbox[3]));
        if (R[0] == 21 && blk[0] == 1)                      /* define mouse bounding box: l, b, r, t */
            for (int k = 0; k < 4; k++) mbox[k] = (int16_t)(blk[1 + 2 * k] | blk[2 + 2 * k] << 8);
        if (R[0] == 12) {                                    /* OS_Word 12: write palette entry.
             * Block is {colour, flag/unused, red, green, blue} - confirmed
             * against two real callers (F_8178, F_8234's 16-colour loop)
             * which both write R/G/B to offsets 2/3/4, leaving offset 1
             * untouched. Reading R/G/B from 1/2/3 (one off) was why only
             * colour 0 ever appeared to be set correctly - see README. */
            unsigned colour = blk[0] & 0xF;                   /* logical colour 0-15 (4bpp) */
            vidc_palette[colour] = blk[2] | (uint32_t)blk[3] << 8 | (uint32_t)blk[4] << 16;
            /*fprintf(stderr, "palette: colour %u = #%06x (icount %llu)\n",
                    colour, vidc_palette[colour], (unsigned long long)icount);*/
        }
        if (R[0] == 22 && (blk[0] & 2))                     /* OS_Word 22: set display start */
            display_off = (blk[1] | blk[2] << 8 | blk[3] << 16 | (uint32_t)blk[4] << 24) & 0xFFFFF;
        if (R[0] == 21 && blk[0] == 0)
            ev("OS_Word", "isi", R[0], blk, 6, blk[6] | blk[7] << 8 | blk[8] << 16 | (uint32_t)blk[9] << 24);
        else ev("OS_Word", "is", R[0], blk, 8);
        return;
    }
    case 0x1C:                                   /* OS_Mouse: pointer confined to the bounding box */
        if (interactive) { R[0] = clamp_i(mouse_x, mbox[0], mbox[2]); R[1] = clamp_i(mouse_y, mbox[1], mbox[3]);
                           R[2] = mouse_buttons; R[3] = monotonic; }
        else { R[0] = 640; R[1] = 512; R[2] = 0; R[3] = monotonic; }
        return;
    case 0x1F: case 0x20:
        ev(b == 0x1F ? "OS_Claim" : "OS_Release", "iii", R[0], R[1], R[2]);
        if (b == 0x1F && R[0] < 0x20) {
            vectors[R[0]].code = R[1]; vectors[R[0]].ws = R[2]; vectors[R[0]].set = 1;
        }
        return;
    case 0x1D: return;                      /* OS_RemoveCursors: no cursor to hide */
    /* OS_EnterOS: switch the caller to SVC mode (R13/R14 become the SVC
     * bank). LemBoot calls this (X-flagged) right before writing IOC
     * registers at &87e4, then returns to USR with `TEQP pc,#0` at &87fc. */
    case 0x16: set_psr_mode((MODEBITS & ~3u) | 3); return;
    case 0x2C: CF = interactive ? escape_pressed : 0; return;
    case 0x31: {
        uint32_t i = R[0], o = R[1];
        for (;;) { uint32_t v = RD32(i); if (v == 0xFFFFFFFF) break;
                   WR32(o, vduvar(v)); i += 4; o += 4; }
        return;
    }
    case 0x35: {
        /* OS_ReadModeVariable, indices 0-12: ModeFlags, ScrRCol, ScrBRow,
         * NColour, XEig, YEig, LineLength, ScreenSize, YShadowSize, Log2BPP,
         * ?, ScrRCol(dup), ScrBRow(dup). Lemmings values - see vduvar(). */
        static const uint32_t mv[13] = {0, 319, 255, 15, 2, 2, 160, 0xA000, 0, 2, 0, 319, 255};
        R[2] = R[1] < 13 ? mv[R[1]] : 0;
        return;
    }
    case 0x2E: sprite_op(); return;
    case 8: os_file(); return;
    case 5: {
        char s[1100]; int l = cstr(R[0], s, 1);
        ev("OS_CLI", "s", s, l);
        if (!strncasecmp(s, "QUIT", 4)) finish("OS_CLI QUIT");
        return;
    }
    case 0x1E:                                   /* OS_Module */
        if (R[0] == 6) {                         /* claim RMA block */
            R[2] = rma_next + 4;
            WR32(rma_next, R[3] + 4);
            rma_next = (rma_next + R[3] + 4 + 15) & ~15u;
        } else ev("OS_Module", "ii", R[0], R[1]);
        return;
    case 0x11: finish("OS_Exit");
    case 0x2B: finish("OS_GenerateError");
    case 0x42: R[0] = interactive ? (uint32_t)((display_ticks_ns() - t0_ns) / CS_NS)
                                  : (uint32_t)(icount / 20000); return;
    }
    if (b >= 0xD0 && b <= 0xE8) { convert(b); return; }
    uint32_t grp = b & ~0x3Fu;
    if (grp == 0x40140 || grp == 0x40180 || grp == 0x401C0) {
        int nargs = 3;
        switch (b) {
        case 0x40140: nargs = 5; break; case 0x40141: case 0x40143: case 0x40180:
        case 0x40184: nargs = 1; break; case 0x40142: case 0x40183: case 0x40185:
        case 0x4018A: nargs = 2; break; case 0x40189: nargs = 4; break;
        }
        char name[32]; sprintf(name, "Sound_%x", b);
        const char *fmts[] = {"", "i", "ii", "iii", "iiii", "iiiii"};
        ev(name, fmts[nargs], R[0], R[1], R[2], R[3], R[4]);
        if (b == 0x40183) R[1] = voices++;
        if (!sound_swi_impl(b)) sound_swi(b);
        return;
    }
    if ((b & ~0x3Fu) == 0x41C40) {         /* MusicModule2's own SWI chunk */
        musmod2_swi(b);
        module_swi(b, x);
        return;
    }
    char name[48]; sprintf(name, "unhandled_SWI_%x", n);
    ev(name, "iii", R[0], R[1], R[2]);
    if (!x) finish("unhandled SWI");
    VF = 1;
}

/* ---------------------------------------------------------------- interpreter
 * One ARM2 instruction at npc (C port of tools/arm2.py ARM.step), used for
 * addresses with no compiled entry and for self-modified instructions.     */
static uint32_t ipc;                     /* address of the instruction being interpreted */

static int cond_ok(uint32_t c)
{
    switch (c) {
    case 0: return ZF; case 1: return !ZF; case 2: return CF; case 3: return !CF;
    case 4: return NF; case 5: return !NF; case 6: return VF; case 7: return !VF;
    case 8: return CF && !ZF; case 9: return !CF || ZF; case 10: return NF == VF;
    case 11: return NF != VF; case 12: return !ZF && NF == VF; case 13: return ZF || NF != VF;
    case 14: return 1; default: return 0;
    }
}
static uint32_t getr(int n, int pcoff, int full)
{
    if (n == 15) { uint32_t p = (ipc + pcoff) & 0x3FFFFFC; return full ? p | PSR() : p; }
    return R[n];
}
static uint32_t shift_imm(uint32_t v, int typ, uint32_t amt, uint32_t *c)
{
    switch (typ) {
    case 0: if (amt == 0) { *c = CF; return v; } *c = (v >> (32 - amt)) & 1; return v << amt;
    case 1: if (amt == 0) amt = 32;
            if (amt == 32) { *c = v >> 31; return 0; } *c = (v >> (amt - 1)) & 1; return v >> amt;
    case 2: if (amt == 0) amt = 32;
            if (amt >= 32) { *c = v >> 31; return *c ? 0xFFFFFFFF : 0; }
            *c = (v >> (amt - 1)) & 1; return (uint32_t)((int32_t)v >> amt);
    default: if (amt == 0) { *c = v & 1; return (CF << 31) | (v >> 1); }
             *c = (v >> (amt - 1)) & 1; return (v >> amt) | (v << (32 - amt));
    }
}
static uint32_t reg_op(uint32_t i, uint32_t *c)
{
    int rm = i & 15, typ = (i >> 5) & 3;
    if (i & 0x10) {
        uint32_t amt = getr((i >> 8) & 15, 8, 1) & 0xFF;
        return shr_val(getr(rm, 12, 1), typ, amt, c);
    }
    return shift_imm(getr(rm, 8, 1), typ, (i >> 7) & 31, c);
}
static void setpc_i(uint32_t v, int s) { npc = v & 0x3FFFFFC; if (s) SETPSR(v); }

static int exec_word(uint32_t pc, uint32_t i)
{
    ipc = pc;
    uint32_t next = (pc + 4) & 0x3FFFFFC;
    npc = next;
    if (!cond_ok(i >> 28)) return 0;
    uint32_t op = (i >> 25) & 7;
    if (op <= 1 && (i & 0x0FC000F0) == 0x00000090) {          /* MUL/MLA */
        int rd = (i >> 16) & 15, rn = (i >> 12) & 15, rs = (i >> 8) & 15, rm = i & 15;
        uint32_t v = R[rm] * R[rs];
        if (i & (1 << 21)) v += R[rn];
        R[rd] = v;
        if (i & (1 << 20)) SETNZ(v);
    } else if (op <= 1 && (i & 0x0FB00FF0) == 0x01000090) {   /* SWP */
        int rn = (i >> 16) & 15, rd = (i >> 12) & 15, rm = i & 15;
        uint32_t a = R[rn], t;
        if (i & (1 << 22)) { t = RD8(a); WR8(a, R[rm]); } else { t = RD32(a); WR32(a, R[rm]); }
        R[rd] = t;
    } else if (op <= 1) {                                      /* data processing */
        uint32_t opc = (i >> 21) & 15, s = (i >> 20) & 1, rn = (i >> 16) & 15, rd = (i >> 12) & 15;
        uint32_t op2, sc, c = CF, v = VF, res;
        if (i & (1 << 25)) {
            uint32_t rot = ((i >> 8) & 15) * 2;
            op2 = rot ? ((i & 0xFF) >> rot) | ((i & 0xFF) << (32 - rot)) : (i & 0xFF);
            sc = rot ? op2 >> 31 : CF;
        } else op2 = reg_op(i, &sc);
        int regshift = !(i & (1 << 25)) && (i & 0x10);
        uint32_t a = getr(rn, regshift ? 12 : 8, 0);
        int logical = 1;
        uint64_t t;
        #define ADDC(x, y, ci) (t = (uint64_t)(x) + (y) + (ci), res = (uint32_t)t, c = (uint32_t)(t >> 32), \
                                v = (((x) ^ res) & ((y) ^ res)) >> 31, logical = 0)
        switch (opc) {
        case 0: case 8: res = a & op2; break;
        case 1: case 9: res = a ^ op2; break;
        case 2: case 10: ADDC(a, ~op2, 1); break;
        case 3: ADDC(op2, ~a, 1); break;
        case 4: case 11: ADDC(a, op2, 0); break;
        case 5: ADDC(a, op2, CF); break;
        case 6: ADDC(a, ~op2, CF); break;
        case 7: ADDC(op2, ~a, CF); break;
        case 12: res = a | op2; break;
        case 13: res = op2; break;
        case 14: res = a & ~op2; break;
        default: res = ~op2;
        }
        #undef ADDC
        if (logical) c = sc;
        if ((s && rd != 15) || (s && opc >= 8 && opc <= 11)) {
            if (opc >= 8 && opc <= 11 && rd == 15) SETPSR(res);
            else { NF = res >> 31; ZF = res == 0; CF = c; VF = v; }
        }
        if (opc >= 8 && opc <= 11) return 0;
        if (rd == 15) { setpc_i(res, s); return 1; }
        R[rd] = res;
    } else if (op <= 3) {                                      /* LDR/STR */
        uint32_t p = (i >> 24) & 1, u = (i >> 23) & 1, bb = (i >> 22) & 1, w = (i >> 21) & 1,
                 l = (i >> 20) & 1, rn = (i >> 16) & 15, rd = (i >> 12) & 15, off, dummy;
        if (i & (1 << 25)) off = reg_op(i, &dummy); else off = i & 0xFFF;
        uint32_t base = getr(rn, 8, 0);
        uint32_t addr = u ? base + off : base - off, ea = p ? addr : base, val = 0;
        if (l) val = bb ? RD8(ea) : RD32(ea);
        else {
            val = rd == 15 ? ((pc + 12) & 0x3FFFFFC) | PSR() : R[rd];
            if (bb) WR8(ea, val); else WR32(ea, val);
        }
        if ((!p || w) && rn != 15) R[rn] = addr;
        if (l) { if (rd == 15) { setpc_i(val, 0); return 1; } R[rd] = val; }
    } else if (op == 4) {                                      /* LDM/STM */
        uint32_t p = (i >> 24) & 1, u = (i >> 23) & 1, s = (i >> 22) & 1, w = (i >> 21) & 1,
                 l = (i >> 20) & 1, rn = (i >> 16) & 15;
        int n = __builtin_popcount(i & 0xFFFF);
        uint32_t base = rn != 15 ? R[rn] : pc + 8, start, wbv;
        if (u) { start = base + (p ? 4 : 0); wbv = base + 4 * n; }
        else { start = base - 4 * n + (p ? 0 : 4); wbv = base - 4 * n; }
        uint32_t a = start & ~3u;                              /* LDM/STM ignore address bits 0-1 */
        int jumped = 0;
        if (l) {
            if (w && rn != 15) R[rn] = wbv;
            for (int k = 0; k < 16; k++) if (i & (1 << k)) {
                uint32_t v2 = RD32(a);
                if (k == 15) { setpc_i(v2, s); jumped = 1; } else R[k] = v2;
                a += 4;
            }
        } else {
            for (int k = 0; k < 16; k++) if (i & (1 << k)) {
                WR32(a, k == 15 ? ((pc + 12) & 0x3FFFFFC) | PSR() : R[k]);
                a += 4;
            }
            if (w && rn != 15) R[rn] = wbv;
        }
        return jumped;
    } else if (op == 5) {                                      /* B/BL */
        int32_t off = i & 0xFFFFFF;
        if (off & 0x800000) off -= 0x1000000;
        if (i & (1 << 24)) R[14] = next | PSR();
        npc = (pc + 8 + off * 4) & 0x3FFFFFC;
        return 1;
    } else if (op == 7 && (i >> 24) & 1) {                     /* SWI */
        swi(i & 0xFFFFFF, next);
        return npc != next;
    } else undefined_insn(pc, i);
    return 0;
}

#define ISTAT 4096
static struct { uint32_t a, why; uint64_t n; } istat[ISTAT];
static void note_interp(uint32_t a, uint32_t why)
{
    unsigned h = (a >> 2) % ISTAT;
    while (istat[h].n && (istat[h].a != a || istat[h].why != why)) h = (h + 1) % ISTAT;
    istat[h].a = a; istat[h].why = why; istat[h].n++;
}

static void interp_step(void)
{
    uint32_t pc = npc;
    I(pc);
    interp_count++;
    note_interp(pc, 0);
    exec_word(pc, RD32(pc));
}

int interp_exec(uint32_t a, uint32_t w)
{
    interp_count++;
    note_interp(a, w);
    return exec_word(a, w);
}

#ifdef RECOMP_TRACE
/* RECOMP_TRACE=from:to  ->  "<icount> <pc> r0..r14 psr" per instruction in that window */
static uint64_t tr_from = ~0ull, tr_to;
static FILE *trf;
void trace_insn(uint32_t a)
{
    if (icount < tr_from || icount >= tr_to) return;
    if (!trf) trf = fopen("rec.trace", "w");
    fprintf(trf, "%llu %x", (unsigned long long)icount, a);
    for (int k = 0; k < 15; k++) fprintf(trf, " %x", R[k]);
    fprintf(trf, " %x\n", PSR());
}
#endif

/* ---------------------------------------------------------------- start/finish */
static void finish(const char *why)
{
    char fn[512];
    fclose(evlog);
#ifdef RECOMP_TRACE
    if (trf) fclose(trf);
#endif
    snprintf(fn, sizeof fn, "%s.vdu", outprefix);
    FILE *f = fopen(fn, "wb"); fwrite(vdu, 1, nvdu, f); fclose(f);
    snprintf(fn, sizeof fn, "%s.screen", outprefix);
    f = fopen(fn, "wb"); fwrite(MEM + SCREEN - 0x20000, 1, 0x60000, f); fclose(f);
    snprintf(fn, sizeof fn, "%s.regs", outprefix);
    f = fopen(fn, "w");
    for (int k = 0; k < 15; k++) fprintf(f, "r%d %08x\n", k, R[k]);
    fprintf(f, "psr %08x\n", PSR());
    fclose(f);
    if (getenv("RECOMP_ISTAT"))
        for (int k = 0; k < ISTAT; k++) if (istat[k].n)
            fprintf(stderr, "interp %08x %s %08x x%llu\n", istat[k].a, istat[k].why ? "smc-form" : "no-entry",
                    istat[k].why, (unsigned long long)istat[k].n);
    dump_pchist();
    sound_close();
    if (vdu_unhandled) fprintf(stderr, "VDU: %u unhandled codes/characters\n", vdu_unhandled);
    fprintf(stderr, "stopped: %s after %llu instructions (%llu interpreted, %llu SMC stores noted)\n",
            why, (unsigned long long)icount, (unsigned long long)interp_count,
            (unsigned long long)smc_count);
    exit(0);
}

static fn_t *build_tab(const struct entry *ents, unsigned n, uint32_t base, uint32_t end)
{
    fn_t *tab = calloc((end - base) / 4 + 1, sizeof(fn_t));
    for (unsigned k = 0; k < n; k++) tab[(ents[k].a - base) >> 2] = ents[k].f;
    return tab;
}

/* Freeze diagnostics. The window only stays alive while the main loop keeps
 * reaching rt_service(); anything that stops it (a runaway loop inside a
 * synthetic handler or module call, where interrupts are held off) freezes
 * the whole window. The watchdog reports where the CPU is once the main loop
 * has gone 3s without servicing the display; Ctrl-C / SIGTERM print the
 * same plus the PC histogram before exiting. */
static void report_state(const char *why)
{
    fprintf(stderr, "%s: pc=%08x npc=%08x icount=%llu in_handler=%d in_module=%d mode=%u boot_mode=%d "
            "img=%08x-%08x\n", why, g_cur_pc, npc, (unsigned long long)icount, in_handler, in_module,
            MODEBITS & 3, boot_mode, img_base, img_end);
}
static void on_signal(int sig)
{
    static volatile sig_atomic_t once;
    (void)sig;
    if (once++) _exit(1);
    report_state("interrupted");
    dump_pchist();
    _exit(1);
}
static void *watchdog(void *arg)
{
    (void)arg;
    int reported = 0;
    for (;;) {
        sleep(1);
        uint64_t last = last_service_ns, now = display_ticks_ns();
        if (last && now - last > 3000000000ull) {
            if (!reported) { report_state("main loop stalled for 3s"); reported = 1; }
        } else reported = 0;
    }
    return NULL;
}

int main(int argc, char **argv)
{
    const char *image = "../extracted_decompressed/LemProg.bin";
    const char *boot_image = "../extracted/!LEMMINGS/LemBoot,fffff843-00000000";
    const char *musmod_image = "../extracted/!LEMMINGS/musmod2,fffffa43-00000000";
    int scale = 4, headless = 0, no_title = 0, want_boot = 0;
    const char *fs = NULL, *wavpath = NULL;
    int no_sound = 0, crt = 0;
    for (int k = 1; k < argc; k++)
        if (!strncmp(argv[k], "--limit=", 8) || !strcmp(argv[k], "--headless")) headless = 1;
    interactive = full_os = !headless;
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    if (interactive) { pthread_t wd; pthread_create(&wd, NULL, watchdog, NULL); pthread_detach(wd); }
    if (interactive) { limit = ~0ull; nclicks = 0; nkeys = 0; }
    for (int k = 1; k < argc; k++) {
        if (!strncmp(argv[k], "--limit=", 8)) limit = (uint64_t)strtod(argv[k] + 8, 0);
        else if (!strcmp(argv[k], "--headless")) ;
        else if (!strcmp(argv[k], "--full-os")) full_os = 1;
        else if (!strcmp(argv[k], "--no-title")) no_title = 1;
        else if (!strcmp(argv[k], "--trace-gaps")) trace_gaps = 1;
        else if (!strcmp(argv[k], "--boot")) want_boot = 1;
        else if (!strncmp(argv[k], "--bootimg=", 10)) boot_image = argv[k] + 10;
        else if (!strcmp(argv[k], "--fullscreen")) fs = "";
        else if (!strcmp(argv[k], "--no-sound")) no_sound = 1;
        else if (!strcmp(argv[k], "--crt")) crt = 1;
        else if (!strncmp(argv[k], "--wav=", 6)) wavpath = argv[k] + 6;
        else if (!strncmp(argv[k], "--fullscreen=", 13)) fs = argv[k] + 13;
        else if (!strcmp(argv[k], "--list-modes")) { display_list_modes(); return 0; }
        else if (!strncmp(argv[k], "--scale=", 8)) scale = atoi(argv[k] + 8);
        else if (!strncmp(argv[k], "--script=", 9)) parse_script(argv[k] + 9);
        else if (!strncmp(argv[k], "--app=", 6)) appdir = argv[k] + 6;
        else if (!strncmp(argv[k], "--out=", 6)) outprefix = argv[k] + 6;
        else image = argv[k];
    }
#ifdef RECOMP_TRACE
    if (getenv("RECOMP_TRACE")) {
        tr_from = (uint64_t)strtod(getenv("RECOMP_TRACE"), 0);
        tr_to = (uint64_t)strtod(strchr(getenv("RECOMP_TRACE"), ':') + 1, 0);
    }
#endif
    MEM = calloc(1, MEMSIZE);
    char fn[512];
    snprintf(fn, sizeof fn, "%s.events", outprefix);
    evlog = fopen(fn, "w");
    if (interactive) {
        if (!display_init(scale, fs, crt)) return 1;
        if (!no_sound && !wavpath) sound_init_device();
        t0_ns = next_tick_ns = next_vsync_ns = display_ticks_ns();
    }
    if (wavpath && !sound_init_wav(wavpath)) fprintf(stderr, "cannot write %s\n", wavpath);
    if (full_os && !no_title) {
        /* Galactic Dan's !Run displays !TitlePic (a small loader-stage
         * program) before !RunImage; Lemmings' equivalent splash sequence
         * (Krisalis/PSYGNO/DmaLogo) is driven by LemBoot's own code - see
         * --boot, which runs LemBoot for real instead of jumping straight
         * to the decompressed LemProg. */
        recompute_irq();
    }
    img_end_game = recomp_img_end;
    entry_tab_game = build_tab(recomp_entries, recomp_nentries, LOAD, img_end_game);
    codemap_game = recomp_codemap;
    img_end_boot = recompB_img_end;
    entry_tab_boot = build_tab(recompB_entries, recompB_nentries, LOAD, img_end_boot);
    codemap_boot = recompB_codemap;

    const char *start_image = want_boot ? boot_image : image;
    FILE *f = fopen(start_image, "rb");
    if (!f) { perror(start_image); return 1; }
    long n = fread(MEM + LOAD, 1, MEMSIZE - LOAD, f);
    fclose(f);
    uint32_t start_img_end = want_boot ? img_end_boot : img_end_game;
    if (LOAD + n != start_img_end) fprintf(stderr, "warning: image size differs from compiled image\n");
    boot_mode = want_boot;
    entry_tab = want_boot ? entry_tab_boot : entry_tab_game;
    codemap = want_boot ? codemap_boot : codemap_game;
    img_end = start_img_end;
    bank_r13[3] = SVC_STACK; bank_r13[2] = IRQ_STACK;   /* privileged-mode stacks */
    module_load(musmod_image);                   /* !Run: RMLoad MusMod2, before LemBoot */
    R[13] = 0xA8000; R[14] = RETURN_TO_OS; R[12] = 0;
    npc = LOAD;
    recompute_irq();
    clock_t t0 = clock();
    run_until(RETURN_TO_OS);
    (void)t0;
    finish("returned to OS");
}
