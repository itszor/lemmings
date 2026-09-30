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
#include "runtime.h"
#include "os.h"

#define MEMSIZE      0x4000000u
#define SCREEN       (0x1C00000u - 0x80000u)
#define RETURN_TO_OS 0x3FFFFF0u
#define HANDLER_RET  0x3FFFFE0u
#define TICK_STEPS   20000
#define VSYNC_STEPS  40000
#define LOAD         0x8000u

uint32_t R[16];
uint32_t NF, ZF, CF, VF;
uint8_t *MEM;
uint32_t npc;
uint64_t icount, irq_next;
const uint8_t *codemap;
uint32_t img_end;

/* generated */
extern const struct entry { uint32_t a; fn_t f; } recomp_entries[];
extern const unsigned recomp_nentries;
extern const uint8_t recomp_codemap[];
extern const uint32_t recomp_img_end;

static fn_t *entry_tab;                 /* direct-mapped: (a - LOAD) >> 2 */
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
static int last_buttons;
/* --script=ms:action[:args],...  actions: click:x:y (OS units), release, buttons:mask,
   move:dx:dy, key:inkey (held 200ms), type:ascii, shot, quit                         */
static struct { uint64_t ms; char act[8]; int a, b; } script[1024];
static int nscript, script_i, shots;
static uint64_t key_release_ms[129];

static void parse_script(const char *p)
{
    while (*p && nscript < 1024) {
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

uint32_t os_write_bank_addr(void) { return SCREEN + bank * 0x14000; }
uint32_t os_screen_base(void) { return SCREEN; }

/* scenario: no fixed click/key timings for Lemmings yet (galactic dan's were
 * tuned to its title screen); headless (--limit=N) runs are keyboard/mouse-
 * silent until we have real ones, or use --script for ad hoc input. */
static struct { uint64_t step; uint32_t x, y, b; } clicks[1];
static unsigned nclicks, click_i;
static struct { int inkey; uint64_t from, to; } keys[1];
static unsigned nkeys;

static void finish(const char *why) __attribute__((noreturn));
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
static void vdu_put(uint8_t c)
{
    if (nvdu < sizeof vdu) vdu[nvdu++] = c;
    if (full_os) vdu_write(c);
}

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
        fprintf(f, "%llu: branch to untranslated address %08x (LR=%08x)\n",
                (unsigned long long)icount, a, R[14]);
        fclose(f);
    }
    fprintf(stderr, "branch to untranslated address %08x (icount %llu, LR=%08x) - see untranslated.log\n",
            a, (unsigned long long)icount, R[14]);
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
    fn_t f = (!interp_only && a >= LOAD && a < img_end) ? entry_tab[(a - LOAD) >> 2] : 0;
    if (f) { f(a); return; }
    if (a == HANDLER_RET) return;
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

static const uint8_t *displayed(void)
{
    return MEM + SCREEN + (vdu_mode == 15 ? 0 : display_bank * 0x14000);
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
        sound_render(480);                       /* --wav in interactive runs */
        call_vector(0x1C, 0, 0);
    }
    if (vsync_now || now >= next_vsync_ns) {
        next_vsync_ns += 2 * CS_NS;
        display_poll();
        if (nscript) run_script();
        if (screenshot_requested) {
            char fn[64];
            snprintf(fn, sizeof fn, "screenshot-%d.bmp", ++shots);
            display_screenshot(displayed(), vdu_mode == 15 ? 640 : 320, fn);
            fprintf(stderr, "saved %s\n", fn);
            screenshot_requested = 0;
        }
        if (quit_requested) finish("window closed");
        display_present(displayed(), vdu_mode == 15 ? 640 : 320);
        monotonic += 2;
        uint32_t r[2] = {4, 0};
        call_vector(0x10, 2, r);
        if (mouse_buttons != last_buttons) {
            last_buttons = mouse_buttons;
            ev("mouse", "iii", mouse_x, mouse_y, mouse_buttons);
            uint32_t m[5] = {10, mouse_x, mouse_y, mouse_buttons, monotonic};
            call_vector(0x10, 5, m);
        }
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
        sound_render(480);                       /* --wav: 1 cs of audio */
        call_vector(0x1C, 0, 0);
    }
    if (icount >= next_vsync) {
        next_vsync += VSYNC_STEPS;
        monotonic += 2;
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
    switch (v) {
    case 148: return SCREEN + bank * 0x14000;
    case 149: return SCREEN + (full_os ? display_bank : bank) * 0x14000;
    case 150: case 7: return 81920;
    case 1: case 11: return 319;
    case 2: case 3: case 12: return 255;
    case 4: case 5: return 1;
    case 6: return 320;
    case 9: return 3;
    default: return 0;
    }
}

static uint32_t swi_pc;
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
        if (!ok) { fprintf(stderr, "file not found %s\n", name); finish("file not found"); }
        if (R[3] & 0xFF) finish("load at file address unsupported");
        long len = load_file(path, R[2]);
        R[4] = (uint32_t)len; R[0] = 1;
        return;
    }
    if (op == 5 || op == 17 || op == 13 || op == 15) {
        if (!ok) { R[0] = 0; return; }
        struct stat st;
        stat(path, &st);
        R[0] = 1; R[2] = 0xFFFFFD00; R[3] = 0; R[4] = (uint32_t)st.st_size; R[5] = 3;
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
            display_set_mouse((int16_t)(blk[1] | blk[2] << 8), (int16_t)(blk[3] | blk[4] << 8));
        if (R[0] == 21 && blk[0] == 0)
            ev("OS_Word", "isi", R[0], blk, 6, blk[6] | blk[7] << 8 | blk[8] << 16 | (uint32_t)blk[9] << 24);
        else ev("OS_Word", "is", R[0], blk, 8);
        return;
    }
    case 0x1C:
        if (interactive) { R[0] = mouse_x; R[1] = mouse_y; R[2] = mouse_buttons; R[3] = monotonic; }
        else { R[0] = 640; R[1] = 512; R[2] = 0; R[3] = monotonic; }
        return;
    case 0x1F: case 0x20:
        ev(b == 0x1F ? "OS_Claim" : "OS_Release", "iii", R[0], R[1], R[2]);
        if (b == 0x1F && R[0] < 0x20) {
            vectors[R[0]].code = R[1]; vectors[R[0]].ws = R[2]; vectors[R[0]].set = 1;
        }
        return;
    case 0x2C: CF = interactive ? escape_pressed : 0; return;
    case 0x31: {
        uint32_t i = R[0], o = R[1];
        for (;;) { uint32_t v = RD32(i); if (v == 0xFFFFFFFF) break;
                   WR32(o, vduvar(v)); i += 4; o += 4; }
        return;
    }
    case 0x35: {
        static const uint32_t mv[13] = {0, 319, 255, 255, 1, 1, 320, 81920, 0, 3, 0, 319, 255};
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
        sound_swi(b);
        return;
    }
    if ((b & ~0xFu) == 0x41C40) {          /* MusicModule2's own SWI chunk */
        musmod2_swi(b);
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
            if (opc >= 8 && opc <= 11 && rd == 15) SETPSR(res & 0xF0000000);
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
        uint32_t a = start;
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
    sound_close();
    if (vdu_unhandled) fprintf(stderr, "VDU: %u unhandled codes/characters\n", vdu_unhandled);
    fprintf(stderr, "stopped: %s after %llu instructions (%llu interpreted, %llu SMC stores noted)\n",
            why, (unsigned long long)icount, (unsigned long long)interp_count,
            (unsigned long long)smc_count);
    exit(0);
}

int main(int argc, char **argv)
{
    const char *image = "../extracted_decompressed/LemProg.bin";
    int scale = 4, headless = 0, no_title = 0;
    const char *fs = NULL, *wavpath = NULL;
    int no_sound = 0;
    for (int k = 1; k < argc; k++)
        if (!strncmp(argv[k], "--limit=", 8) || !strcmp(argv[k], "--headless")) headless = 1;
    interactive = full_os = !headless;
    if (interactive) { limit = ~0ull; nclicks = 0; nkeys = 0; }
    for (int k = 1; k < argc; k++) {
        if (!strncmp(argv[k], "--limit=", 8)) limit = (uint64_t)strtod(argv[k] + 8, 0);
        else if (!strcmp(argv[k], "--headless")) ;
        else if (!strcmp(argv[k], "--full-os")) full_os = 1;
        else if (!strcmp(argv[k], "--no-title")) no_title = 1;
        else if (!strcmp(argv[k], "--trace-gaps")) trace_gaps = 1;
        else if (!strcmp(argv[k], "--fullscreen")) fs = "";
        else if (!strcmp(argv[k], "--no-sound")) no_sound = 1;
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
    img_end = recomp_img_end;
    if (interactive) {
        if (!display_init(scale, fs)) return 1;
        if (!no_sound && !wavpath) sound_init_device();
        t0_ns = next_tick_ns = next_vsync_ns = display_ticks_ns();
    }
    if (wavpath && !sound_init_wav(wavpath)) fprintf(stderr, "cannot write %s\n", wavpath);
    if (full_os && !no_title) {
        /* Galactic Dan's !Run displays !TitlePic (a small loader-stage
         * program) before !RunImage; Lemmings' equivalent splash sequence
         * (Krisalis/PSYGNO/DmaLogo) is driven by LemBoot's own code, which
         * we don't execute here (we jump straight to the decompressed
         * LemProg) - so there's nothing to run_loader_program() yet. */
        recompute_irq();
    }
    FILE *f = fopen(image, "rb");
    if (!f) { perror(image); return 1; }
    long n = fread(MEM + LOAD, 1, MEMSIZE - LOAD, f);
    fclose(f);
    if (LOAD + n != img_end) fprintf(stderr, "warning: image size differs from compiled image\n");
    codemap = recomp_codemap;
    entry_tab = calloc((img_end - LOAD) / 4 + 1, sizeof(fn_t));
    for (unsigned k = 0; k < recomp_nentries; k++)
        entry_tab[(recomp_entries[k].a - LOAD) >> 2] = recomp_entries[k].f;
    R[13] = 0xA8000; R[14] = RETURN_TO_OS; R[12] = 0;
    npc = LOAD;
    recompute_irq();
    clock_t t0 = clock();
    run_until(RETURN_TO_OS);
    (void)t0;
    finish("returned to OS");
}
