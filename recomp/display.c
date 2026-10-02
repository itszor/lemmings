/* SDL3 window, keyboard and mouse for the recompiled game.
 *
 * Mode 13 is 320x256 at 8bpp using the default 256-colour palette; it is shown
 * at 4:3 as on an Archimedes monitor.  Keys are tracked by RISC OS internal
 * key number (INKEY -(n+1)) and typed characters go to a small key buffer.
 */
#include <SDL3/SDL.h>
#include <stdio.h>
#include <string.h>
#include "os.h"

uint8_t key_down[128];
int mouse_x = 640, mouse_y = 512, mouse_buttons;
int quit_requested, escape_pressed;

static SDL_Window *win;
static SDL_Renderer *ren;
static SDL_Texture *tex;
static uint32_t palette[256];
static int kbuf[64], khead, ktail;
static uint64_t last_setpos_ns;                 /* game re-centres the pointer: capture mouse */
static int relative;
static SDL_DisplayMode fs_mode;                 /* exclusive fullscreen mode, if chosen */
static int fs_exclusive, fullscreen;
#define MOUSE_SENS 2.0f                         /* OS units per host pixel in relative mode */

void display_set_mouse(int x, int y)
{
    mouse_x = x; mouse_y = y;
    last_setpos_ns = SDL_GetTicksNS();
}
#define LW 1024
#define LH 768

void key_buffer_put(int c)
{
    int n = (khead + 1) % 64;
    if (n != ktail) { kbuf[khead] = c; khead = n; }
}
void key_buffer_flush(void) { ktail = khead; }

int key_buffer_get(void)
{
    if (ktail == khead) return -1;
    int c = kbuf[ktail];
    ktail = (ktail + 1) % 64;
    return c;
}

/* SDL scancode -> RISC OS internal key number (INKEY -(n+1)), -1 if none */
static int internal_key(SDL_Scancode s)
{
    static const struct { SDL_Scancode s; int k; } map[] = {
        {SDL_SCANCODE_LSHIFT, 3}, {SDL_SCANCODE_RSHIFT, 6}, {SDL_SCANCODE_LCTRL, 4},
        {SDL_SCANCODE_RCTRL, 7}, {SDL_SCANCODE_LALT, 5}, {SDL_SCANCODE_RALT, 8},
        {SDL_SCANCODE_Q, 16}, {SDL_SCANCODE_3, 17}, {SDL_SCANCODE_4, 18}, {SDL_SCANCODE_5, 19},
        {SDL_SCANCODE_F4, 20}, {SDL_SCANCODE_8, 21}, {SDL_SCANCODE_F7, 22}, {SDL_SCANCODE_MINUS, 23},
        {SDL_SCANCODE_LEFT, 25}, {SDL_SCANCODE_KP_6, 26}, {SDL_SCANCODE_KP_7, 27},
        {SDL_SCANCODE_F11, 28}, {SDL_SCANCODE_F12, 29}, {SDL_SCANCODE_F10, 30},
        {SDL_SCANCODE_SCROLLLOCK, 31}, {SDL_SCANCODE_PRINTSCREEN, 32}, {SDL_SCANCODE_W, 33},
        {SDL_SCANCODE_E, 34}, {SDL_SCANCODE_T, 35}, {SDL_SCANCODE_7, 36}, {SDL_SCANCODE_I, 37},
        {SDL_SCANCODE_9, 38}, {SDL_SCANCODE_0, 39}, {SDL_SCANCODE_DOWN, 41},
        {SDL_SCANCODE_KP_8, 42}, {SDL_SCANCODE_KP_9, 43}, {SDL_SCANCODE_PAUSE, 44},
        {SDL_SCANCODE_GRAVE, 45}, {SDL_SCANCODE_BACKSPACE, 47}, {SDL_SCANCODE_1, 48},
        {SDL_SCANCODE_2, 49}, {SDL_SCANCODE_D, 50}, {SDL_SCANCODE_R, 51}, {SDL_SCANCODE_6, 52},
        {SDL_SCANCODE_U, 53}, {SDL_SCANCODE_O, 54}, {SDL_SCANCODE_P, 55},
        {SDL_SCANCODE_LEFTBRACKET, 56}, {SDL_SCANCODE_UP, 57}, {SDL_SCANCODE_KP_PLUS, 58},
        {SDL_SCANCODE_KP_MINUS, 59}, {SDL_SCANCODE_KP_ENTER, 60}, {SDL_SCANCODE_INSERT, 61},
        {SDL_SCANCODE_HOME, 62}, {SDL_SCANCODE_PAGEUP, 63}, {SDL_SCANCODE_CAPSLOCK, 64},
        {SDL_SCANCODE_A, 65}, {SDL_SCANCODE_X, 66}, {SDL_SCANCODE_F, 67}, {SDL_SCANCODE_Y, 68},
        {SDL_SCANCODE_J, 69}, {SDL_SCANCODE_K, 70}, {SDL_SCANCODE_APOSTROPHE, 79},
        {SDL_SCANCODE_RETURN, 73}, {SDL_SCANCODE_KP_DIVIDE, 74}, {SDL_SCANCODE_KP_PERIOD, 76},
        {SDL_SCANCODE_NUMLOCKCLEAR, 77}, {SDL_SCANCODE_PAGEDOWN, 78}, {SDL_SCANCODE_S, 81},
        {SDL_SCANCODE_C, 82}, {SDL_SCANCODE_G, 83}, {SDL_SCANCODE_H, 84}, {SDL_SCANCODE_N, 85},
        {SDL_SCANCODE_L, 86}, {SDL_SCANCODE_SEMICOLON, 87}, {SDL_SCANCODE_RIGHTBRACKET, 88},
        {SDL_SCANCODE_DELETE, 89}, {SDL_SCANCODE_KP_MULTIPLY, 91}, {SDL_SCANCODE_EQUALS, 93},
        {SDL_SCANCODE_TAB, 96}, {SDL_SCANCODE_Z, 97}, {SDL_SCANCODE_SPACE, 98},
        {SDL_SCANCODE_V, 99}, {SDL_SCANCODE_B, 100}, {SDL_SCANCODE_M, 101},
        {SDL_SCANCODE_COMMA, 102}, {SDL_SCANCODE_PERIOD, 103}, {SDL_SCANCODE_SLASH, 104},
        {SDL_SCANCODE_END, 105}, {SDL_SCANCODE_KP_0, 106}, {SDL_SCANCODE_KP_1, 107},
        {SDL_SCANCODE_KP_3, 108}, {SDL_SCANCODE_ESCAPE, 112}, {SDL_SCANCODE_F1, 113},
        {SDL_SCANCODE_F2, 114}, {SDL_SCANCODE_F3, 115}, {SDL_SCANCODE_F5, 116},
        {SDL_SCANCODE_F6, 117}, {SDL_SCANCODE_F8, 118}, {SDL_SCANCODE_F9, 119},
        {SDL_SCANCODE_BACKSLASH, 120}, {SDL_SCANCODE_RIGHT, 121}, {SDL_SCANCODE_KP_4, 122},
        {SDL_SCANCODE_KP_5, 123}, {SDL_SCANCODE_KP_2, 124},
    };
    for (unsigned i = 0; i < sizeof map / sizeof map[0]; i++)
        if (map[i].s == s) return map[i].k;
    return -1;
}

/* Fullscreen keeps the 4:3 picture: the logical presentation letterboxes it
   (bars at the sides on a widescreen monitor).  Exclusive mode switches the
   monitor to a real display mode; desktop mode just scales. */
static void apply_fullscreen(void)
{
    if (fullscreen && fs_exclusive) SDL_SetWindowFullscreenMode(win, &fs_mode);
    else SDL_SetWindowFullscreenMode(win, NULL);            /* borderless desktop */
    SDL_SetWindowFullscreen(win, fullscreen);
    SDL_SyncWindow(win);
}

void display_toggle_fullscreen(void)
{
    fullscreen = !fullscreen;
    apply_fullscreen();
}

void display_list_modes(void)
{
    if (!SDL_Init(SDL_INIT_VIDEO)) { SDL_Log("SDL_Init: %s", SDL_GetError()); return; }
    int n = 0;
    SDL_DisplayID d = SDL_GetPrimaryDisplay();
    const SDL_DisplayMode *cur = SDL_GetCurrentDisplayMode(d);
    if (cur) printf("current: %dx%d @ %.2fHz (driver %s)\n", cur->w, cur->h, cur->refresh_rate,
                    SDL_GetCurrentVideoDriver());
    SDL_DisplayMode **m = SDL_GetFullscreenDisplayModes(d, &n);
    for (int i = 0; i < n; i++)
        printf("  %dx%d @ %.2fHz%s\n", m[i]->w, m[i]->h, m[i]->refresh_rate,
               m[i]->pixel_density != 1.0f ? " (high density)" : "");
    SDL_free(m);
    SDL_Quit();
}

/* spec: NULL windowed, "" desktop fullscreen, "WxH[@Hz]" exclusive mode */
int display_init(int scale, const char *fs)
{
    if (!SDL_Init(SDL_INIT_VIDEO)) {
        SDL_Log("SDL_Init: %s", SDL_GetError());
        return 0;
    }
    if (!SDL_CreateWindowAndRenderer("Lemmings (recompiled)", 256 * scale, 192 * scale,
                                     SDL_WINDOW_RESIZABLE, &win, &ren)) {
        SDL_Log("window: %s", SDL_GetError());
        return 0;
    }
    SDL_SetRenderLogicalPresentation(ren, LW, LH, SDL_LOGICAL_PRESENTATION_LETTERBOX);
    if (fs) {
        int w = 0, h = 0;
        float hz = 0;
        fullscreen = 1;
        if (*fs && sscanf(fs, "%dx%d@%f", &w, &h, &hz) >= 2) {
            if (SDL_GetClosestFullscreenDisplayMode(SDL_GetDisplayForWindow(win), w, h, hz, false, &fs_mode)) {
                fs_exclusive = 1;
                SDL_Log("fullscreen mode %dx%d @ %.2fHz", fs_mode.w, fs_mode.h, fs_mode.refresh_rate);
            } else SDL_Log("no display mode near %s (%s); using desktop fullscreen", fs, SDL_GetError());
        }
        apply_fullscreen();
    }
    tex = SDL_CreateTexture(ren, SDL_PIXELFORMAT_XRGB8888, SDL_TEXTUREACCESS_STREAMING, 640, 256);
    SDL_SetTextureScaleMode(tex, SDL_SCALEMODE_NEAREST);
    for (int c = 0; c < 256; c++) {              /* default 256-colour palette (unused for
                                                      Lemmings - see update_palette() below;
                                                      kept as a fallback for --full-os VDU) */
        int t = c & 3;
        int r = ((c >> 4) & 1) << 3 | ((c >> 2) & 1) << 2 | t;
        int g = ((c >> 6) & 1) << 3 | ((c >> 5) & 1) << 2 | t;
        int b = ((c >> 7) & 1) << 3 | ((c >> 3) & 1) << 2 | t;
        palette[c] = (uint32_t)(r * 17) << 16 | (uint32_t)(g * 17) << 8 | (uint32_t)(b * 17);
    }
    return 1;
}

/* Lemmings programs VIDC's 16-entry palette directly (runtime.c's
 * vidc_write()), not via the OS - refresh our copy from it each frame.
 * Register format: bits 0-3 red, 4-7 green, 8-11 blue (4 bits each, 4bpp). */
static uint32_t palette_top[16];           /* lines above palette_split (see os.h) */
static void update_palette(void)
{
    for (int c = 0; c < 16; c++) {
        uint32_t v = vidc_palette[c], t = vidc_palette_top[c];
        int r = (v & 0xF) * 17, g = ((v >> 4) & 0xF) * 17, b = ((v >> 8) & 0xF) * 17;
        palette[c] = (uint32_t)r << 16 | (uint32_t)g << 8 | (uint32_t)b;
        r = (t & 0xF) * 17, g = ((t >> 4) & 0xF) * 17, b = ((t >> 8) & 0xF) * 17;
        palette_top[c] = (uint32_t)r << 16 | (uint32_t)g << 8 | (uint32_t)b;
    }
}
static const uint32_t *line_palette(int y) { return y < palette_split ? palette_top : palette; }

void display_present(const uint8_t *pix, int width)
{
    uint32_t *out;
    int pitch;
    update_palette();
    if (!SDL_LockTexture(tex, NULL, (void **)&out, &pitch)) return;
    for (int y = 0; y < 256; y++) {
        uint32_t *row = (uint32_t *)((uint8_t *)out + y * pitch);
        for (int x = 0; x < width; x++) {
            uint8_t byte = pix[y * (width / 2) + x / 2];
            uint8_t nib = (x & 1) ? (byte >> 4) : (byte & 0xF);
            row[x] = line_palette(y)[nib];
        }
    }
    SDL_UnlockTexture(tex);
    SDL_FRect src = {0, 0, (float)width, 256};
    SDL_SetRenderDrawColor(ren, 0, 0, 0, 255);
    SDL_RenderClear(ren);
    SDL_RenderTexture(ren, tex, &src, NULL);
    SDL_RenderPresent(ren);
}

static int ascii_for(SDL_Scancode s, int shift)
{
    SDL_Keycode k = SDL_GetKeyFromScancode(s, shift ? SDL_KMOD_SHIFT : SDL_KMOD_NONE, false);
    if (k == SDLK_RETURN) return 13;
    if (k == SDLK_BACKSPACE || k == SDLK_DELETE) return 127;
    if (k == SDLK_TAB) return 9;
    if (k >= 32 && k < 127) return (int)k;
    return -1;
}

void display_poll(void)
{
    SDL_Event e;
    int want = last_setpos_ns && SDL_GetTicksNS() - last_setpos_ns < 500000000ull;
    if (want != relative) {
        relative = want;
        SDL_SetWindowRelativeMouseMode(win, relative);
    }
    while (SDL_PollEvent(&e)) {
        switch (e.type) {
        case SDL_EVENT_QUIT:
            quit_requested = 1;
            break;
        case SDL_EVENT_KEY_DOWN:
        case SDL_EVENT_KEY_UP: {
            int down = e.type == SDL_EVENT_KEY_DOWN;
            int k = internal_key(e.key.scancode);
            if (k >= 0) key_down[k] = down;
            if (e.key.scancode == SDL_SCANCODE_LSHIFT || e.key.scancode == SDL_SCANCODE_RSHIFT)
                key_down[0] = down;
            if (e.key.scancode == SDL_SCANCODE_LCTRL || e.key.scancode == SDL_SCANCODE_RCTRL)
                key_down[1] = down;
            if (e.key.scancode == SDL_SCANCODE_LALT || e.key.scancode == SDL_SCANCODE_RALT)
                key_down[2] = down;
            if (down && e.key.scancode == SDL_SCANCODE_F12) { screenshot_requested = 1; break; }
            if (e.key.scancode == SDL_SCANCODE_F11 ||
                (e.key.scancode == SDL_SCANCODE_RETURN && (e.key.mod & SDL_KMOD_ALT))) {
                if (down && !e.key.repeat) display_toggle_fullscreen();
                break;                                      /* not passed to the game */
            }
            if (e.key.scancode == SDL_SCANCODE_ESCAPE) {
                if (down && !e.key.repeat) escape_pressed = 1;   /* one condition per press */
            }
            else if (down && !e.key.repeat) {
                int c = ascii_for(e.key.scancode, (e.key.mod & SDL_KMOD_SHIFT) != 0);
                if (c >= 0) key_buffer_put(c);
            }
            break;
        }
        case SDL_EVENT_MOUSE_MOTION:
        case SDL_EVENT_MOUSE_BUTTON_DOWN:
        case SDL_EVENT_MOUSE_BUTTON_UP: {
            if (relative) {
                if (e.type == SDL_EVENT_MOUSE_MOTION) {
                    mouse_x += (int)(e.motion.xrel * MOUSE_SENS);
                    mouse_y -= (int)(e.motion.yrel * MOUSE_SENS);
                }
            } else {
                SDL_ConvertEventToRenderCoordinates(ren, &e);
                float x = e.type == SDL_EVENT_MOUSE_MOTION ? e.motion.x : e.button.x;
                float y = e.type == SDL_EVENT_MOUSE_MOTION ? e.motion.y : e.button.y;
                mouse_x = (int)(x * 1280 / LW);
                mouse_y = 1023 - (int)(y * 1024 / LH);
            }
            if (mouse_x < 0) mouse_x = 0; if (mouse_x > 1279) mouse_x = 1279;
            if (mouse_y < 0) mouse_y = 0; if (mouse_y > 1023) mouse_y = 1023;
            if (e.type != SDL_EVENT_MOUSE_MOTION) {
                int bit = e.button.button == SDL_BUTTON_LEFT ? 4 : e.button.button == SDL_BUTTON_MIDDLE ? 2 : 1;
                int kn = bit == 4 ? 9 : bit == 2 ? 10 : 11;
                if (e.type == SDL_EVENT_MOUSE_BUTTON_DOWN) mouse_buttons |= bit; else mouse_buttons &= ~bit;
                key_down[kn] = (mouse_buttons & bit) != 0;
            }
            break;
        }
        default:
            break;
        }
    }
}

/* save the displayed screen as BMP (F12, or --script shot) */
void display_screenshot(const uint8_t *pix, int width, const char *path)
{
    SDL_Surface *s = SDL_CreateSurface(width, 256, SDL_PIXELFORMAT_XRGB8888);
    if (!s) return;
    update_palette();
    for (int y = 0; y < 256; y++) {
        uint32_t *row = (uint32_t *)((uint8_t *)s->pixels + y * s->pitch);
        for (int x = 0; x < width; x++) {
            uint8_t byte = pix[y * (width / 2) + x / 2];
            uint8_t nib = (x & 1) ? (byte >> 4) : (byte & 0xF);
            row[x] = line_palette(y)[nib];
        }
    }
    SDL_SaveBMP(s, path);
    SDL_DestroySurface(s);
}
int screenshot_requested;

uint64_t display_ticks_ns(void) { return SDL_GetTicksNS(); }
void display_sleep_ns(uint64_t ns) { SDL_DelayNS(ns); }
