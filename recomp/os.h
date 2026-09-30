/* Interfaces between the OS emulation pieces (runtime.c, vdu.c, display.c). */
#ifndef OS_H
#define OS_H
#include <stdint.h>

/* runtime.c */
uint32_t os_write_bank_addr(void);        /* screen memory the VDU drivers write to */
uint32_t os_screen_base(void);

/* vdu.c */
void vdu_write(uint8_t c);
int  sprite_op_full(void);
extern unsigned vdu_unhandled;
extern int vdu_mode;

/* display.c (SDL3) */
int  display_init(int scale, const char *fullscreen);   /* NULL, "" or "WxH[@Hz]" */
void display_toggle_fullscreen(void);
void display_list_modes(void);
void display_present(const uint8_t *pixels, int width);   /* width x 256 bytes, 8bpp */
void display_poll(void);                        /* pump SDL events */
uint64_t display_ticks_ns(void);
void display_sleep_ns(uint64_t ns);
extern uint8_t key_down[128];                   /* by RISC OS internal key number */
extern int mouse_x, mouse_y, mouse_buttons;     /* OS units; 4 select, 2 menu, 1 adjust */
extern int quit_requested, escape_pressed;
int  key_buffer_get(void);
void display_set_mouse(int x, int y);             /* OS_Word 21,3 */
void key_buffer_put(int c);
void key_buffer_flush(void);
void display_screenshot(const uint8_t *pix, int width, const char *path);
extern int screenshot_requested;                      /* -1 if empty */
/* sound.c */
int  sound_init_device(void);
int  sound_init_wav(const char *path);
void sound_render(int frames);                  /* headless: frames at 48kHz */
void sound_swi(uint32_t b);
void sound_close(void);
#endif
