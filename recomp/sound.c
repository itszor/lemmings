/* Sound stub. LemProg doesn't use the standard Sound_* SWIs at all - it
 * talks to its own MusicModule2 (musmod2) via a custom SWI chunk
 * (&41C40-&41C4B), which we haven't implemented yet (see runtime.c's
 * musmod2_swi). This file just satisfies os.h's interface so the runtime
 * links and runs silently until that's built out.
 */
#include "os.h"

int sound_init_device(void) { return 1; }
int sound_init_wav(const char *path) { (void)path; return 0; }
void sound_render(int frames) { (void)frames; }
void sound_swi(uint32_t b) { (void)b; }
void sound_close(void) {}
