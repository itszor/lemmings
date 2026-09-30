/* VDU driver stub. Not yet implemented for Lemmings - we don't know its
 * screen mode / sprite plotting conventions yet, so this just counts
 * unhandled output rather than interpreting it. Fill in once LemProg's
 * display setup (mode selection, screen bank handling) has been read from
 * the decompile.
 */
#include "os.h"

unsigned vdu_unhandled;
int vdu_mode = 13;      /* placeholder: RISC OS default 320x256 8bpp */

void vdu_write(uint8_t c)
{
    (void)c;
    vdu_unhandled++;
}

int sprite_op_full(void)
{
    return 0;      /* not handled: caller (runtime.c's sprite_op) logs and continues */
}
