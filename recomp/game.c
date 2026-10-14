/* Lemmings (Psygnosis/DMA Design; Archimedes version by Krisalis, 1991):
 * what libroger needs to know about the game.
 *
 * Three translated images: LemProg (the game; ../extracted_decompressed),
 * LemBoot (the loader, which !Run starts: it shows the splash logos and
 * decompresses and chain-loads LemProg to &8000) and MusicModule 1.02
 * (musmod2, RMLoaded by !Run: a tracker player that also plays the sound
 * effects, translated for its RMA address &1800000). By default the run
 * starts in LemProg directly; --boot runs LemBoot first, as !Run does. */
#include <string.h>
#include <roger.h>

extern const struct roger_image recomp_image, recompB_image, recompM_image;   /* gen{,boot,mus}/entries.c */

static const char *const prefixes[] = {"<Obey$Dir>.", "<Lem$Dir>.", NULL};
static const struct roger_program programs[] = {{"LemProg", &recomp_image}, {NULL, NULL}};
static const struct roger_module modules[] = {
    {"../game/!LEMMINGS/musmod2,fffffa43-5842cdf9", &recompM_image}, {NULL, NULL}};

/* LemBoot copies itself from &8000 to &40000 and continues running from
 * there, so that it can load the next asset at &8000 over the low copy (the
 * loop at &8010-&802c). It is translated with --pcbias. */
static struct roger_relocation relocations[] = {{&recompB_image, 0x8000, 0x40000, 0}, {NULL, 0, 0, 0}};

static const char *boot_path = "../game/!LEMMINGS/LemBoot,fffff843-5e629b4c";
static int want_boot;
static struct roger_config config;

static int arg(const char *a)
{
    if (!strcmp(a, "--boot")) want_boot = 1;
    else if (!strncmp(a, "--bootimg=", 10)) boot_path = a + 10;
    else return 0;
    if (want_boot) { config.image = &recompB_image; config.image_path = boot_path; }
    return 1;
}

/* LemBoot's "return" from its shared loader after unpacking (&8aac et al)
 * goes through the hardware vector area (&0-&34) with a push-pc/pop-pc
 * trick that, however the kernel's vectors are set up, ends up at &8000
 * (the program just loaded): go straight there. */
static int boot_dispatch(uint32_t a)
{
    if (!roger_in_handler() && roger_current_image() == &recompB_image && a < ROGER_LOAD) {
        npc = ROGER_LOAD;
        return 1;
    }
    return 0;
}

static struct roger_config config = {
    .title = "Lemmings (recompiled)",
    .image_path = "../extracted_decompressed/LemProg.bin",
    .image = &recomp_image,
    .programs = programs,
    .relocations = relocations,
    .modules = modules,
    .appdir = "../game/!LEMMINGS",
    .dir_prefixes = prefixes,
    /* !Run selects MODE 12; LemBoot and LemProg then select MODE 9 */
    .initial_mode = 12,
    .wimpslot = 664 * 1024,
    .stack = 0xA8000,
    .screen_base = 0x1B80000,
    /* The palette is VIDC's, loaded by a raw IRQ handler LemBoot and
     * LemProg each install at &100 (LemProg: &8530, installed at &84f4).
     * For vsync it pushes the top palette; LemProg also programs timer 1
     * to fire part way down the frame, where it pushes the panel's
     * palette. The timer call also clears the handler's re-entry gate
     * (&85fc), so it is made every frame. */
    .irq1v = 1,
    .irq1v_timer_always = 1,
    .pointer_y_offset = 64,              /* the pointer's hit point is 16 rows below its top */
    .call_addr = boot_dispatch,
    .arg = arg,
    .usage = "  --boot            start with LemBoot (splash screens), as !Run does\n"
             "  --bootimg=FILE    LemBoot's file\n",
};

int main(int argc, char **argv)
{
    relocations[0].len = recompB_image.end - 0x8000;
    roger_main(argc, argv, &config);
}
