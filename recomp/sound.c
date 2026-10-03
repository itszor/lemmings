/* Host audio for the emulated sound DMA (see runtime.c's sound_dma_fill()).
 *
 * The music/effects player (musmod2) is real translated code running as the
 * OS Sound system's Level 1 handler, so it has to run on the emulation
 * thread: runtime.c calls its fill code once per emulated DMA buffer period
 * and hands each converted buffer (16-bit stereo, at the DMA rate,
 * 1e6/period Hz) to sound_out(). Here that goes either to an SDL audio
 * stream - pushed, not pulled: no callback, SDL resamples to the device rate
 * - or to a --wav file for headless runs.
 */
#include <SDL3/SDL.h>
#include <stdio.h>
#include <string.h>
#include "os.h"

static SDL_AudioStream *stream;
static int stream_rate;
static FILE *wav;
static uint32_t wav_frames;
static int wav_rate;

int sound_init_device(void)
{
    if (!SDL_InitSubSystem(SDL_INIT_AUDIO)) { SDL_Log("audio: %s", SDL_GetError()); return 0; }
    SDL_AudioSpec spec = {SDL_AUDIO_S16, 2, 41666};
    stream = SDL_OpenAudioDeviceStream(SDL_AUDIO_DEVICE_DEFAULT_PLAYBACK, &spec, NULL, NULL);
    if (!stream) { SDL_Log("audio: %s", SDL_GetError()); return 0; }
    stream_rate = spec.freq;
    SDL_ResumeAudioStreamDevice(stream);
    return 1;
}

static void wav_header(void)
{
    uint32_t data = wav_frames * 4;
    uint8_t h[44];
    memcpy(h, "RIFF", 4); *(uint32_t *)(h + 4) = 36 + data; memcpy(h + 8, "WAVEfmt ", 8);
    *(uint32_t *)(h + 16) = 16; *(uint16_t *)(h + 20) = 1; *(uint16_t *)(h + 22) = 2;
    *(uint32_t *)(h + 24) = wav_rate; *(uint32_t *)(h + 28) = wav_rate * 4; *(uint16_t *)(h + 32) = 4;
    *(uint16_t *)(h + 34) = 16; memcpy(h + 36, "data", 4); *(uint32_t *)(h + 40) = data;
    fseek(wav, 0, SEEK_SET);
    fwrite(h, 1, 44, wav);
    fseek(wav, 0, SEEK_END);
}

int sound_init_wav(const char *path)
{
    wav = fopen(path, "wb");
    if (!wav) return 0;
    wav_rate = 41666;
    wav_header();
    return 1;
}

/* One emulated DMA buffer: `frames` stereo frames at `rate` Hz. */
void sound_out(const int16_t *lr, int frames, int rate)
{
    if (wav) {
        /* A WAV file has one rate: keep the first one seen (the game picks
         * its rate once, via MusicModule's Samplerate SWI). */
        if (!wav_frames) wav_rate = rate;
        fwrite(lr, 4, frames, wav);
        wav_frames += frames;
    }
    if (stream) {
        if (rate != stream_rate) {
            SDL_AudioSpec spec = {SDL_AUDIO_S16, 2, rate};
            SDL_SetAudioStreamFormat(stream, &spec, NULL);
            stream_rate = rate;
        }
        /* Fills are paced by the wall-clock centisecond tick, so the queue
         * should hover around a few buffers; if the device has fallen
         * behind (e.g. after a stall), drop rather than build up latency. */
        int queued = SDL_GetAudioStreamQueued(stream);
        if (queued == 0) {                       /* start, or ran dry: re-establish a cushion */
            static int16_t zero[2 * 4096];
            int pad = rate / 25;                 /* 40ms */
            SDL_PutAudioStreamData(stream, zero, (pad < 4096 ? pad : 4096) * 4);
        }
        if (queued < rate * 4 / 4)
            SDL_PutAudioStreamData(stream, lr, frames * 4);
    }
}

/* Superseded by runtime.c's sound DMA; kept for os.h. */
void sound_render(int frames) { (void)frames; }
void sound_swi(uint32_t b) { (void)b; }

void sound_close(void)
{
    if (wav) { wav_header(); fclose(wav); wav = 0; }
    if (stream) { SDL_DestroyAudioStream(stream); stream = 0; }
}
