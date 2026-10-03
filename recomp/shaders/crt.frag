#version 450
// CRT fragment shader for --crt (SDL 3.4 GPU renderer, SDL_GPURenderState).
//
// Draws the game's 1:1 screen texture (320x256 or 640x256, already
// palette-converted RGB) as a monitor would: each source row is an electron
// beam with a gaussian vertical profile that widens with brightness, rows are
// sharply interpolated horizontally, and an aperture-grille mask is applied
// in output pixels. All blending is done in linear light.
//
// Inputs follow SDL's GPU renderer conventions: v_color/v_uv from its vertex
// shader, the bound texture at set 2 binding 0, uniforms at set 3 binding 0.
// Rebuild the SPIR-V header with shaders/build.sh after editing.

layout(location = 0) in vec4 v_color;
layout(location = 1) in vec2 v_uv;
layout(location = 0) out vec4 o_color;

layout(set = 2, binding = 0) uniform sampler2D u_texture;

layout(set = 3, binding = 0, std140) uniform Context {
    vec2 source_size;       // game pixels (e.g. 320x256)
    vec2 output_size;       // destination rectangle in output pixels
};

const float GAMMA = 2.4;            // CRT-ish transfer
const float BEAM_MIN = 0.30;        // beam half-width (in rows) for dark pixels
const float BEAM_MAX = 0.48;        // ...and for bright ones (blooming)
const float SHARPNESS = 3.0;        // horizontal: 1 = bilinear, higher = sharper
const float MASK_DARK = 0.70;       // aperture grille: attenuation of the other phosphors
const float BRIGHTNESS = 1.30;      // compensates scanline + mask darkening

vec3 fetch_linear(vec2 texel)
{
    vec2 uv = (clamp(texel, vec2(0.0), source_size - 1.0) + 0.5) / source_size;
    return pow(texture(u_texture, uv).rgb, vec3(GAMMA));
}

// one source row, sharply interpolated horizontally at source x position px
vec3 row_color(float px, float row)
{
    float x0 = floor(px - 0.5);
    float t = (px - 0.5) - x0;
    t = clamp((t - 0.5) * SHARPNESS + 0.5, 0.0, 1.0);
    return mix(fetch_linear(vec2(x0, row)), fetch_linear(vec2(x0 + 1.0, row)), t);
}

vec3 beam(vec3 c, float dist)
{
    vec3 w = mix(vec3(BEAM_MIN), vec3(BEAM_MAX), sqrt(c));      // brighter = wider
    return c * exp(-0.5 * (dist * dist) / (w * w));
}

void main()
{
    vec2 pos = v_uv * source_size;
    float row = floor(pos.y);
    float dy = pos.y - (row + 0.5);                                 // -0.5..0.5 from row centre
    float nrow = row + (dy < 0.0 ? -1.0 : 1.0);                     // nearest neighbouring row

    vec3 c0 = row_color(pos.x, row);
    vec3 c1 = row_color(pos.x, nrow);
    vec3 col = beam(c0, dy) + beam(c1, 1.0 - abs(dy));

    // aperture grille, one phosphor triad per 3 output pixels
    float phase = mod(floor(gl_FragCoord.x), 3.0);
    vec3 mask = vec3(MASK_DARK);
    if (phase < 1.0) mask.r = 1.0; else if (phase < 2.0) mask.g = 1.0; else mask.b = 1.0;
    col *= mask * BRIGHTNESS;

    o_color = vec4(pow(clamp(col, 0.0, 1.0), vec3(1.0 / GAMMA)), 1.0) * v_color;
}
