#!/bin/sh
# Compile shaders/crt.frag to SPIR-V and embed it as a C header for display.c.
# Needs glslang (https://github.com/KhronosGroup/glslang/releases); point
# GLSLANG at the binary if it isn't on PATH. The generated header is committed,
# so this is only needed after editing the shader.
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
GLSLANG=${GLSLANG:-glslang}
"$GLSLANG" -V --target-env vulkan1.0 --vn crt_frag_spv -o "$HERE/crt.frag.spv.h" "$HERE/crt.frag"
