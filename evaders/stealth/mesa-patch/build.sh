#!/bin/sh
# evaders/stealth/mesa-patch/build — build a patched Mesa llvmpipe that env-overrides the GL renderer/vendor strings.
# Clones Mesa 23.2.1, patches lp_screen.c to honor KS_GL_RENDERER/KS_GL_VENDOR, stamps the base image's exact Mesa
# version (so libGL's DRI version check accepts the driver), builds swrast_dri.so. Run in ubuntu:22.04 (jammy glibc
# + LLVM 15 match). Grounded 2026-07-06: the driver flips Chromium/ANGLE's WebGL renderer to a hardware GPU natively
# (no JS spoof) -> br.webgl_software + caps/tamper/worker all silent. NB the MESA_VER must equal the stealth base
# image's `dpkg -l libgl1-mesa-dri` version, or libGL rejects the driver ("not from this Mesa build").
set -e
export DEBIAN_FRONTEND=noninteractive
MESA_VER="23.2.1-1ubuntu3.1~22.04.3"   # must match mcr.microsoft.com/playwright:v1.52.0-jammy's Mesa package
echo "=== installing build deps ==="
apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq git build-essential ninja-build pkg-config python3-pip python3-mako \
  llvm-15-dev libclang-15-dev clang-15 libelf-dev bison flex libdrm-dev libzstd-dev zlib1g-dev libexpat1-dev \
  libx11-dev libxext-dev libxdamage-dev libxfixes-dev libx11-xcb-dev libxcb1-dev libxcb-glx0-dev \
  libxcb-dri2-0-dev libxcb-dri3-dev libxcb-present-dev libxcb-sync-dev libxcb-shm0-dev libxcb-xfixes0-dev \
  libxcb-randr0-dev libxcb-render0-dev libxcb-shape0-dev libxshmfence-dev libxxf86vm-dev libxrandr-dev \
  libwayland-dev wayland-protocols libwayland-egl-backend-dev >/dev/null 2>&1
pip3 install -q "meson>=1.1" >/dev/null 2>&1
cd /work
[ -d mesa ] || git clone --branch mesa-23.2.1 --depth 1 https://gitlab.freedesktop.org/mesa/mesa.git 2>&1 | tail -1
cd mesa
if ! grep -q "KS_GL" src/gallium/drivers/llvmpipe/lp_screen.c; then
python3 - <<'PY'
import re
f = "src/gallium/drivers/llvmpipe/lp_screen.c"
s = open(f).read()
def inj(src, fn, env):
    pat = re.compile(r"(\b" + fn + r"\s*\([^)]*\)\s*\{)")
    return pat.sub(r'\1\n   { const char *_ks = getenv("' + env + r'"); if (_ks) return _ks; }', src, count=1)
s = inj(s, "llvmpipe_get_name", "KS_GL_RENDERER")
s = inj(s, "llvmpipe_get_vendor", "KS_GL_VENDOR")
open(f, "w").write(s)
PY
fi
echo "$MESA_VER" > VERSION   # stamp the base image's version so libGL's DRI version check accepts the driver
rm -rf .git build           # drop git so the build appends no "(git-sha)" suffix
meson setup build -Dgallium-drivers=swrast -Dvulkan-drivers= -Dglx=dri -Degl=enabled -Dgbm=enabled \
  -Dplatforms=x11 -Dllvm=enabled -Dshared-llvm=enabled -Dbuildtype=release \
  -Dgallium-va=disabled -Dgallium-vdpau=disabled -Dvideo-codecs= 2>&1 | tail -3
ninja -C build 2>&1 | tail -4
SO=$(find build -name "swrast_dri.so" | head -1)
[ -n "$SO" ] && cp "$SO" /work/swrast_dri.so && echo "BUILD_DONE size=$(stat -c%s /work/swrast_dri.so)" || echo "BUILD_FAILED"
