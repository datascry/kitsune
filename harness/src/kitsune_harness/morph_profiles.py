# harness/kitsune_harness/morph_profiles — the unified cross-layer morphing-profile registry + composer.
# One declared identity pins every layer coherently; compose() fans it out to the per-tool env the evaders consume.

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Gpu:
    """The GPU layer: the renderer STRING (engine-level, camoufox) + the CAPS it must cohere with (llvmpipe backend)."""

    vendor: str
    renderer: str
    caps: int  # MAX_TEXTURE_SIZE the renderer's real GPU exposes (16384 for modern); the backend must ALLOCATE it
    backend: str  # the GL backend that supplies+allocates the caps in software — "llvmpipe"


@dataclass(frozen=True)
class MorphProfile:
    """A coherent identity across ALL layers — the executable form of docs/coherent-stack.md's per-layer table.

    Coherence invariant: every field tells one OS story. Running the composed profile must yield ZERO incoherence
    tells across the layers it declares (the detector is the oracle).
    """

    name: str
    os_target: str  # linux | windows | macos | ios — the OS every layer must agree on
    browser: str  # camoufox (engine-level) | stealth (chromium)
    os_spoof: str | None  # os-spoof KS_PROFILE name for the kernel/TLS layer, or None when the host OS matches natively
    mobile: bool
    touch: bool
    gpu: Gpu
    provision: bool  # KS_PROVISION — real audio/voices/webrtc floor
    humanize: bool  # KS_REAL_INPUT — genuine XTEST input (real coalesced batches)


# The registry. Seeded with the Linux-desktop identity — FULLY coherent in-sandbox (grounded 2026-07-05): the host
# IS Linux so the kernel/TLS are native (no os-spoof needed), and llvmpipe supplies a real 16384 GPU cap under a
# coherent Mesa renderer string. Cross-OS profiles (ios-safari, windows-chrome) compose os-spoof for the kernel/TLS.
REGISTRY: dict[str, MorphProfile] = {
    "linux-desktop": MorphProfile(
        name="linux-desktop",
        os_target="linux",
        browser="camoufox",
        os_spoof=None,
        mobile=False,
        touch=False,
        gpu=Gpu(vendor="Mesa", renderer="GeForce GTX 980, or similar", caps=16384, backend="llvmpipe"),
        provision=True,
        humanize=False,
    ),
    # A CROSS-OS identity: the host is Linux, so the kernel/TLS are forged to Windows by os-spoof (windows-firefox —
    # the engine matches camoufox's Firefox), while camoufox supplies the Windows UA + a coherent Windows NVIDIA GPU
    # @ 16384 (llvmpipe). One Windows story across kernel + TLS + UA + GPU.
    "windows-firefox": MorphProfile(
        name="windows-firefox",
        os_target="windows",
        browser="camoufox",
        os_spoof="windows-firefox",
        mobile=False,
        touch=False,
        gpu=Gpu(
            vendor="Google Inc. (NVIDIA)",
            renderer="ANGLE (NVIDIA, NVIDIA GeForce GTX 980 Direct3D11 vs_5_0 ps_5_0), or similar",
            caps=16384,
            backend="llvmpipe",
        ),
        provision=True,
        humanize=False,
    ),
}


# The container name the validator gives the os-spoof SOCKS5 proxy (so composed browser env can reach it).
OS_SPOOF_HOST = "os-spoof-proxy"


def compose(name: str) -> dict[str, str]:
    """Fan a profile out to the browser-container env the evaders consume (os-spoof proxy wiring is the validator's).

    Returns the env dict for the camoufox/stealth container: the GPU caps (llvmpipe), the OS + renderer that make the
    morph coherent, and the provisioning/behaviour floors.
    """
    p = REGISTRY[name]
    env: dict[str, str] = {"KS_HEADFUL": "1"}
    if p.provision:
        env["KS_PROVISION"] = "1"
    if p.humanize:
        env["KS_REAL_INPUT"] = "1"
    if p.gpu.backend == "llvmpipe":
        env["KS_LLVMPIPE"] = "1"
        env["GALLIUM_DRIVER"] = "llvmpipe"
        env["LIBGL_ALWAYS_SOFTWARE"] = "1"
        env["KS_OS"] = p.os_target
        env["KS_WEBGL_VENDOR"] = p.gpu.vendor
        env["KS_WEBGL_RENDERER"] = p.gpu.renderer
    if p.os_spoof is not None:
        # Route the browser through the os-spoof SOCKS5 proxy so the TCP SYN kernel is forged to the target OS. The
        # validator launches os-spoof with KS_PROFILE=<p.os_spoof>. camoufox reads SOCKS via KS_SOCKS (routes WebRTC
        # too, ice.proxy_only); stealth reads KS_PROXY.
        proxy = f"socks5://{OS_SPOOF_HOST}:1080"
        env["KS_SOCKS" if p.browser == "camoufox" else "KS_PROXY"] = proxy
    return env
