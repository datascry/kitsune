# harness/tests/test_morph_profiles — the unified morphing-profile registry + composer.
# Asserts a declared profile fans out to the coherent per-tool env the evaders consume.

from __future__ import annotations

from kitsune_harness.morph_profiles import REGISTRY, compose


def test_linux_desktop_composes_coherent_env() -> None:
    env = compose("linux-desktop")
    # the GPU layer: llvmpipe backend supplies the real 16384 caps under a coherent Mesa renderer string
    assert env["KS_LLVMPIPE"] == "1"
    assert env["GALLIUM_DRIVER"] == "llvmpipe"
    assert env["KS_OS"] == "linux"
    assert env["KS_WEBGL_VENDOR"] == "Mesa"
    assert "GeForce GTX 980" in env["KS_WEBGL_RENDERER"]
    assert env["KS_PROVISION"] == "1" and env["KS_HEADFUL"] == "1"


def test_registry_profiles_are_internally_coherent() -> None:
    # every profile's GPU caps must be the 16384 floor a real GPU exposes, and a native-OS profile needs no os-spoof
    for p in REGISTRY.values():
        assert p.gpu.caps == 16384, p.name
        assert p.os_target in {"linux", "windows", "macos", "ios"}, p.name
        # a profile whose target OS is the container's Linux host needs no kernel forge
        if p.os_target == "linux":
            assert p.os_spoof is None, p.name


def test_windows_firefox_composes_cross_os_proxy() -> None:
    env = compose("windows-firefox")
    assert env["KS_OS"] == "windows"
    assert "GTX 980" in env["KS_WEBGL_RENDERER"]
    # a cross-OS target forges the kernel via the os-spoof SOCKS proxy (camoufox reads KS_SOCKS)
    assert env["KS_SOCKS"] == "socks5://os-spoof-proxy:1080"


def test_cross_os_profiles_declare_a_kernel_forge() -> None:
    for p in REGISTRY.values():
        if p.os_target != "linux":  # a target != the Linux host must forge the kernel
            assert p.os_spoof is not None, p.name
