# harness/kitsune_harness/morph_validate — the full-stack morphing-profile validator.
# Composes + runs a profile end-to-end and asserts ZERO tells across the coherence layers it declares.

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass

from .morph_profiles import REGISTRY, compose

# Each detector tell mapped to the morph LAYER it belongs to. The COHERENCE layers must be silent for a pass — a
# firing one is a cross-layer disagreement (a registry/composer bug). The OTHER layers are noted, not coherence fails:
# provision/behaviour are tuning knobs, runtime is headful+patchright territory, robustness is os-spoof's stack.
COHERENCE_LAYERS: dict[str, tuple[str, ...]] = {
    "kernel": ("net.tcp_os_vs_ua", "net.tcp_syn_anomaly", "net.tcp_static_window", "net.tls_os_vs_tcp_os"),
    "tls": ("net.tls_grease_vs_ua", "net.tls_vs_ua_browser", "net.tls_pq_keyshare_vs_ua", "net.h2_unknown_vs_ua"),
    "ua_ch": ("net.ch_ua_mobile_no_model", "net.ch_ua_version_vs_ua", "br.mobile_no_js_model", "br.ch_he_headless"),
    "device": (
        "br.ios_screen_oversized",
        "br.ios_dpr_incoherent",
        "br.macos_dpr1",
        "br.navplatform_vs_ua",
        "br.mobile_cores_high",
    ),
    "gpu_string": (
        "br.webgl_software",
        "br.mobile_gpu_not_mobile",
        "br.webgl_renderer_artifact",
        "br.canvas_lie",
        "br.webgl_getparameter_tampered",
        "br.webgl_worker_vs_main",
        "br.webgpu_webgl_vs",
    ),
    "gpu_caps": (
        "br.webgl_renderer_caps_mismatch",
        "br.webgl_maxtexture_unallocatable",
        "br.mobile_gpu_caps_mismatch",
        "br.webgl_caps_worker_vs_main",
    ),
}
OTHER_LAYERS: dict[str, tuple[str, ...]] = {
    "provision": ("br.voices_empty", "br.media_devices_empty", "br.webrtc_unavailable"),
    "behaviour": (
        "bh.synthetic_no_coalesced",
        "bh.power_law_violation",
        "br.input_entropy_floor",
        "br.pointer_touch_incoherent",
    ),
    "runtime": (
        "br.automation_globals",
        "br.webdriver_present",
        "br.cdp_runtime_enabled",
        "br.no_chrome_object",
        "br.permissions_anomaly",
        "br.webdriver_getter_tampered",
    ),
    "robustness": ("net.no_js_execution",),
}
_TELL_TO_LAYER: dict[str, str] = {
    t: layer for group in (COHERENCE_LAYERS, OTHER_LAYERS) for layer, ts in group.items() for t in ts
}


def classify(tells: list[str]) -> dict[str, list[str]]:
    """Bucket fired tells by morph layer; unmapped tells land in 'other'."""
    out: dict[str, list[str]] = {}
    for t in tells:
        out.setdefault(_TELL_TO_LAYER.get(t, "other"), []).append(t)
    return out


@dataclass(frozen=True)
class Assessment:
    profile: str
    label: str
    by_layer: dict[str, list[str]]  # layer -> firing tells
    coherent: bool  # True iff NO coherence-layer tell fired


def assess(profile: str, label: str, tells: list[str]) -> Assessment:
    """Pure: given a run's label + fired tells, report per-layer status + whether every COHERENCE layer is silent."""
    by_layer = classify(tells)
    coherent = not any(layer in by_layer for layer in COHERENCE_LAYERS)
    return Assessment(profile=profile, label=label, by_layer=by_layer, coherent=coherent)


def _run_profile(
    name: str, detector: str = "http://detector:8080", edge: str = "https://edge:8443/"
) -> tuple[str, list[str]]:  # pragma: no cover - docker IO
    """Compose + run a profile end-to-end (os-spoof proxy if declared + the browser), returning (label, tells)."""
    p = REGISTRY[name]
    env = compose(name)
    image = {"camoufox": "kitsune-camoufox:latest", "stealth": "kitsune-stealth:latest"}[p.browser]
    if p.os_spoof is not None:
        subprocess.run(["docker", "rm", "-f", "os-spoof-proxy"], capture_output=True, check=False)
        subprocess.run(
            [
                "docker",
                "run",
                "-d",
                "--name",
                "os-spoof-proxy",
                "--network",
                "kitsune_default",
                "--cap-add",
                "NET_RAW",
                "--cap-add",
                "NET_ADMIN",
                "-e",
                "KS_MODE=proxy",
                "-e",
                f"KS_PROFILE={p.os_spoof}",
                "kitsune-os-spoof:latest",
            ],
            capture_output=True,
            check=True,
        )
    try:
        args = [
            "docker",
            "run",
            "--rm",
            "--network",
            "kitsune_default",
            "-e",
            f"KITSUNE_DETECTOR={detector}",
            "-e",
            f"KITSUNE_EDGE={edge}",
        ]
        for k, v in env.items():
            args += ["-e", f"{k}={v}"]
        args.append(image)
        out = subprocess.run(args, capture_output=True, text=True, timeout=300, check=False).stdout
    finally:
        if p.os_spoof is not None:
            subprocess.run(["docker", "rm", "-f", "os-spoof-proxy"], capture_output=True, check=False)
    line = next((ln for ln in out.splitlines() if ln.startswith("__KS__")), None)
    if line is None:
        return "ERROR", ["harness.no_verdict"]
    v = json.loads(line[len("__KS__") :])
    return str(v.get("label", "?")), sorted(c["rule_id"] for c in v.get("contradictions", []))


def main() -> None:  # pragma: no cover - CLI over docker IO
    for name in REGISTRY:
        label, tells = _run_profile(name)
        a = assess(name, label, tells)
        mark = "COHERENT" if a.coherent else "INCOHERENT"
        print(f"\n=== {name}: label={label} · {mark} ===")
        for layer in (*COHERENCE_LAYERS, *OTHER_LAYERS, "other"):
            fired = a.by_layer.get(layer)
            tag = "coherence" if layer in COHERENCE_LAYERS else "note"
            print(f"  {layer:11} [{tag:9}] -> {'FIRING ' + ','.join(fired) if fired else 'silent'}")


if __name__ == "__main__":  # pragma: no cover
    main()
