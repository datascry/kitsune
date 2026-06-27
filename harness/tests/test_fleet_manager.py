# harness/tests/test_fleet_manager — the managed-fleet orchestration: ethics gate, retry, mixed, capture+grade.
# Docker + detector are injected (fake launcher / get_json) so the logic is covered without containers.

from __future__ import annotations

import json
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from kitsune_detector.ingest import group_signals
from kitsune_detector.models import Layer, Signal, Source

from kitsune_harness.allowlist import EthicsError
from kitsune_harness.coordination import FleetVerdict
from kitsune_harness.fleet_manager import (
    FleetPlan,
    NodeSpec,
    _binding,
    _node_label,
    _session_id,
    archetype_plan,
    campaign_from_obj,
    campaign_report_dict,
    evasion_node,
    homogeneous_plan,
    load_campaign,
    load_plan,
    plan_from_obj,
    render,
    render_campaign,
    report_dict,
    run_campaign,
    run_fleet,
)

_EXAMPLES = Path(__file__).resolve().parents[1] / "examples"

_WHEN = datetime(2026, 6, 27, 12, 0, 0, tzinfo=UTC)


def _session_json(sid: str, ja4: str, ip: str, fp: str, *, datacenter: bool = False) -> dict[str, Any]:
    sigs = [
        Signal(session_id=sid, layer=Layer.network, kind="ja4", value=ja4, source=Source.edge, observed_at=_WHEN),
        Signal(
            session_id=sid, layer=Layer.network, kind="observed_ip", value=ip, source=Source.edge, observed_at=_WHEN
        ),
        Signal(
            session_id=sid, layer=Layer.browser, kind="fp_hash", value=fp, source=Source.collector, observed_at=_WHEN
        ),
    ]
    if datacenter:  # an IP-reputation flag corroborates an fp-collision as a convicted fleet
        sigs.append(
            Signal(
                session_id=sid,
                layer=Layer.reputation,
                kind="asn_is_datacenter",
                value=True,
                source=Source.detector,
                observed_at=_WHEN,
            )
        )
    return group_signals(sigs)[0].model_dump(mode="json")


def _get_json(url: str) -> dict[str, Any]:
    sid = url.rsplit("/", 1)[-1]
    ipn = abs(hash(sid)) % 200 + 1
    return _session_json(sid, "t13d1516h2_aaaabbbbcccc", f"10.0.0.{ipn}", f"fp-{sid}")  # one JA4 → a cluster


class _FakeLauncher:
    """A Docker stand-in: returns a ``__KS__`` line (a minted session) unless the image is told to flake."""

    def __init__(self, *, never: tuple[str, ...] = (), fail_first: tuple[str, ...] = ()) -> None:
        self.never = set(never)
        self.fail_first = set(fail_first)
        self._lock = threading.Lock()
        self._n = 0
        self._per_image: dict[str, int] = {}

    def __call__(self, *, image: str, env: dict[str, str], network: str, proxy: str | None, timeout: float) -> str:
        with self._lock:
            self._n += 1
            n = self._n
            self._per_image[image] = self._per_image.get(image, 0) + 1
            first = self._per_image[image] == 1
        if image in self.never:
            return "booting…\nno session minted\n"
        if image in self.fail_first and first:
            return "Chrome failed to start: running as root without --no-sandbox\n"
        return "__KS__" + json.dumps({"session_id": f"sid{n}", "mode": "m"})


def test_ethics_gate_refuses_non_allowlisted_edge() -> None:
    plan = FleetPlan(nodes=[NodeSpec("kitsune-zendriver:latest")], edge="https://evil.example/")
    with pytest.raises(EthicsError):
        run_fleet(plan, launcher=_FakeLauncher(), get_json=_get_json)


def test_basic_fleet_captures_and_grades() -> None:
    plan = homogeneous_plan("kitsune-zendriver:latest", 3, max_concurrency=1)
    report = run_fleet(plan, launcher=_FakeLauncher(), get_json=_get_json)
    assert len(report.ok) == 3 and not report.failed
    assert report.verdict is not None and len(report.verdict.members) == 3  # graded as one cluster


def test_retry_heals_a_transient_sandbox_flake() -> None:
    # The node flakes once (the Chrome-sandbox error seen live) then succeeds — the manager re-runs it.
    plan = FleetPlan(nodes=[NodeSpec("kitsune-camoufox:latest")], retries=1, max_concurrency=1)
    report = run_fleet(plan, launcher=_FakeLauncher(fail_first=("kitsune-camoufox:latest",)), get_json=_get_json)
    assert report.ok and report.ok[0].attempts == 2 and report.ok[0].status == "ok"


def test_node_failing_all_attempts_is_reported_not_dropped() -> None:
    plan = FleetPlan(nodes=[NodeSpec("kitsune-broken:latest")], retries=1, max_concurrency=1)
    report = run_fleet(plan, launcher=_FakeLauncher(never=("kitsune-broken:latest",)), get_json=_get_json)
    assert not report.ok and len(report.failed) == 1
    assert report.failed[0].attempts == 2 and report.failed[0].error
    assert report.verdict is None  # <2 sessions → nothing to grade


def test_mixed_image_fleet() -> None:
    plan = FleetPlan(
        nodes=[NodeSpec("kitsune-camoufox:latest"), NodeSpec("kitsune-zendriver:latest", env={"KS_UACH": "1"})],
        max_concurrency=1,
    )
    report = run_fleet(plan, launcher=_FakeLauncher(), get_json=_get_json)
    images = {n.image for n in report.ok}
    assert images == {"kitsune-camoufox:latest", "kitsune-zendriver:latest"}  # heterogeneous fleet
    assert {n.label for n in report.nodes} == {"camoufox-0", "zendriver-1"}


def test_launch_exception_is_retried_then_reported() -> None:
    class _Boom:
        def __call__(self, **_kw: Any) -> str:
            raise RuntimeError("docker daemon down")

    plan = FleetPlan(nodes=[NodeSpec("kitsune-zendriver:latest")], retries=1, max_concurrency=1)
    report = run_fleet(plan, launcher=_Boom(), get_json=_get_json)
    assert report.failed[0].status == "failed" and "docker daemon down" in (report.failed[0].error or "")


def test_session_fetch_failure_demotes_the_node() -> None:
    def _bad_get(url: str) -> dict[str, Any]:
        raise OSError("detector unreachable")

    plan = FleetPlan(nodes=[NodeSpec("kitsune-zendriver:latest")], max_concurrency=1)
    report = run_fleet(plan, launcher=_FakeLauncher(), get_json=_bad_get)
    assert report.failed and "session fetch failed" in (report.failed[0].error or "")


def test_homogeneous_plan_round_robins_proxies() -> None:
    plan = homogeneous_plan("kitsune-zendriver:latest", 4, proxies=["socks5://p1", "socks5://p2"])
    assert [n.proxy for n in plan.nodes] == ["socks5://p1", "socks5://p2", "socks5://p1", "socks5://p2"]


def test_evasion_node_resolves_a_named_evasion() -> None:
    node = evasion_node("zendriver-uach")
    assert node.image == "kitsune-zendriver:latest" and node.env == {"KS_UACH": "1"} and node.label == "zendriver-uach"
    proxied = evasion_node("camoufox-linux", proxy="socks5://p", extra_env={"KS_REPEAT": "2"})
    assert proxied.proxy == "socks5://p" and proxied.env == {"KS_LINUX": "1", "KS_REPEAT": "2"}


def test_mixed_named_evasion_fleet_runs_and_labels() -> None:
    # Compose a fleet from the BAKED-IN ladder: a camoufox node + a zendriver node, by name.
    plan = FleetPlan(nodes=[evasion_node("camoufox-linux"), evasion_node("zendriver-uach")], max_concurrency=1)
    report = run_fleet(plan, launcher=_FakeLauncher(), get_json=_get_json)
    assert {n.label for n in report.ok} == {"camoufox-linux", "zendriver-uach"}
    assert {n.image for n in report.ok} == {"kitsune-camoufox:latest", "kitsune-zendriver:latest"}


def test_plan_from_obj_expands_replicas_and_overlays_env() -> None:
    plan = plan_from_obj(
        {
            "edge": "https://edge:8443/",
            "retries": 3,
            "nodes": [
                {"evasion": "camoufox-linux", "replicas": 2, "proxy": "socks5://p", "env": {"KS_REPEAT": 2}},
                {"image": "kitsune-pydoll:latest", "env": {"FOO": "bar"}},
            ],
        }
    )
    assert plan.retries == 3 and len(plan.nodes) == 3
    cam = [n for n in plan.nodes if n.label.startswith("camoufox-linux")]
    assert len(cam) == 2 and all(n.proxy == "socks5://p" for n in cam)
    assert cam[0].env == {"KS_LINUX": "1", "KS_REPEAT": "2"}  # evasion env + overlay, values coerced to str
    assert cam[0].label == "camoufox-linux-0" and cam[1].label == "camoufox-linux-1"
    img = next(n for n in plan.nodes if n.image == "kitsune-pydoll:latest")
    assert img.env == {"FOO": "bar"} and img.label == "pydoll-0"


def test_plan_node_task_becomes_ks_task_env() -> None:
    import json as _json

    plan = plan_from_obj(
        {
            "nodes": [
                {"evasion": "zendriver-uach", "task": "browse"},  # a preset name
                {"image": "kitsune-zendriver:latest", "task": [{"scroll": 400}, {"wait": 100}]},  # inline steps
            ]
        }
    )
    preset_node = plan.nodes[0]
    assert preset_node.env["KS_UACH"] == "1" and "KS_TASK" in preset_node.env
    assert any("scroll" in s for s in _json.loads(preset_node.env["KS_TASK"]))
    inline_node = plan.nodes[1]
    assert _json.loads(inline_node.env["KS_TASK"]) == [{"scroll": 400}, {"wait": 100}]


def test_plan_node_needs_exactly_one_of_evasion_or_image() -> None:
    with pytest.raises(ValueError, match="exactly one"):
        plan_from_obj({"nodes": [{"replicas": 2}]})  # neither
    with pytest.raises(ValueError, match="exactly one"):
        plan_from_obj({"nodes": [{"evasion": "vanilla", "image": "x"}]})  # both


def test_plan_requires_nodes() -> None:
    with pytest.raises(ValueError, match="non-empty 'nodes'"):
        plan_from_obj({"edge": "https://edge:8443/"})


def test_committed_examples_load_and_build() -> None:
    # Every shipped engagement/campaign template must parse into a runnable, allow-listed plan.
    import yaml

    for path in sorted(_EXAMPLES.glob("*.yaml")):
        obj = yaml.safe_load(path.read_text())
        if "waves" in obj:
            campaign = load_campaign(str(path))
            assert campaign.waves
            run_campaign(
                campaign,
                launcher=_FakeLauncher(),
                get_json=_get_json,
                scout_requester=lambda _u: (200, 1.0, "ok"),  # don't hit the network for a scout wave
                scout_sleep=lambda _s: None,
            )
        else:
            plan = load_plan(str(path))
            assert plan.nodes and plan.edge.startswith("https://edge")
            run_fleet(plan, launcher=_FakeLauncher(), get_json=_get_json)  # ethics gate passes + it executes


def _cloned_get(url: str) -> dict[str, Any]:
    # every node returns the SAME high-entropy fp on a DATACENTER IP → fp-collision + corroboration → `fleet`.
    sid = url.rsplit("/", 1)[-1]
    ipn = abs(hash(sid)) % 200 + 1
    return _session_json(sid, "t13d1516h2_cloned", f"10.0.0.{ipn}", "CLONED-FP", datacenter=True)


def test_report_caught_outcome_with_binding() -> None:
    plan = homogeneous_plan("kitsune-camoufox:latest", 3, max_concurrency=1)
    d = report_dict(run_fleet(plan, launcher=_FakeLauncher(), get_json=_cloned_get), name="acct-fraud")
    assert d["name"] == "acct-fraud" and d["outcome"] == "caught"
    assert d["coordination"]["label"] == "fleet" and d["coordination"]["binding"] == "fp_collision"
    assert "CAUGHT" in d["assessment"]
    assert d["fleet"] == {"requested": 3, "minted": 3, "failed": 0, "images": ["kitsune-camoufox:latest"]}
    assert all(n["status"] == "ok" for n in d["nodes"])


def test_distinct_builds_fleet_fragments_into_multiple_clusters() -> None:
    # The distinct-builds lever: nodes on DIFFERENT engines land in different JA4 prefixes → the fleet fragments
    # into >1 cluster. A Chrome sub-fleet (shared JA4 + cloned fp) is caught; a Firefox node sits in its own
    # cluster. The report surfaces the fragmentation and stays CAUGHT if any cluster convicts.
    def _mixed_get(url: str) -> dict[str, Any]:
        sid = url.rsplit("/", 1)[-1]
        ipn = abs(hash(sid)) % 200 + 1
        if "chrome" in sid:  # two Chrome nodes: same JA4 + same fp on datacenter → fp_collision → caught
            return _session_json(sid, "t13d1516h2_chrome", f"10.0.0.{ipn}", "CLONED", datacenter=True)
        return _session_json(sid, "t13d1717h2_firefox", f"10.0.1.{ipn}", f"ff-{sid}")  # distinct Firefox prefix

    plan = FleetPlan(
        nodes=[
            NodeSpec("kitsune-zendriver:latest", label="chrome-0"),
            NodeSpec("kitsune-zendriver:latest", label="chrome-1"),
            NodeSpec("kitsune-camoufox:latest", label="firefox-0"),
            NodeSpec("kitsune-camoufox:latest", label="firefox-1"),
        ],
        max_concurrency=1,
    )

    class _LabelLauncher:
        def __init__(self) -> None:
            self.n = 0

        def __call__(self, *, image: str, env: dict[str, str], network: str, proxy: str | None, timeout: float) -> str:
            self.n += 1  # unique sid per call; engine tag drives the JA4/fp shape in _mixed_get
            tag = "chrome" if "zendriver" in image else "firefox"
            return "__KS__" + json.dumps({"session_id": f"{tag}-{self.n}"})

    report = run_fleet(plan, launcher=_LabelLauncher(), get_json=_mixed_get)
    d = report_dict(report)
    assert d["fragmented"] is True and len(d["clusters"]) >= 2  # the JA4 prefix no longer binds the whole fleet
    assert d["outcome"] == "caught"  # but the same-engine Chrome sub-fleet still fp-collides
    labels = {c["label"] for c in d["clusters"]}
    assert "fleet" in labels and "candidate" in labels  # Chrome caught, Firefox evaded — partial evasion


def test_report_evaded_outcome() -> None:
    # distinct fps on residential IPs → shared JA4 but no convicting binding → `candidate` = the fleet EVADED.
    plan = homogeneous_plan("kitsune-zendriver:latest", 3, max_concurrency=1)
    d = report_dict(run_fleet(plan, launcher=_FakeLauncher(), get_json=_get_json))
    assert d["outcome"] == "evaded" and d["coordination"]["label"] != "fleet"
    assert d["coordination"]["binding"] is None and "EVADED" in d["assessment"]


def test_binding_names_each_signal() -> None:
    base = dict(ja4="x", members=["a", "b"], diverged_traits={}, score=0.7, label="fleet")
    assert _binding(FleetVerdict(**base, cloned_fingerprint="fp")) == "fp_collision"
    assert _binding(FleetVerdict(**base, cloned_trace="t")) == "trace_collision"
    assert _binding(FleetVerdict(**base, shared_ticket="tk")) == "ticket_reuse"
    assert _binding(FleetVerdict(**base, template_radius=0.05)) == "template_similarity"
    assert _binding(FleetVerdict(**base)) is None


def test_report_inconclusive_and_proxy_recorded() -> None:
    plan = FleetPlan(nodes=[NodeSpec("kitsune-zendriver:latest", proxy="socks5://p")], max_concurrency=1)
    d = report_dict(run_fleet(plan, launcher=_FakeLauncher(), get_json=_get_json))
    assert d["outcome"] == "inconclusive" and d["coordination"] is None  # 1 session → no cluster
    assert d["nodes"][0]["proxy"] == "socks5://p"  # egress recorded as engagement evidence


def test_archetype_plan_builds_a_runnable_fleet() -> None:
    plan = archetype_plan("credential-stuffer", detector="http://localhost:8099")
    assert plan.detector == "http://localhost:8099" and len(plan.nodes) == 3
    # cloned-fp persona: a deterministic Chromium tool (zendriver) + the form-fill task
    assert all(n.image == "kitsune-zendriver:latest" and "KS_TASK" in n.env for n in plan.nodes)
    report = run_fleet(plan, launcher=_FakeLauncher(), get_json=_cloned_get)
    assert report.verdict is not None and report.verdict.label == "fleet"  # cloned persona → caught


def test_archetype_sybil_farmer_is_diverse() -> None:
    plan = archetype_plan("sybil-farmer")
    # diversity is per-launch fp RANDOMIZATION (camoufox), not a Chromium mix (which would collide → caught)
    assert all(n.image == "kitsune-camoufox:latest" for n in plan.nodes) and len(plan.nodes) == 3


def test_campaign_from_obj_inherits_globals_and_names_waves() -> None:
    campaign = campaign_from_obj(
        {
            "name": "atk",
            "edge": "https://edge:8443/",
            "retries": 2,
            "waves": [
                {"name": "recon", "nodes": [{"evasion": "vanilla", "replicas": 1}]},
                {"nodes": [{"evasion": "camoufox-hardened", "replicas": 3}]},  # unnamed → wave-1
            ],
        }
    )
    assert campaign.name == "atk" and [w.name for w in campaign.waves] == ["recon", "wave-1"]
    assert all(w.plan.retries == 2 for w in campaign.waves)  # campaign globals inherited
    assert len(campaign.waves[1].plan.nodes) == 3


def test_campaign_needs_waves() -> None:
    with pytest.raises(ValueError, match="non-empty 'waves'"):
        campaign_from_obj({"name": "x"})


def test_run_campaign_grades_each_wave_and_aggregates() -> None:
    campaign = campaign_from_obj(
        {
            "waves": [
                {"name": "recon", "nodes": [{"evasion": "vanilla", "replicas": 1}]},  # 1 node → inconclusive
                {"name": "fraud", "nodes": [{"image": "kitsune-camoufox:latest", "replicas": 3}]},  # cloned → caught
            ],
            "max_concurrency": 1,
        }
    )
    result = run_campaign(campaign, launcher=_FakeLauncher(), get_json=_cloned_get)
    d = campaign_report_dict(result)
    assert d["waves_caught"] == ["fraud"] and "recon" not in d["waves_caught"]
    assert "CAUGHT 1/2" in d["assessment"]
    assert d["waves"][0]["outcome"] == "inconclusive" and d["waves"][1]["outcome"] == "caught"
    assert "Campaign" in render_campaign(result)


def test_campaign_with_rps_recon_wave() -> None:
    # The recon phase literally includes RPS scoping: a scout wave (no fleet) + a fleet attack wave.
    campaign = campaign_from_obj(
        {
            "waves": [
                {"name": "recon-rps", "scout": "http://detector:8080/arena/rate?level=hard", "rates": [1, 2, 5]},
                {"name": "attack", "nodes": [{"image": "kitsune-camoufox:latest", "replicas": 3}]},
            ],
            "max_concurrency": 1,
        }
    )

    def throttling(_url: str) -> tuple[int, float, str]:
        with _lock:
            _seen["n"] += 1
            n = _seen["n"]
        return (429, 2.0, "") if n > 4 else (200, 2.0, "ok")

    _seen = {"n": 0}
    import threading as _t

    _lock = _t.Lock()
    result = run_campaign(
        campaign,
        launcher=_FakeLauncher(),
        get_json=_cloned_get,
        scout_requester=throttling,
        scout_sleep=lambda _s: None,
    )
    d = campaign_report_dict(result)
    recon = d["waves"][0]
    assert recon["kind"] == "rps-scope" and recon["rps"]["knee"] == "throttled"
    assert d["waves_caught"] == ["attack"] and "1/1 fleet wave" in d["assessment"]  # only the FLEET wave counts
    assert "RPS-SCOPE" in render_campaign(result)


def test_campaign_all_waves_evaded_assessment() -> None:
    campaign = campaign_from_obj(
        {"waves": [{"name": "w", "nodes": [{"evasion": "zendriver-uach", "replicas": 3}]}], "max_concurrency": 1}
    )
    d = campaign_report_dict(run_campaign(campaign, launcher=_FakeLauncher(), get_json=_get_json))
    assert d["waves_caught"] == [] and "EVADED" in d["assessment"]


def test_campaign_no_gradeable_cluster_assessment() -> None:
    campaign = campaign_from_obj({"waves": [{"name": "solo", "nodes": [{"evasion": "vanilla", "replicas": 1}]}]})
    result = run_campaign(campaign, launcher=_FakeLauncher(), get_json=_get_json)
    d = campaign_report_dict(result)
    assert d["waves_caught"] == [] and d["waves_evaded"] == [] and "no fleet wave" in d["assessment"]
    assert "no cluster" in render_campaign(result)  # the render no-coordination branch


def test_node_label_default_and_explicit() -> None:
    assert _node_label(NodeSpec("registry.io/kitsune-camoufox:latest"), 2) == "camoufox-2"
    assert _node_label(NodeSpec("x", label="lead"), 0) == "lead"


def test_session_id_parsing_edge_cases() -> None:
    assert _session_id("__KS__" + json.dumps({"session_id": "abc"})) == "abc"
    assert _session_id("no marker here") is None
    assert _session_id("__KS__{not json}") is None
    assert _session_id("__KS__[1,2]") is None  # valid json but not an object → no .get
    assert _session_id("__KS__" + json.dumps({"mode": "m"})) is None  # no session_id key


def test_render_with_and_without_verdict() -> None:
    plan = homogeneous_plan("kitsune-zendriver:latest", 2, max_concurrency=1)
    out = render(run_fleet(plan, launcher=_FakeLauncher(), get_json=_get_json))
    assert "2/2 nodes minted a session" in out and "Coordination" in out

    one = render(
        run_fleet(FleetPlan(nodes=[NodeSpec("kitsune-zendriver:latest")]), launcher=_FakeLauncher(), get_json=_get_json)
    )
    assert "no coordination cluster" in one

    flaked = render(
        run_fleet(
            FleetPlan(nodes=[NodeSpec("kitsune-broken:latest")]),
            launcher=_FakeLauncher(never=("kitsune-broken:latest",)),
            get_json=_get_json,
        )
    )
    assert "❌" in flaked
