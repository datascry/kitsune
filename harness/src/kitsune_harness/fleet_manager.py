# harness/fleet_manager — orchestrate a managed fleet of REAL evader-browser workers (camoufox/zendriver/…).
# The stateful, self-healing layer over fleet_capture.sh: mixed images, per-node proxy, retry, capture + grade.

"""A managed fleet runner for real adversary-emulation.

``fleet_capture.sh`` launches N copies of ONE evader image and drops any node that flakes. This is the
orchestrated upgrade the engagement use-case wants: a declarative :class:`FleetPlan` of heterogeneous nodes
(mix camoufox + zendriver + …), each with its own env + proxy, launched concurrently with **per-node retry**
(so a transient Chrome-sandbox flake re-runs instead of silently shrinking the fleet), then every minted session
is pulled from the detector and graded as one coordination cluster.

Ethics: this drives REAL browsers, so the target is checked against the harness allow-list FIRST
(:func:`~kitsune_harness.allowlist.assert_allowed`) — it points only at Kitsune's own edge/detector/arena or the
approved test endpoints, and refuses anything else. It is adversary-emulation for testing our OWN coordination
defenses (the red half of the lab), authorization-scoped in code — not a scraping/attack botnet.

The real Docker launch and the detector HTTP fetch are injected (``launcher`` / ``get_json``) so the orchestration
logic — retry, concurrency, health accounting, grading — is unit-tested without Docker or a live detector.
"""

from __future__ import annotations

import concurrent.futures
import json
import subprocess
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from kitsune_detector.models import Session

from .allowlist import assert_allowed
from .archetypes import all_archetypes
from .archetypes import get as get_archetype
from .coordination import FleetVerdict, score_corpus
from .evasions import families
from .evasions import get as get_evasion
from .tasks import get_preset, task_from_obj


@dataclass(frozen=True)
class NodeSpec:
    """One fleet node: which evader image, its env knobs (KS_UACH/KS_LINUX/…), and an optional egress proxy."""

    image: str
    env: dict[str, str] = field(default_factory=dict)
    proxy: str | None = None
    label: str = ""  # display label; defaults to a short image-derived name


@dataclass(frozen=True)
class FleetPlan:
    """A declarative fleet: heterogeneous nodes + the (allow-listed) targets and run policy."""

    nodes: list[NodeSpec]
    edge: str = "https://edge:8443/"  # worker target (KITSUNE_EDGE) — network-internal hostname
    detector: str = "http://detector:8080"  # where the MANAGER fetches /session — host port when run off-network
    worker_detector: str = "http://detector:8080"  # KITSUNE_DETECTOR given to workers — always the network name
    network: str = "kitsune_default"
    retries: int = 1  # extra attempts per node on a transient failure (the Chrome-sandbox flake)
    timeout: float = 120.0
    max_concurrency: int = 8


@dataclass
class NodeResult:
    """The outcome for one node: did it mint a session, after how many attempts, else why not."""

    label: str
    image: str
    status: str  # "ok" | "failed"
    session_id: str | None = None
    attempts: int = 0
    error: str | None = None
    proxy: str | None = None  # the egress proxy this node ran behind (engagement evidence), if any


@dataclass
class FleetReport:
    nodes: list[NodeResult]
    verdict: FleetVerdict | None  # the graded coordination cluster over the nodes that minted a session

    @property
    def ok(self) -> list[NodeResult]:
        return [n for n in self.nodes if n.status == "ok"]

    @property
    def failed(self) -> list[NodeResult]:
        return [n for n in self.nodes if n.status != "ok"]


class Launcher(Protocol):
    """Runs one evader container to completion and returns its stdout (which carries the ``__KS__`` marker)."""

    def __call__(self, *, image: str, env: dict[str, str], network: str, proxy: str | None, timeout: float) -> str: ...


JsonGetter = Callable[[str], Any]


def _docker_launch(  # pragma: no cover - real Docker I/O
    *, image: str, env: dict[str, str], network: str, proxy: str | None, timeout: float
) -> str:
    """Real launcher: ``docker run --rm --network <net> -e …  <image>``."""
    args = ["docker", "run", "--rm", "--network", network]
    for key, value in env.items():
        args += ["-e", f"{key}={value}"]
    if proxy:
        args += ["-e", f"KS_PROXY={proxy}"]
    args.append(image)
    done = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
    return done.stdout


def _http_get_json(url: str) -> Any:  # pragma: no cover - thin network shim
    with urllib.request.urlopen(url, timeout=10) as resp:
        return json.loads(resp.read())


def _session_id(stdout: str) -> str | None:
    """Extract the ``ks_sid`` a worker reports via its ``__KS__{…}`` line, or None if it never minted one."""
    for line in stdout.splitlines():
        if line.startswith("__KS__"):
            try:
                sid = json.loads(line[len("__KS__") :]).get("session_id")
            except (json.JSONDecodeError, AttributeError):
                return None
            return str(sid) if sid else None
    return None


def _node_label(spec: NodeSpec, index: int) -> str:
    if spec.label:
        return spec.label
    base = spec.image.split(":")[0].rsplit("/", 1)[-1].removeprefix("kitsune-")
    return f"{base}-{index}"


def _launch_node(spec: NodeSpec, plan: FleetPlan, launcher: Launcher, label: str) -> NodeResult:
    """Run one node, RE-RUNNING up to ``plan.retries`` times on a transient failure (no session / launch error)."""
    env = {"KITSUNE_EDGE": plan.edge, "KITSUNE_DETECTOR": plan.worker_detector, **spec.env}
    last_err = "no __KS__ session marker (worker minted no session)"
    for attempt in range(1, plan.retries + 2):
        try:
            out = launcher(image=spec.image, env=env, network=plan.network, proxy=spec.proxy, timeout=plan.timeout)
        except Exception as exc:
            last_err = f"launch error: {exc}"
            continue
        sid = _session_id(out)
        if sid:
            return NodeResult(label, spec.image, "ok", sid, attempt, proxy=spec.proxy)
    return NodeResult(label, spec.image, "failed", None, plan.retries + 1, last_err, proxy=spec.proxy)


def run_fleet(
    plan: FleetPlan, *, launcher: Launcher = _docker_launch, get_json: JsonGetter = _http_get_json
) -> FleetReport:
    """Launch the plan's nodes concurrently (with per-node retry), capture each minted session, and grade the
    cluster. The allow-list check runs FIRST and raises ``EthicsError`` before any browser is launched."""
    assert_allowed(plan.edge)  # ETHICS GATE — refuses a non-allow-listed target before anything runs
    labels = [_node_label(spec, i) for i, spec in enumerate(plan.nodes)]
    by_index: dict[int, NodeResult] = {}
    workers = min(plan.max_concurrency, len(plan.nodes)) or 1
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_launch_node, spec, plan, launcher, labels[i]): i for i, spec in enumerate(plan.nodes)}
        for future in concurrent.futures.as_completed(futures):
            by_index[futures[future]] = future.result()
    results = [by_index[i] for i in range(len(plan.nodes))]

    corpus: list[tuple[str, Session]] = []
    for result in results:
        if result.status == "ok" and result.session_id:
            try:
                session = Session.model_validate(get_json(f"{plan.detector.rstrip('/')}/session/{result.session_id}"))
            except Exception as exc:
                result.status = "failed"
                result.error = f"session fetch failed: {exc}"
                continue
            corpus.append((result.label, session))
    verdict = score_corpus(corpus)[0] if len(corpus) >= 2 else None
    return FleetReport(nodes=results, verdict=verdict)


def homogeneous_plan(
    image: str, n: int, *, env: dict[str, str] | None = None, proxies: list[str] | None = None, **kw: Any
) -> FleetPlan:
    """N identical nodes (one image) — the fleet_capture.sh shape, with per-node proxy round-robin if given."""
    proxies = proxies or []
    nodes = [
        NodeSpec(image=image, env=dict(env or {}), proxy=(proxies[i % len(proxies)] if proxies else None))
        for i in range(n)
    ]
    return FleetPlan(nodes=nodes, **kw)


def evasion_node(
    name: str, *, proxy: str | None = None, label: str | None = None, extra_env: dict[str, str] | None = None
) -> NodeSpec:
    """A :class:`NodeSpec` for a NAMED evasion from the registry (e.g. ``camoufox-linux``) — the baked-in form,
    so a fleet is composed from the existing red-team ladder, not raw image+env. ``extra_env`` overlays the
    evasion's env (e.g. a per-node KS_PROXY); ``label`` defaults to the evasion name."""
    ev = get_evasion(name)
    return NodeSpec(image=ev.image, env=ev.env_with(extra_env), proxy=proxy, label=label or name)


def _image_base(image: str) -> str:
    return image.split(":")[0].rsplit("/", 1)[-1].removeprefix("kitsune-")


def plan_from_obj(obj: Mapping[str, Any]) -> FleetPlan:
    """Build a :class:`FleetPlan` from a declarative engagement spec (a parsed YAML/JSON mapping). Each entry in
    ``nodes`` is ``{evasion|image, replicas?, proxy?, env?}``; ``replicas`` expands to that many labelled nodes.
    A version-controllable, shareable engagement: the reusable form for education + authorized engagements."""
    raw = obj.get("nodes")
    if not isinstance(raw, list) or not raw:
        raise ValueError("fleet plan needs a non-empty 'nodes' list")
    nodes: list[NodeSpec] = []
    for entry in raw:
        evasion, image = entry.get("evasion"), entry.get("image")
        if bool(evasion) == bool(image):
            raise ValueError(f"node {entry!r} needs exactly one of 'evasion' or 'image'")
        replicas = int(entry.get("replicas", 1))
        proxy = entry.get("proxy")
        extra_env = {str(k): str(v) for k, v in (entry.get("env") or {}).items()}
        if entry.get("task") is not None:  # a behavioral script the worker replays via CDP (KS_TASK)
            extra_env["KS_TASK"] = task_from_obj(entry["task"]).to_env()
        base_label = evasion if evasion else _image_base(str(image))
        for rep in range(replicas):
            label = f"{base_label}-{rep}"
            if evasion:
                spec = evasion_node(str(evasion), proxy=proxy, label=label, extra_env=extra_env)
            else:
                spec = NodeSpec(image=str(image), env=extra_env, proxy=proxy, label=label)
            nodes.append(spec)
    defaults = FleetPlan(nodes=[])
    return FleetPlan(
        nodes=nodes,
        edge=str(obj.get("edge", defaults.edge)),
        detector=str(obj.get("detector", defaults.detector)),
        worker_detector=str(obj.get("worker_detector", defaults.worker_detector)),
        network=str(obj.get("network", defaults.network)),
        retries=int(obj.get("retries", defaults.retries)),
        timeout=float(obj.get("timeout", defaults.timeout)),
        max_concurrency=int(obj.get("max_concurrency", defaults.max_concurrency)),
    )


def load_plan(path: str) -> FleetPlan:
    """Load an engagement plan from a YAML or JSON file (YAML is a JSON superset, so one parser covers both)."""
    import yaml

    return plan_from_obj(yaml.safe_load(Path(path).read_text()))


def archetype_plan(name: str, **overrides: Any) -> FleetPlan:
    """Build a :class:`FleetPlan` from a named adversary archetype (e.g. ``credential-stuffer``) — the persona's
    fleet shape (evasions + replicas + behavioral task) resolved into a runnable plan."""
    return plan_from_obj(get_archetype(name).to_plan_obj(**overrides))


def render(report: FleetReport) -> str:
    """Markdown: per-node health (with retries) + the graded coordination verdict."""
    lines = [f"# Fleet — {len(report.ok)}/{len(report.nodes)} nodes minted a session", ""]
    for n in report.nodes:
        if n.status == "ok":
            retry = f" (after {n.attempts} attempts)" if n.attempts > 1 else ""
            lines.append(f"- ✅ `{n.label}` [{n.image}] → session `{n.session_id}`{retry}")
        else:
            lines.append(f"- ❌ `{n.label}` [{n.image}] → {n.error}")
    lines.append("")
    v = report.verdict
    if v is None:
        lines.append("_fewer than 2 sessions captured — no coordination cluster to grade_")
    else:
        lines.append(f"## Coordination — `{v.label}` score **{v.score:.2f}** · {len(v.members)} nodes")
        for e in v.evidence:
            lines.append(f"- {e}")
    return "\n".join(lines) + "\n"


_BINDINGS = (
    ("cloned_fingerprint", "fp_collision"),
    ("cloned_trace", "trace_collision"),
    ("shared_real_ip", "shared_origin"),
    ("shared_ticket", "ticket_reuse"),
)


def _binding(v: FleetVerdict) -> str | None:
    """The convicting/clustering binding the verdict rests on (fp_collision / trace_collision / …), or None."""
    for attr, name in _BINDINGS:
        if getattr(v, attr) is not None:
            return name
    if v.template_radius is not None:
        return "template_similarity"
    return None


def report_dict(report: FleetReport, *, name: str = "") -> dict[str, Any]:
    """A structured engagement FINDING: per-node health + the coordination verdict + the red⇄blue OUTCOME — the
    reviewable, diffable artifact a run produces. ``outcome`` is ``caught`` (defense convicted the fleet),
    ``evaded`` (the fleet ran but the defense did not convict — the honest boundary), or ``inconclusive`` (too
    few sessions to form a cluster)."""
    v = report.verdict
    outcome = "inconclusive" if v is None else "caught" if v.label == "fleet" else "evaded"
    minted, requested = len(report.ok), len(report.nodes)
    images = sorted({n.image for n in report.nodes})
    if outcome == "caught" and v is not None:
        assessment = f"the {minted}-node fleet {images} was CAUGHT — graded `fleet` {v.score:.2f} via {_binding(v)}"
    elif outcome == "evaded" and v is not None:
        assessment = (
            f"the {minted}-node fleet {images} EVADED conviction — graded `{v.label}` {v.score:.2f}, no convicting "
            f"coordination signal (the honest boundary: this shape is also a real diverse cohort)"
        )
    else:
        assessment = f"only {minted} session(s) captured — too few to form a coordination cluster"
    return {
        "name": name,
        "outcome": outcome,
        "assessment": assessment,
        "fleet": {"requested": requested, "minted": minted, "failed": len(report.failed), "images": images},
        "nodes": [
            {
                "label": n.label,
                "image": n.image,
                "status": n.status,
                "session_id": n.session_id,
                "attempts": n.attempts,
                "proxy": n.proxy,
                "error": n.error,
            }
            for n in report.nodes
        ],
        "coordination": None
        if v is None
        else {
            "label": v.label,
            "score": round(v.score, 3),
            "severity": v.severity,
            "binding": _binding(v),
            "members": v.members,
            "distinct_ips": v.distinct_observed_ips,
            "evidence": v.evidence,
        },
    }


# --- multi-wave campaigns: an engagement as a SEQUENCE of fleet waves (recon → coordinated attack → …) ---


@dataclass(frozen=True)
class Wave:
    """One phase of a campaign: a named fleet plan run in sequence."""

    name: str
    plan: FleetPlan


@dataclass(frozen=True)
class CampaignPlan:
    name: str
    waves: list[Wave]


@dataclass
class WaveResult:
    name: str
    report: FleetReport


@dataclass
class CampaignReport:
    name: str
    waves: list[WaveResult]


_PLAN_GLOBALS = ("edge", "detector", "worker_detector", "network", "retries", "timeout", "max_concurrency")


def campaign_from_obj(obj: Mapping[str, Any]) -> CampaignPlan:
    """Build a :class:`CampaignPlan` from a declarative spec: a ``waves`` list, each wave a fleet-plan body
    (``nodes`` + optional overrides) with a ``name``. Campaign-level targets/policy (``edge``/``detector``/…)
    are inherited by every wave unless the wave overrides them — so an engagement is one timeline-shaped file."""
    raw = obj.get("waves")
    if not isinstance(raw, list) or not raw:
        raise ValueError("campaign needs a non-empty 'waves' list")
    shared = {k: obj[k] for k in _PLAN_GLOBALS if k in obj}
    waves: list[Wave] = []
    for entry in raw:
        wave_name = str(entry.get("name") or f"wave-{len(waves)}")
        body = {**shared, **{k: v for k, v in entry.items() if k != "name"}}
        waves.append(Wave(name=wave_name, plan=plan_from_obj(body)))
    return CampaignPlan(name=str(obj.get("name", "campaign")), waves=waves)


def load_campaign(path: str) -> CampaignPlan:
    """Load a multi-wave campaign from a YAML/JSON file."""
    import yaml

    return campaign_from_obj(yaml.safe_load(Path(path).read_text()))


def run_campaign(
    campaign: CampaignPlan, *, launcher: Launcher = _docker_launch, get_json: JsonGetter = _http_get_json
) -> CampaignReport:
    """Run each wave in sequence (each a full managed fleet, independently captured + graded). Waves are graded
    in isolation — run_fleet grades only the sessions IT minted — so a recon wave does not pollute the attack
    wave's coordination cluster even though both hit the same detector store."""
    return CampaignReport(
        name=campaign.name,
        waves=[WaveResult(w.name, run_fleet(w.plan, launcher=launcher, get_json=get_json)) for w in campaign.waves],
    )


def campaign_report_dict(report: CampaignReport) -> dict[str, Any]:
    """The aggregated campaign FINDING: each wave's engagement report + the campaign-level outcome (which waves
    the defense caught vs which evaded)."""
    waves = [{"wave": w.name, **report_dict(w.report, name=w.name)} for w in report.waves]
    caught = [w["wave"] for w in waves if w["outcome"] == "caught"]
    evaded = [w["wave"] for w in waves if w["outcome"] == "evaded"]
    if caught:
        assessment = f"the defense CAUGHT {len(caught)}/{len(waves)} wave(s): {', '.join(caught)}"
    elif evaded:
        assessment = f"all graded waves EVADED conviction ({', '.join(evaded)}) — no wave was caught"
    else:
        assessment = "no wave formed a gradeable coordination cluster"
    return {
        "name": report.name,
        "assessment": assessment,
        "waves_caught": caught,
        "waves_evaded": evaded,
        "waves": waves,
    }


def render_campaign(report: CampaignReport) -> str:
    """Markdown campaign summary: one line per wave + the aggregated finding."""
    d = campaign_report_dict(report)
    lines = [f"# Campaign `{report.name}` — {len(report.waves)} waves", "", f"_{d['assessment']}_", ""]
    for w in d["waves"]:
        coord = w["coordination"]
        verdict = f"`{coord['label']}` {coord['score']:.2f}" if coord else "no cluster"
        lines.append(f"- **{w['wave']}** → {w['outcome'].upper()} ({w['fleet']['minted']} nodes, {verdict})")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:  # pragma: no cover - thin CLI
    import argparse

    ap = argparse.ArgumentParser(description="Run a managed fleet of real evader workers (authorized targets only).")
    ap.add_argument("--plan", help="declarative engagement plan (YAML/JSON); overrides --evasion/--image/--n")
    ap.add_argument(
        "--evasion", action="append", default=[], help="NAMED evasion from the registry; repeat for a MIXED fleet"
    )
    ap.add_argument("--image", action="append", default=[], help="raw evader image (alternative to --evasion)")
    ap.add_argument("--archetype", help="a named adversary persona (e.g. credential-stuffer, scalper, sybil-farmer)")
    ap.add_argument("--list-evasions", action="store_true", help="print the evasion registry and exit")
    ap.add_argument("--list-archetypes", action="store_true", help="print the adversary archetype catalog and exit")
    ap.add_argument("--n", type=int, default=3, help="replicas per --evasion/--image")
    ap.add_argument("--env", action="append", default=[], help="KEY=VALUE applied to every node (repeatable)")
    ap.add_argument("--proxy", action="append", default=[], help="egress proxy URL; round-robin across nodes")
    ap.add_argument("--edge", default="https://edge:8443/")
    ap.add_argument("--detector", default="http://detector:8080", help="where the MANAGER fetches /session")
    ap.add_argument("--worker-detector", default="http://detector:8080", help="KITSUNE_DETECTOR for workers")
    ap.add_argument("--network", default="kitsune_default")
    ap.add_argument("--retries", type=int, default=1)
    ap.add_argument("--task", help="behavioral task preset every node replays (e.g. browse, scrape-scroll)")
    ap.add_argument("--campaign", help="declarative multi-wave campaign (YAML/JSON); runs each wave in sequence")
    ap.add_argument("--report", help="write the structured engagement finding (JSON) to this path")
    args = ap.parse_args(argv)

    if args.list_evasions:
        for fam, evs in families().items():
            print(f"\n{fam}:")
            for ev in evs:
                print(f"  {ev.name:24} {ev.summary}")
        return 0

    if args.list_archetypes:
        for a in all_archetypes():
            print(f"  {a.name:20} [{a.threat}] {a.expected} via {a.binding}")
            print(f"  {'':20} {a.summary}")
            print(f"  {'':20} rate: {a.rate}\n")
        return 0

    if args.campaign:
        campaign = load_campaign(args.campaign)
        if args.detector != "http://detector:8080":  # override every wave's manager-fetch target off-network
            campaign = CampaignPlan(
                name=campaign.name,
                waves=[
                    Wave(w.name, FleetPlan(**{**w.plan.__dict__, "detector": args.detector})) for w in campaign.waves
                ],
            )
        cresult = run_campaign(campaign)
        print(render_campaign(cresult), end="")
        if args.report:
            Path(args.report).write_text(json.dumps(campaign_report_dict(cresult), indent=2) + "\n")
            print(f"\ncampaign report → {args.report}")
        return 0

    name = "fleet"
    if args.archetype:
        plan = archetype_plan(args.archetype, detector=args.detector)
        name = args.archetype
    elif args.plan:
        plan = load_plan(args.plan)
        name = Path(args.plan).stem
        if args.detector != "http://detector:8080":  # let --detector override the plan for off-network runs
            plan = FleetPlan(**{**plan.__dict__, "detector": args.detector})
    else:
        env = dict(kv.split("=", 1) for kv in args.env)
        if args.task:
            env["KS_TASK"] = get_preset(args.task).to_env()
        proxies = args.proxy or None
        nodes: list[NodeSpec] = []
        specs = [evasion_node(n) for n in args.evasion] + [NodeSpec(image=img) for img in args.image]
        if not specs:
            specs = [evasion_node("zendriver-uach")]
        for spec in specs:
            for rep in range(args.n):
                px = proxies[len(nodes) % len(proxies)] if proxies else None
                label = f"{spec.label}-{rep}" if spec.label else ""  # unique per evasion+replica
                nodes.append(NodeSpec(image=spec.image, env={**spec.env, **env}, proxy=px, label=label))
        plan = FleetPlan(
            nodes=nodes,
            edge=args.edge,
            detector=args.detector,
            worker_detector=args.worker_detector,
            network=args.network,
            retries=args.retries,
        )

    result = run_fleet(plan)
    print(render(result), end="")
    if args.report:
        Path(args.report).write_text(json.dumps(report_dict(result, name=name), indent=2) + "\n")
        print(f"\nengagement report → {args.report}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
