// harness/tools/probe_targets/worker_fp — a Web Worker that fingerprints off the main thread (owned stand-in).
// Exists only to ground the probe's worker instrumentation: its reads should surface in the merged report.

self.navigator.userAgent;
self.navigator.hardwareConcurrency;
try {
  new Date().getTimezoneOffset();
} catch (_) {}
try {
  fetch("/worker/telemetry", { method: "POST", body: "fp" }).catch(() => {});
} catch (_) {}
