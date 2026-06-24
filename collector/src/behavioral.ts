// collector/behavioral — quantify pointer behaviour into the signals the detector scores.
// Normalised movement-direction entropy + event count; scripted/straight motion -> low entropy.

import type { PointerSample } from "./types.js";

const BINS = 8;

export function pointerEventCount(samples: PointerSample[]): number {
  return samples.length;
}

/**
 * Shannon entropy of quantised movement directions, normalised to [0, 1].
 * Straight or absent motion -> ~0 (trips the human-entropy floor); varied human motion -> high.
 */
export function mouseEntropy(samples: PointerSample[]): number {
  const bins = new Array<number>(BINS).fill(0);
  let total = 0;
  for (let i = 1; i < samples.length; i++) {
    const a = samples[i - 1]!;
    const b = samples[i]!;
    const dx = b.x - a.x;
    const dy = b.y - a.y;
    if (dx === 0 && dy === 0) continue;
    const angle = Math.atan2(dy, dx); // [-pi, pi]
    let idx = Math.floor(((angle + Math.PI) / (2 * Math.PI)) * BINS);
    if (idx >= BINS) idx = BINS - 1;
    bins[idx]! += 1;
    total += 1;
  }
  if (total < 2) return 0;

  let h = 0;
  for (const count of bins) {
    if (count > 0) {
      const p = count / total;
      h -= p * Math.log2(p);
    }
  }
  return h / Math.log2(BINS);
}

function dist(a: PointerSample, b: PointerSample): number {
  return Math.hypot(b.x - a.x, b.y - a.y);
}

/**
 * Path straightness: straight-line distance / total path length, in [0, 1].
 * A perfectly straight drag -> ~1 (scripted); a curving human path -> lower. 0 if < 3 samples.
 */
export function pathStraightness(samples: PointerSample[]): number {
  if (samples.length < 3) return 0;
  let total = 0;
  for (let i = 1; i < samples.length; i++) {
    total += dist(samples[i - 1]!, samples[i]!);
  }
  if (total === 0) return 0;
  return dist(samples[0]!, samples[samples.length - 1]!) / total;
}

/**
 * Coefficient of variation (std/mean) of segment speeds.
 * Constant-speed automation -> ~0; variable human motion -> high. Returns 1 when undeterminable.
 */
export function velocityCV(samples: PointerSample[]): number {
  const speeds: number[] = [];
  for (let i = 1; i < samples.length; i++) {
    const dt = samples[i]!.t - samples[i - 1]!.t;
    if (dt > 0) speeds.push(dist(samples[i - 1]!, samples[i]!) / dt);
  }
  if (speeds.length < 2) return 1;
  const mean = speeds.reduce((a, b) => a + b, 0) / speeds.length;
  if (mean === 0) return 1;
  const variance = speeds.reduce((a, s) => a + (s - mean) ** 2, 0) / speeds.length;
  return Math.sqrt(variance) / mean;
}

/**
 * Stable hash of the pointer trajectory's shape (quantised coordinates, timing excluded — it jitters).
 * Two REAL users never produce a byte-identical trace, so an identical trace_hash across distinct sessions
 * is one tool replaying a canned "humanised" trajectory — the behavioural analog of the fingerprint
 * collision. Null below a movement floor (a trivial trace must not collide spuriously).
 */
export function traceHash(samples: PointerSample[]): string | null {
  if (samples.length < 12) return null;
  let h = 2166136261;
  const mix = (n: number): void => {
    h = ((h ^ (n & 0xffff)) * 16777619) >>> 0;
  };
  for (const s of samples) {
    mix(Math.round(s.x));
    mix(Math.round(s.y));
  }
  return (h >>> 0).toString(16);
}

/**
 * Normalised Shannon entropy of inter-keystroke intervals, in [0, 1].
 * Constant cadence (scripted typing) -> ~0; varied human cadence -> high.
 */
export function keystrokeEntropy(times: number[]): number {
  if (times.length < 3) return 0;
  const intervals: number[] = [];
  for (let i = 1; i < times.length; i++) {
    intervals.push(times[i]! - times[i - 1]!);
  }
  const min = Math.min(...intervals);
  const max = Math.max(...intervals);
  if (max === min) return 0;

  const bins = new Array<number>(BINS).fill(0);
  for (const v of intervals) {
    let idx = Math.floor(((v - min) / (max - min)) * BINS);
    if (idx >= BINS) idx = BINS - 1;
    bins[idx]! += 1;
  }
  let h = 0;
  for (const count of bins) {
    if (count > 0) {
      const p = count / intervals.length;
      h -= p * Math.log2(p);
    }
  }
  return h / Math.log2(BINS);
}

/**
 * Median inter-keystroke interval in ms, or -1 when there are too few intervals to judge.
 * Catches agent-speed typing that keeps human-like entropy (varied sub-ms gaps) yet types far below any
 * human cadence (Browser-Use ~5ms, Manus ~1ms vs a human 100ms+) — orthogonal to {@link keystrokeEntropy},
 * which only collapses for fixed-delay scripts. Backs the `bh.keystroke_interval_floor` rule (radar G13).
 */
export function keystrokeIntervalMedian(times: number[]): number {
  const intervals: number[] = [];
  for (let i = 1; i < times.length; i++) {
    const dt = times[i]! - times[i - 1]!;
    if (dt > 0) intervals.push(dt);
  }
  if (intervals.length < 3) return -1;
  intervals.sort((a, b) => a - b);
  return intervals[Math.floor(intervals.length / 2)]!;
}
