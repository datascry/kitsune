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
