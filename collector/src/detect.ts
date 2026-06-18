// collector/detect — derive browser/platform labels from the User-Agent and Client-Hints.
// Feeds the detector's UA<->Client-Hints coherence checks (ua_browser, ua_platform, ch_platform).

/** Coarse browser family from a User-Agent string. Order matters (Edge/Firefox before Chrome). */
export function uaBrowser(ua: string): string {
  if (/Firefox\//.test(ua)) return "firefox";
  if (/Edg\//.test(ua)) return "edge";
  if (/Chrome\//.test(ua)) return "chrome";
  if (/Safari\//.test(ua)) return "safari";
  return "unknown";
}

/** Coarse OS/platform from a User-Agent string. */
export function uaPlatform(ua: string): string {
  if (/Windows/.test(ua)) return "Windows";
  if (/Macintosh|Mac OS X/.test(ua)) return "macOS";
  if (/Android/.test(ua)) return "Android";
  if (/Linux/.test(ua)) return "Linux";
  return "unknown";
}

/** True if the User-Agent advertises a headless browser (a strong automation tell). */
export function isHeadlessUA(ua: string): boolean {
  return /Headless/i.test(ua);
}

/** Normalise a Sec-CH-UA-Platform / userAgentData.platform value to the ua_platform vocabulary. */
export function normalizePlatform(platform: string): string {
  const map: Record<string, string> = {
    "Mac OS X": "macOS",
    macOS: "macOS",
    Windows: "Windows",
    Linux: "Linux",
    Android: "Android",
  };
  return map[platform] ?? platform;
}
