// collector/session — read the correlation id the edge set as a cookie.
// Parses ks_sid from a cookie string so collector telemetry joins the edge's network signals.

export const COOKIE_NAME = "ks_sid";

export function readSessionId(cookie: string): string | null {
  const match = cookie.match(new RegExp(`(?:^|;\\s*)${COOKIE_NAME}=([^;]+)`));
  return match ? decodeURIComponent(match[1]!) : null;
}
