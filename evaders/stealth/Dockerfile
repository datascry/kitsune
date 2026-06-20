# evaders/stealth/Dockerfile — prebuilt Playwright image so the live run skips per-run npm install.
# Playwright is baked into a layer; editing run.mjs only re-copies the last layer (fast rebuild).

FROM mcr.microsoft.com/playwright:v1.55.1-jammy
WORKDIR /app
# Genuine, ubiquitous Linux desktop font families (DejaVu + Noto, alongside the base image's Liberation).
# This makes the container a faithful Linux DESKTOP rather than a font-bare headless box, so the collector's
# real canvas font probe classifies the host as Linux — the precondition for the FONT_OS_LEAK scenario (a
# Linux desktop scraper spoofing a Windows UA leaks its real Linux fonts → br.font_os_vs_ua). Harmless to
# every other mode: under their coherent Linux UA a Linux font hint is correct, so nothing false-fires.
RUN apt-get update -qq \
    && apt-get install -y -qq --no-install-recommends fonts-dejavu-core fonts-noto-core \
    && rm -rf /var/lib/apt/lists/*
COPY package.json ./
# playwright (baseline) + patchright + rebrowser-playwright (two CDP-patched anti-detect drop-ins).
# These are unpinned and can pull a playwright-core needing a different Chromium revision than the base
# image bakes in, so explicitly install the matching browser for each driver.
# Pin all three to 1.52 so they share the base image's Chromium revision. 1.52 is the ceiling here:
# rebrowser-playwright tops out at 1.52.0 (no 1.55+, confirmed on the npm registry 2026-06-20), so bumping
# playwright past it would reintroduce the Chromium-revision mismatch this pin exists to prevent. patchright
# brings its own browser.
# KNOWN/ACCEPTED CVE: this pin holds playwright at 1.52.0, which Dependabot flags for CVE-2025-59288
# (GHSA-7mvr-c777-76hp: `playwright install` fetches browser binaries without verifying SSL-cert authenticity;
# patched in 1.55.1). NOT remediable by a bump — rebrowser-playwright's 1.52.0 ceiling forces the trio to one
# shared Chromium revision. Exposure is build-time-only (the vulnerable path is browser DOWNLOAD during
# `docker build`, over Microsoft's CDN) on an in-sandbox red-team evader that runs solely against Kitsune's own
# detector + the harness allow-list — never production. Accepted as tolerable; do not re-investigate per-push
# (this analysis is the answer). Revisit if rebrowser-playwright ever publishes >=1.55.1.
RUN npm install --silent --no-audit --no-fund \
      playwright@1.52.0 patchright rebrowser-playwright@1.52.0 \
    && (npx playwright install chromium || true) \
    && (npx patchright install chromium || true)
COPY run.mjs ./
ENTRYPOINT ["node", "run.mjs"]
