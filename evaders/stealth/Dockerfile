# evaders/stealth/Dockerfile — prebuilt Playwright image so the live run skips per-run npm install.
# Playwright is baked into a layer; editing run.mjs only re-copies the last layer (fast rebuild).

FROM mcr.microsoft.com/playwright:v1.52.0-jammy
WORKDIR /app
COPY package.json ./
# playwright (baseline) + patchright + rebrowser-playwright (two CDP-patched anti-detect drop-ins).
# These are unpinned and can pull a playwright-core needing a different Chromium revision than the base
# image bakes in, so explicitly install the matching browser for each driver.
# Pin all three to 1.52 so they share the base image's Chromium revision. 1.52 is the ceiling here:
# rebrowser-playwright tops out at 1.52.0 (no 1.55+), so bumping playwright past it would reintroduce
# the Chromium-revision mismatch this pin exists to prevent. patchright brings its own browser.
RUN npm install --silent --no-audit --no-fund \
      playwright@1.52.0 patchright rebrowser-playwright@1.52.0 \
    && (npx playwright install chromium || true) \
    && (npx patchright install chromium || true)
COPY run.mjs ./
ENTRYPOINT ["node", "run.mjs"]
