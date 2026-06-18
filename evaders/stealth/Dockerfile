# evaders/stealth/Dockerfile — prebuilt Playwright image so the live run skips per-run npm install.
# Playwright is baked into a layer; editing run.mjs only re-copies the last layer (fast rebuild).

FROM mcr.microsoft.com/playwright:v1.48.0-jammy
WORKDIR /app
COPY package.json ./
# playwright (baseline) + patchright + rebrowser-playwright (two CDP-patched anti-detect drop-ins).
# These are unpinned and can pull a playwright-core needing a different Chromium revision than the base
# image bakes in, so explicitly install the matching browser for each driver.
# Pin rebrowser-playwright to 1.48 so it reuses the base image's Chromium-1140 (unpinned pulls 1.52 →
# a different revision and npm-hoisting conflicts with patchright). patchright brings its own browser.
RUN npm install --silent --no-audit --no-fund \
      playwright@1.48.0 patchright rebrowser-playwright@1.48.2 \
    && (npx playwright install chromium || true) \
    && (npx patchright install chromium || true)
COPY run.mjs ./
ENTRYPOINT ["node", "run.mjs"]
