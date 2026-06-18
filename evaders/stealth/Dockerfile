# evaders/stealth/Dockerfile — prebuilt Playwright image so the live run skips per-run npm install.
# Playwright is baked into a layer; editing run.mjs only re-copies the last layer (fast rebuild).

FROM mcr.microsoft.com/playwright:v1.48.0-jammy
WORKDIR /app
COPY package.json ./
# playwright (baseline) + patchright (CDP-patched anti-detect drop-in) and its browser.
# patchright is unpinned and can pull a playwright-core needing a different Chromium revision than the
# base image bakes in, so explicitly install the matching browser for both drivers.
RUN npm install --silent --no-audit --no-fund playwright@1.48.0 patchright \
    && (npx playwright install chromium || true) \
    && (npx patchright install chromium || true)
COPY run.mjs ./
ENTRYPOINT ["node", "run.mjs"]
