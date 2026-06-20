# evaders/apify-fp-inject/Dockerfile — Playwright image + apify fingerprint-injector toolchain.
# Bakes playwright + fingerprint-generator/-injector into a layer; editing run.mjs only re-copies the last layer.

FROM mcr.microsoft.com/playwright:v1.55.1-jammy
WORKDIR /app
COPY package.json ./
# fingerprint-generator samples a real-device fingerprint; fingerprint-injector wires it into a Playwright
# context. Pinned to the base image's Chromium (playwright 1.52.0) so the injected fingerprint drives the
# revision the image bakes in.
RUN npm install --silent --no-audit --no-fund \
      playwright@1.52.0 fingerprint-generator@2.1.82 fingerprint-injector@2.1.82 \
    && (npx playwright install chromium || true)
COPY run.mjs ./
ENTRYPOINT ["node", "run.mjs"]
