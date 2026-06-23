# detector/Dockerfile — container image for the detector HTTP service.
# Bundles the contracts so schema/rule loading works; serves /ingest on :8080.

FROM python:3.12-slim
COPY --from=ghcr.io/astral-sh/uv:0.11 /uv /bin/uv
WORKDIR /app
COPY contracts /app/contracts
COPY detector /app/detector
COPY docs /app/docs
WORKDIR /app/detector
RUN uv sync --frozen --no-dev
ENV KITSUNE_CONTRACTS_DIR=/app/contracts \
    KITSUNE_DOCS_DIR=/app/docs \
    KITSUNE_HOST=0.0.0.0 \
    KITSUNE_PORT=8080
EXPOSE 8080
CMD ["uv", "run", "python", "-m", "kitsune_detector"]
