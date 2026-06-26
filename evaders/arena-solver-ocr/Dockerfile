# evaders/arena-solver-ocr/Dockerfile — the OCR evader (HF TrOCR captcha model; owned gates only).
# Heavy by nature (transformers + torch); run one-shot against Kitsune's own arena to beat the text gate.

FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir "httpx>=0.27" "transformers>=4.40" "torch>=2.2" "pillow>=10.0"
COPY evaders/arena-solver-ocr/src/ ./src/
ENV PYTHONPATH=/app/src
ENTRYPOINT ["python", "-m", "kitsune_arena_ocr"]
