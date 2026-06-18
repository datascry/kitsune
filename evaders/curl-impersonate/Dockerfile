# evaders/curl-impersonate/Dockerfile — curl_cffi evader (curl-impersonate: perfect browser TLS/H2/headers).
# No browser — the TLS-mimicry frontier: a real Chrome JA3/JA4/h2 fingerprint over a scripted client.

FROM python:3.11-slim
RUN pip install --no-cache-dir curl_cffi
COPY run.py /run.py
ENTRYPOINT ["python", "/run.py"]
