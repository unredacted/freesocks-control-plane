FROM debian:13-slim@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl openssl python3 procps && rm -rf /var/lib/apt/lists/*
COPY .cache/compat/bin/sing-box /usr/local/bin/sing-box
COPY .cache/compat/bin/mihomo /usr/local/bin/mihomo
COPY scripts/compat/probe.py /probe.py
CMD ["sleep", "infinity"]
