FROM debian:13-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl openssl python3 procps && rm -rf /var/lib/apt/lists/*
COPY .cache/compat/bin/sing-box /usr/local/bin/sing-box
COPY .cache/compat/bin/mihomo /usr/local/bin/mihomo
COPY scripts/compat/probe.py /probe.py
CMD ["sleep", "infinity"]
