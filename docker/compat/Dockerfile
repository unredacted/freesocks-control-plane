FROM debian:13-slim@sha256:f6b08b09a05725f9431502d3b5714f5c4576e82c1a84fa1debe0c24a7e0c3ec4
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl openssl python3 procps && rm -rf /var/lib/apt/lists/*
COPY .cache/compat/bin/sing-box /usr/local/bin/sing-box
COPY .cache/compat/bin/mihomo /usr/local/bin/mihomo
COPY scripts/compat/probe.py /probe.py
CMD ["sleep", "infinity"]
