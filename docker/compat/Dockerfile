FROM debian:trixie-20261104-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl openssl python3 procps && rm -rf /var/lib/apt/lists/*
COPY .cache/compat/bin/sing-box /usr/local/bin/sing-box
COPY .cache/compat/bin/mihomo /usr/local/bin/mihomo
COPY scripts/compat/probe.py /probe.py
CMD ["sleep", "infinity"]
