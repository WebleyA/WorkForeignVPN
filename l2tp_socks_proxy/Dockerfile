ARG XRAY_VERSION=26.3.27
FROM ghcr.io/xtls/xray-core:${XRAY_VERSION} AS xray

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        bash \
        gettext-base \
        iproute2 \
        iptables \
        kmod \
        ppp \
        libstrongswan-extra-plugins \
        strongswan \
        xl2tpd \
    && rm -rf /var/lib/apt/lists/*

COPY --from=xray /usr/local/bin/xray /usr/local/bin/xray
COPY config/ /etc/gateway/templates/
COPY entrypoint.sh /usr/local/bin/gateway-entrypoint

RUN chmod +x /usr/local/bin/gateway-entrypoint \
    && mkdir -p /run/xl2tpd /etc/xray

EXPOSE 1081/tcp

ENTRYPOINT ["/usr/local/bin/gateway-entrypoint"]
