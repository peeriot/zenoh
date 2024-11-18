FROM debian:bookworm-slim

COPY artifacts/zenohd /usr/local/bin/
COPY artifacts/libzenoh_plugin_*.so /usr/local/lib/
COPY config/* /etc/zenohd/
COPY certs/* /etc/zenohd/certs/
COPY scripts/entrypoint /entrypoint

RUN     apt-get update \
    &&  apt-get install -y \
            curl \
            openssl \
            tini \
    &&  rm -rf /var/lib/apt/lists/*

ENTRYPOINT [ "/usr/bin/tini", "--" ]
CMD [ "zenohd", "--config", "/etc/zenohd/config.json" ]
