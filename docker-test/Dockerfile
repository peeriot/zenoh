FROM debian:bookworm-slim

COPY artifacts/zenohd /usr/local/bin/
COPY artifacts/libzenoh_plugin_*.so /usr/local/lib/
COPY config/* /etc/zenohd/

RUN     apt-get update \
    &&  apt-get install -y \
            curl \
            tini \
    &&  rm -rf /var/lib/apt/lists/*

ENTRYPOINT [ "/usr/bin/tini", "--", "zenohd" ]
CMD [ "--config", "/etc/zenohd/config.json" ]
