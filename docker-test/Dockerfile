FROM test-net-client

COPY artifacts/zenohd /usr/local/bin/
COPY artifacts/libzenoh_plugin_*.so /usr/local/lib/
COPY config/* /etc/zenohd/
COPY certs/* /etc/zenohd/certs/
COPY scripts/entrypoint /entrypoint

RUN     apt-get update \
    &&  apt-get install -y \
            curl \
            htop \
            openssl \
            tini \
    &&  rm -rf /var/lib/apt/lists/*

CMD [ "zenohd", "--config", "/etc/zenohd/config.json" ]
