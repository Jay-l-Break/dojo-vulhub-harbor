FROM curlimages/curl:8.11.1@sha256:c1fe1679c34d9784c1b0d1e5f62ac0a79fca01fb6377cdd33e90473c6f9f9a69 AS archive-fetcher
USER root

RUN set -eu; \
    archive=/tmp/elasticsearch-5.0.0-alpha2.tar.gz; \
    curl --fail --location --silent --show-error \
        https://download.elastic.co/elasticsearch/release/org/elasticsearch/distribution/tar/elasticsearch/5.0.0-alpha2/elasticsearch-5.0.0-alpha2.tar.gz --output "$archive"; \
    echo 'df8b204ccede97d3a2c38efddacce59eaac9a4ef19d107eb0f048b33a720e584  /tmp/elasticsearch-5.0.0-alpha2.tar.gz' \
        | sha256sum -c -

FROM elasticsearch:5.0.0@sha256:29f6b68a0088238f4a108e6c725163130e382a0f34ed62159c82e3961f0639fa
USER root

COPY --from=archive-fetcher /tmp/elasticsearch-5.0.0-alpha2.tar.gz \
    /tmp/elasticsearch-5.0.0-alpha2.tar.gz

RUN set -eu; \
    archive=/tmp/elasticsearch-5.0.0-alpha2.tar.gz; \
    rm -rf /usr/share/elasticsearch/NOTICE.txt \
        /usr/share/elasticsearch/README.textile /usr/share/elasticsearch/bin \
        /usr/share/elasticsearch/config /usr/share/elasticsearch/lib \
        /usr/share/elasticsearch/logs /usr/share/elasticsearch/modules \
        /usr/share/elasticsearch/plugins; \
    tar --extract --gzip --file "$archive" --strip-components=1 \
        --directory /usr/share/elasticsearch; \
    rm "$archive"; \
    mkdir -p /usr/share/elasticsearch/data /usr/share/elasticsearch/logs; \
    chown -R elasticsearch:elasticsearch /usr/share/elasticsearch
