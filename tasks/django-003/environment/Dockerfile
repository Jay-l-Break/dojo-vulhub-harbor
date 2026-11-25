FROM debian:bookworm-slim@sha256:e67eeead736ff7bbe258ef088bff683635c561b1fcfefad0806c1df4ab49ce0e

RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        ca-certificates curl git gzip jq netcat-openbsd python3 python3-msgpack \
        python3-pip python3-zmq ripgrep tar xz-utils \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --system agent \
    && useradd --create-home --gid agent --shell /bin/bash agent \
    && mkdir -p /app /submission /workspace /run/dojo-forward /run/dojo-callback

RUN git init /app/repo \
    && git -C /app/repo remote add origin https://github.com/Jay-l-Break/dojo-vulhub.git \
    && git -C /app/repo fetch --depth=1 origin fb845e626c877a5ef344d03a2c12a934073eba80 \
    && git -C /app/repo checkout --detach FETCH_HEAD \
    && test "$(git -C /app/repo rev-parse HEAD)" = "fb845e626c877a5ef344d03a2c12a934073eba80" \
    && rm -rf /app/repo/.git \
    && find /app/repo -type f -name 'attack_scope.json' -delete

RUN mkdir -p /app/repo/app-source \
    && find /app/repo -type f \
        \( -name '*source*.tar.gz' -o -name '*source*.tgz' \
        -o -name '*source*.tar.xz' \) -print0 \
    | sort --zero-terminated \
    | xargs --null --no-run-if-empty --max-args=1 \
        tar --extract --directory /app/repo/app-source --file \
    && find /app/repo -type f -name 'attack_scope.json' -delete \
    && chown -R agent:agent /app/repo /submission /workspace

COPY fixed_bridge.py /opt/dojo/fixed_bridge.py
COPY forward_bridge.json /opt/dojo/forward_bridge.json
COPY callback_bridge.json /opt/dojo/callback_bridge.json
COPY oracle_contract.json /app/oracle_contract.json
COPY main-entrypoint.sh /opt/dojo/main-entrypoint.sh
RUN chmod 0755 /opt/dojo/main-entrypoint.sh

ENTRYPOINT ["/opt/dojo/main-entrypoint.sh"]
WORKDIR /app/repo
CMD ["sleep", "infinity"]
