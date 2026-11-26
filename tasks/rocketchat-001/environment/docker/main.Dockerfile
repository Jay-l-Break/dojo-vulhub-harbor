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
    && git -C /app/repo fetch --depth=1 origin d3024176f86e406d45cf45378c4af3f0ac7fe6c7 \
    && git -C /app/repo checkout --detach FETCH_HEAD \
    && test "$(git -C /app/repo rev-parse HEAD)" = "d3024176f86e406d45cf45378c4af3f0ac7fe6c7" \
    && rm -rf /app/repo/.git \
    && find /app/repo -type f -name 'attack_scope.json' -delete

RUN python3 -c 'exec('"'"'import hashlib\nimport pathlib\n\npath = pathlib.Path(\'"'"'/app/repo/bridge.js\'"'"')\nsource = path.read_bytes()\ndigest = hashlib.sha256(source).hexdigest()\nold = b"  const material = request.headers[\'"'"'x-rocket-identity\'"'"'] || \'"'"'\'"'"';\\n  const separator = material.indexOf(\'"'"':\'"'"');\\n  if (separator < 1) {\\n    response.writeHead(401);\\n    response.end(\'"'"'Missing identity\'"'"');\\n    return;\\n  }\\n  const userId = material.slice(0, separator);\\n  const token = material.slice(separator + 1);\\n"\nnew = b"  const token = request.headers[\'"'"'x-rocket-identity\'"'"'] || \'"'"'\'"'"';\\n  if (!token) {\\n    response.writeHead(401);\\n    response.end(\'"'"'Missing token\'"'"');\\n    return;\\n  }\\n  const userId = user.user_id;\\n"\nif digest == \'"'"'0a971bc4bd51bf046b5fbe059044bc8ce17a1d171eb05b2a79f5589e0b4626c1\'"'"':\n    if source.count(old) != 1 or source.count(new) != 0:\n        raise SystemExit("Rocket.Chat identity hardener token mismatch")\n    path.write_bytes(source.replace(old, new))\nelif digest != \'"'"'59f00d14b9bfbb5b2350c52292a7dc2d2ac322319260ec6217fafc8a1b3d0917\'"'"':\n    raise SystemExit("Rocket.Chat identity hardener source checksum mismatch")\nif hashlib.sha256(path.read_bytes()).hexdigest() != \'"'"'59f00d14b9bfbb5b2350c52292a7dc2d2ac322319260ec6217fafc8a1b3d0917\'"'"':\n    raise SystemExit("Rocket.Chat identity hardener output checksum mismatch")\n'"'"')'
RUN mkdir -p /app/repo/app-source \
    && find /app/repo -type f \
        \( -name '*source*.tar.gz' -o -name '*source*.tgz' \
        -o -name '*source*.tar.xz' \) -print0 \
    | sort --zero-terminated \
    | xargs --null --no-run-if-empty --max-args=1 \
        tar --extract --directory /app/repo/app-source --file \
    && find /app/repo -type f -name 'attack_scope.json' -delete \
    && chown -R agent:agent /app/repo /submission /workspace

COPY python/fixed_bridge.py /opt/dojo/fixed_bridge.py
COPY json/forward_bridge.json /opt/dojo/forward_bridge.json
COPY json/oracle_contract.json /app/oracle_contract.json
COPY shell/main-entrypoint.sh /opt/dojo/main-entrypoint.sh
RUN chmod 0755 /opt/dojo/main-entrypoint.sh

ENTRYPOINT ["/opt/dojo/main-entrypoint.sh"]
WORKDIR /app/repo
CMD ["sleep", "infinity"]
