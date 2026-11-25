FROM public.ecr.aws/docker/library/golang:1.24-bookworm@sha256:1a6d4452c65dea36aac2e2d606b01b4a029ec90cc1ae53890540ce6173ea77ac AS helper-builder
WORKDIR /src
COPY rce_helper.go /src/rce_helper.go
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/helper /src/rce_helper.go

FROM python:3.12-slim@sha256:191083cdf6c7bda8c76158983163ead5d5cf7b77cf3033e805bb0f5296f51b4b
RUN pip install --no-cache-dir 'psycopg[binary]==3.2.13' 'PyMySQL==1.1.2'
RUN mkdir -p /opt/dojo /oracle/private /submission /run/dojo-seed \
    /run/oracle-proof /run/dojo-oracle /run/dojo-forward /run/dojo-callback \
    /oracle/observed/file-creation
COPY runtime_oracle.py /oracle/runtime_oracle.py
COPY runtime_config.json /oracle/config.json
COPY fixed_bridge.py /opt/dojo/fixed_bridge.py
COPY forward_bridge.json /opt/dojo/forward_bridge.json
COPY callback_bridge.json /opt/dojo/callback_bridge.json
COPY gateway-entrypoint.sh /opt/dojo/gateway-entrypoint.sh
COPY --from=helper-builder /out/helper /usr/local/bin/dojo-rce-helper
RUN chmod 0755 /opt/dojo/gateway-entrypoint.sh /usr/local/bin/dojo-rce-helper
