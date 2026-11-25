FROM python:3.12-slim@sha256:191083cdf6c7bda8c76158983163ead5d5cf7b77cf3033e805bb0f5296f51b4b
RUN pip install --no-cache-dir 'psycopg[binary]==3.2.13' 'PyMySQL==1.1.2'
RUN mkdir -p /opt/dojo /oracle/private /submission /run/dojo-seed \
    /run/oracle-proof /run/dojo-oracle /run/dojo-forward /run/dojo-callback \
    /oracle/observed/file-creation
COPY python/runtime_oracle.py /oracle/runtime_oracle.py
COPY json/runtime_config.json /oracle/config.json
COPY python/fixed_bridge.py /opt/dojo/fixed_bridge.py
COPY json/forward_bridge.json /opt/dojo/forward_bridge.json
COPY shell/gateway-entrypoint.sh /opt/dojo/gateway-entrypoint.sh
RUN chmod 0755 /opt/dojo/gateway-entrypoint.sh
