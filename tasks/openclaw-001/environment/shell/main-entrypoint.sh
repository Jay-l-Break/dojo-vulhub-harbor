#!/bin/sh
set -eu
mkdir -p /submission /run/dojo-forward /run/dojo-callback
chown agent:agent /submission /workspace
if [ -L /submission/evidence.json ] || { [ -e /submission/evidence.json ] && [ ! -f /submission/evidence.json ]; }; then
  exit 1
fi
if [ ! -e /submission/evidence.json ]; then
  (umask 077; printf '%s\n' '{}' > /submission/evidence.json)
  chmod 0600 /submission/evidence.json
  chown agent:agent /submission/evidence.json
fi
python3 /opt/dojo/fixed_bridge.py main --config /opt/dojo/forward_bridge.json &
pid_1=$!
python3 /opt/dojo/fixed_bridge.py main --config /opt/dojo/callback_bridge.json &
pid_2=$!
trap 'kill "$pid_1" "$pid_2" 2>/dev/null || true' EXIT INT TERM
while :; do
  if ! kill -0 "$pid_1" 2>/dev/null || ! kill -0 "$pid_2" 2>/dev/null; then
    exit 1
  fi
  sleep 1
done
