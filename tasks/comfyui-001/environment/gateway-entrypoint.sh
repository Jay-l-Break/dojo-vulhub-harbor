#!/bin/sh
set -eu
mkdir -p /submission /run/dojo-forward /run/dojo-callback
python3 /opt/dojo/fixed_bridge.py target --config /opt/dojo/forward_bridge.json &
pid_1=$!
python3 /opt/dojo/fixed_bridge.py target --config /opt/dojo/callback_bridge.json &
pid_2=$!
trap 'kill "$pid_1" "$pid_2" 2>/dev/null || true' EXIT INT TERM
while :; do
  if ! kill -0 "$pid_1" 2>/dev/null || ! kill -0 "$pid_2" 2>/dev/null; then
    exit 1
  fi
  sleep 1
done
