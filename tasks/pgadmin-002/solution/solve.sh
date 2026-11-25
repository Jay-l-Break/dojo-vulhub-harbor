#!/bin/sh
set -eu
exec python3 /solution/solution_runner.py \
  --task-id pgadmin-002 \
  --manifest /solution/manifest.json \
  --poc-dir /solution/poc \
  --challenge /submission/challenge.json \
  --output /submission/evidence.json
