#!/bin/sh
set -u
mkdir -p /logs/verifier
printf '%s
' '{"groups_passed":0,"groups_total":0,"oracles_passed":0,"oracles_total":0,"reward":0.0}' > /logs/verifier/reward.json
python3 /tests/cli.py \
  --contract /tests/oracle_contract.json \
  --submission /submission/evidence.json \
  --oracle-result /oracle/result.json \
  --output /logs/verifier/reward.json
