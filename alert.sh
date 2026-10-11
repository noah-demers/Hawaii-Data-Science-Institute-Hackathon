#!/usr/bin/env bash
# Usage: bash alert.sh <type> "<detail>"
# Types: queue_anomaly, data_anomaly, control_anomaly, hardening

set -euo pipefail

ALERTS_FILE="/home/ubuntu/control/logs/alerts.log"
mkdir -p /home/ubuntu/control/logs

TYPE="${1:-}"
DETAIL="${2:-}"

if [[ -z "$TYPE" || -z "$DETAIL" ]]; then
    echo "Usage: bash alert.sh <type> \"<detail>\""
    echo "Types: queue_anomaly, data_anomaly, control_anomaly, hardening"
    exit 1
fi

VALID_TYPES=("queue_anomaly" "data_anomaly" "control_anomaly" "hardening")
VALID=false
for t in "${VALID_TYPES[@]}"; do
    if [[ "$TYPE" == "$t" ]]; then VALID=true; break; fi
done

if [[ "$VALID" == false ]]; then
    echo "Invalid type: $TYPE"
    echo "Valid types: queue_anomaly, data_anomaly, control_anomaly, hardening"
    exit 1
fi

TS=$(date +%s.%3N)
echo "$TS | $TYPE | $DETAIL" >> "$ALERTS_FILE"
echo "Alert logged at $TS: [$TYPE] $DETAIL"