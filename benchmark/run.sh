#!/usr/bin/env bash
# Minimal tool-agnostic benchmark runner.
#
# Sends every attack and negative in the corpus to a scan endpoint and
# reports blocked / missed / false-positive / flagged counts.
#
# Usage:
#   ./run.sh                                   # default: scan every file
#   ENDPOINT=http://host:port/v1/firewall/scan ./run.sh
#   TOOL=crawdad ./run.sh                      # same, labelled "crawdad"
#
# The endpoint must accept POST with JSON body {"text": "<content>"} and
# return a JSON body containing a field whose value indicates blocked vs.
# allowed. `jq` is required.
#
# By default we look for ".verdict" == "Blocked" or ".blocked" == true
# (either convention works). Override with VERDICT_FILTER for other tools.
set -euo pipefail

ENDPOINT="${ENDPOINT:-http://127.0.0.1:7749/v1/firewall/scan/full}"
TOOL="${TOOL:-unknown}"
ATTACKS_DIR="${ATTACKS_DIR:-$(dirname "$0")/../attacks}"
NEGATIVES_DIR="${NEGATIVES_DIR:-$(dirname "$0")/../negatives}"

if ! command -v jq >/dev/null 2>&1; then
  echo "error: jq is required" >&2
  exit 1
fi

is_blocked() {
  local body="$1"
  echo "$body" | jq -e '(.verdict=="Blocked") or (.blocked==true) or (.decision=="block") or (.block==true)' >/dev/null 2>&1
}

scan_file() {
  local path="$1"
  local body
  body=$(jq -Rs '{text: ., direction: "inbound"}' <"$path")
  curl -s -X POST "$ENDPOINT" -H 'Content-Type: application/json' --data "$body"
}

blocked=0
missed=0
fp=0
tn=0
total_attacks=0
total_negs=0

echo "tool=$TOOL endpoint=$ENDPOINT"
echo "Scanning attacks..."
while IFS= read -r -d '' f; do
  total_attacks=$((total_attacks + 1))
  resp=$(scan_file "$f") || resp=""
  if is_blocked "$resp"; then
    blocked=$((blocked + 1))
  else
    missed=$((missed + 1))
    [ -n "${VERBOSE:-}" ] && echo "MISS: $f"
  fi
done < <(find "$ATTACKS_DIR" -type f -name "*.txt" -print0)

echo "Scanning negatives..."
while IFS= read -r -d '' f; do
  total_negs=$((total_negs + 1))
  resp=$(scan_file "$f") || resp=""
  if is_blocked "$resp"; then
    fp=$((fp + 1))
    [ -n "${VERBOSE:-}" ] && echo "FP:   $f"
  else
    tn=$((tn + 1))
  fi
done < <(find "$NEGATIVES_DIR" -type f -name "*.txt" -print0)

attack_rate=0
fp_rate=0
if [ "$total_attacks" -gt 0 ]; then
  attack_rate=$(awk -v b="$blocked" -v t="$total_attacks" 'BEGIN{printf "%.2f", b*100.0/t}')
fi
if [ "$total_negs" -gt 0 ]; then
  fp_rate=$(awk -v f="$fp" -v t="$total_negs" 'BEGIN{printf "%.2f", f*100.0/t}')
fi

echo
echo "=== $TOOL ==="
echo "Attacks:   $total_attacks   blocked=$blocked missed=$missed   detection=${attack_rate}%"
echo "Negatives: $total_negs   fp=$fp tn=$tn                false_positive=${fp_rate}%"
