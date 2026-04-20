"""
Reference adapter for the Crawdad sidecar.

Exposes a single top-level function `classify(text) -> bool` that POSTs the
text to the local Crawdad sidecar's scan endpoint and returns True if the
sidecar considers the input malicious.

Environment overrides:
    CRAWDAD_ENDPOINT   (default: http://127.0.0.1:7749/v1/firewall/scan)
    CRAWDAD_TIMEOUT    seconds, default 10

Example:
    python3 run.py --adapter adapters.crawdad --tool crawdad-v0.9.1
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

_ENDPOINT = os.environ.get("CRAWDAD_ENDPOINT", "http://127.0.0.1:7749/v1/firewall/scan/full")
_TIMEOUT = float(os.environ.get("CRAWDAD_TIMEOUT", "10"))


def classify(text: str) -> bool:
    body = json.dumps({"text": text}).encode("utf-8")
    req = urllib.request.Request(
        _ENDPOINT,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, json.JSONDecodeError):
        return False
    return bool(data.get("blocked")) or str(data.get("verdict", "")).lower() == "blocked"
