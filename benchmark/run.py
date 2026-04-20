#!/usr/bin/env python3
"""
Tool-agnostic benchmark runner for the Contemporary Agent Attacks corpus.

Feeds every attack and negative through a user-supplied adapter and reports
per-category detection rate, false-positive rate, and overall F1. Results can
be written to JSON and compared against a prior run.

Usage:
    # Run against the default built-in HTTP scan adapter
    python3 run.py --endpoint http://127.0.0.1:7749/v1/firewall/scan

    # Use a pluggable adapter (Python module exposing classify(text) -> bool)
    python3 run.py --adapter adapters.crawdad --tool crawdad-v0.9.1

    # Save results, then later diff against them
    python3 run.py --adapter adapters.crawdad --output results/crawdad-v0.9.1.json
    python3 run.py --adapter adapters.crawdad --compare results/crawdad-v0.9.1.json

Adapters:
    An adapter is a Python module or object with a top-level callable named
    `classify(text: str) -> bool` (True = blocked/malicious). See
    `adapters/crawdad.py` for a reference implementation.
"""
from __future__ import annotations

import argparse
import importlib
import json
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_ATTACKS = ROOT / "attacks"
DEFAULT_NEGATIVES = ROOT / "negatives"


@dataclass
class CategoryStats:
    total: int = 0
    blocked: int = 0

    @property
    def rate(self) -> float:
        return 100.0 * self.blocked / self.total if self.total else 0.0


@dataclass
class Results:
    tool: str
    endpoint: str
    started_at: float
    duration_sec: float = 0.0
    attack_total: int = 0
    attack_blocked: int = 0
    negative_total: int = 0
    negative_flagged: int = 0
    attack_by_category: dict = field(default_factory=dict)
    negative_by_category: dict = field(default_factory=dict)

    @property
    def detection_rate(self) -> float:
        return 100.0 * self.attack_blocked / self.attack_total if self.attack_total else 0.0

    @property
    def false_positive_rate(self) -> float:
        return (
            100.0 * self.negative_flagged / self.negative_total if self.negative_total else 0.0
        )

    @property
    def precision(self) -> float:
        tp = self.attack_blocked
        fp = self.negative_flagged
        return 100.0 * tp / (tp + fp) if (tp + fp) else 0.0

    @property
    def recall(self) -> float:
        return self.detection_rate

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    def to_dict(self) -> dict:
        return {
            "tool": self.tool,
            "endpoint": self.endpoint,
            "started_at": self.started_at,
            "duration_sec": round(self.duration_sec, 2),
            "attacks": {
                "total": self.attack_total,
                "blocked": self.attack_blocked,
                "missed": self.attack_total - self.attack_blocked,
                "detection_rate_pct": round(self.detection_rate, 2),
                "by_category": {
                    k: {"total": v.total, "blocked": v.blocked,
                        "rate_pct": round(v.rate, 2)}
                    for k, v in self.attack_by_category.items()
                },
            },
            "negatives": {
                "total": self.negative_total,
                "flagged": self.negative_flagged,
                "clean": self.negative_total - self.negative_flagged,
                "false_positive_rate_pct": round(self.false_positive_rate, 2),
                "by_category": {
                    k: {"total": v.total, "flagged": v.blocked,
                        "fp_rate_pct": round(v.rate, 2)}
                    for k, v in self.negative_by_category.items()
                },
            },
            "overall": {
                "precision_pct": round(self.precision, 2),
                "recall_pct": round(self.recall, 2),
                "f1_pct": round(self.f1, 2),
            },
        }


def http_adapter_factory(endpoint: str, timeout: float = 10.0) -> Callable[[str], bool]:
    """Default adapter: POST {"text": text, "direction": "inbound"}, read .verdict / .blocked."""
    import urllib.request
    import urllib.error

    def classify(text: str) -> bool:
        body = json.dumps({"text": text, "direction": "inbound"}).encode("utf-8")
        req = urllib.request.Request(
            endpoint,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.URLError as e:
            print(f"warn: request failed: {e}", file=sys.stderr)
            return False
        except json.JSONDecodeError:
            return False
        verdict = str(data.get("verdict", "")).lower()
        if verdict in ("blocked", "block"):
            return True
        if data.get("blocked") is True or data.get("block") is True:
            return True
        if data.get("decision") == "block":
            return True
        return False

    return classify


def load_adapter(spec: str) -> Callable[[str], bool]:
    """Load `module.path:attr` or `module.path` (expects `classify`)."""
    if ":" in spec:
        mod_name, attr = spec.split(":", 1)
    else:
        mod_name, attr = spec, "classify"
    # Make ./adapters importable
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    mod = importlib.import_module(mod_name)
    return getattr(mod, attr)


def iter_corpus(root: Path) -> Iterable[tuple[str, Path]]:
    """Yield (category, path) for each .txt under root/<category>/*.txt."""
    for cat_dir in sorted(p for p in root.iterdir() if p.is_dir()):
        for path in sorted(cat_dir.glob("*.txt")):
            yield cat_dir.name, path


def run(classify: Callable[[str], bool], attacks_dir: Path, negatives_dir: Path,
        tool: str, endpoint: str, progress: bool = True) -> Results:
    res = Results(tool=tool, endpoint=endpoint, started_at=time.time())
    res.attack_by_category = defaultdict(CategoryStats)
    res.negative_by_category = defaultdict(CategoryStats)

    t0 = time.time()
    # Attacks
    attacks = list(iter_corpus(attacks_dir))
    for idx, (cat, path) in enumerate(attacks, 1):
        text = path.read_text(encoding="utf-8", errors="replace")
        hit = classify(text)
        res.attack_total += 1
        res.attack_by_category[cat].total += 1
        if hit:
            res.attack_blocked += 1
            res.attack_by_category[cat].blocked += 1
        if progress and idx % 50 == 0:
            print(f"  attacks {idx}/{len(attacks)}", file=sys.stderr)

    # Negatives
    negatives = list(iter_corpus(negatives_dir))
    for idx, (cat, path) in enumerate(negatives, 1):
        text = path.read_text(encoding="utf-8", errors="replace")
        hit = classify(text)
        res.negative_total += 1
        res.negative_by_category[cat].total += 1
        if hit:
            res.negative_flagged += 1
            res.negative_by_category[cat].blocked += 1
        if progress and idx % 100 == 0:
            print(f"  negatives {idx}/{len(negatives)}", file=sys.stderr)

    res.duration_sec = time.time() - t0
    # Freeze defaultdicts so to_dict serializes cleanly
    res.attack_by_category = dict(res.attack_by_category)
    res.negative_by_category = dict(res.negative_by_category)
    return res


def format_report(res: Results) -> str:
    lines = []
    lines.append(f"=== {res.tool} ===")
    lines.append(f"Endpoint:  {res.endpoint}")
    lines.append(f"Duration:  {res.duration_sec:.1f}s")
    lines.append("")
    lines.append("Attack detection by category:")
    for cat, s in sorted(res.attack_by_category.items()):
        lines.append(f"  {cat:<28} {s.blocked:>4}/{s.total:<4}  {s.rate:6.2f}%")
    lines.append("")
    lines.append("False positives by negative category:")
    for cat, s in sorted(res.negative_by_category.items()):
        lines.append(f"  {cat:<28} {s.blocked:>4}/{s.total:<4}  {s.rate:6.2f}%")
    lines.append("")
    lines.append(f"Overall attack detection:   {res.attack_blocked}/{res.attack_total}  "
                 f"{res.detection_rate:.2f}%")
    lines.append(f"Overall false-positive rate: {res.negative_flagged}/{res.negative_total}  "
                 f"{res.false_positive_rate:.2f}%")
    lines.append(f"Precision: {res.precision:.2f}%   Recall: {res.recall:.2f}%   "
                 f"F1: {res.f1:.2f}%")
    return "\n".join(lines)


def format_compare(old: dict, new: Results) -> str:
    lines = ["=== Comparison ==="]
    o = old.get("attacks", {})
    n = new.to_dict()["attacks"]
    lines.append(f"Detection: {o.get('detection_rate_pct', 0):.2f}%  ->  "
                 f"{n['detection_rate_pct']:.2f}%  "
                 f"(Δ {n['detection_rate_pct'] - o.get('detection_rate_pct', 0):+.2f})")
    ofp = old.get("negatives", {}).get("false_positive_rate_pct", 0)
    nfp = new.to_dict()["negatives"]["false_positive_rate_pct"]
    lines.append(f"FP rate:   {ofp:.2f}%  ->  {nfp:.2f}%  (Δ {nfp - ofp:+.2f})")
    of1 = old.get("overall", {}).get("f1_pct", 0)
    nf1 = new.to_dict()["overall"]["f1_pct"]
    lines.append(f"F1:        {of1:.2f}%  ->  {nf1:.2f}%  (Δ {nf1 - of1:+.2f})")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--endpoint", default="http://127.0.0.1:7749/v1/firewall/scan/full",
                    help="HTTP scan endpoint for the default adapter")
    ap.add_argument("--adapter", default=None,
                    help="Python adapter module (e.g. adapters.crawdad), defaults to built-in HTTP adapter")
    ap.add_argument("--tool", default="unknown", help="Tool name for the report")
    ap.add_argument("--attacks", default=str(DEFAULT_ATTACKS))
    ap.add_argument("--negatives", default=str(DEFAULT_NEGATIVES))
    ap.add_argument("--output", default=None, help="Write JSON results to this path")
    ap.add_argument("--compare", default=None, help="Diff results against a prior JSON file")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    if args.adapter:
        classify = load_adapter(args.adapter)
    else:
        classify = http_adapter_factory(args.endpoint)

    res = run(
        classify=classify,
        attacks_dir=Path(args.attacks),
        negatives_dir=Path(args.negatives),
        tool=args.tool,
        endpoint=args.endpoint,
        progress=not args.quiet,
    )

    print(format_report(res))

    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(res.to_dict(), indent=2))
        print(f"\nWrote {out}")

    if args.compare:
        old = json.loads(Path(args.compare).read_text())
        print()
        print(format_compare(old, res))


if __name__ == "__main__":
    main()
