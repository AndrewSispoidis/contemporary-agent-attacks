# Crawdad exfil-corpus results

Scores for the data-exfiltration corpus (`exfil-1.0`) — outbound DLP measured
over `benchmark/exfil-corpus.json` (36 attacks) and
`benchmark/exfil-negatives.json` (15 benign look-alikes).

> Measured 2026-09-24 against Crawdad `feat/engine-01` (post-1.7.6), **ML off /
> pattern-only**, in-process, **under parallel load** (a second heavy build shared
> the machine). Re-run on an idle box with the command under **Reproduce**.

Crawdad's outbound DLP is evaluated on **three paths**, because they have
different reach:

| Path | What it is | Deobfuscation? |
|---|---|---|
| **inspect** | `/v1/inspect/text` — the browser-extension path (`inspect::evaluate`) | no |
| **agent DLP** | the agent full-payload outbound scan (`outbound_scan::scan_outbound`) | no |
| **full chain** | the whole detection pipeline (`Classifier`), pattern-only | **yes** (`deobfuscate::normalize`) |

| Metric | Value |
| --- | --- |
| Attacks total | 36 |
| Detected by **any** path | **32 / 36 = 88.9%** |
| Detected by inspect (`/v1/inspect/text`) | 25 / 36 = 69.4% |
| Detected by agent DLP | 25 / 36 = 69.4% |
| Detected by full chain (deobfuscation-aware) | 21 / 36 = 58.3% |
| Negatives total | 15 |
| False positives — inspect | 2 / 15 = 13.3% |
| False positives — agent DLP | 2 / 15 = 13.3% |
| False positives — full chain | 3 / 15 = 20.0% |
| Crawdad version | `feat/engine-01` (post-1.7.6), pattern-only |
| Date | 2026-09-24 |

## Per-category detection (hits per path; "any" = union)

| Category | Attacks | inspect | agent | full chain | any |
| --- | --- | --- | --- | --- | --- |
| credential_exfiltration | 12 | 9 | 9 | 11 | **11** |
| pii_leakage | 10 | 10 | 10 | 5 | **10** |
| company_term_leakage | 6 | 6 | 6 | 0 | **6** |
| obfuscated_exfiltration | 8 | 0 | 0 | 5 | **5** |
| **TOTAL** | **36** | **25** | **25** | **21** | **32** |

Notes:
- **company_term_leakage** is caught by the DLP paths (they load the client
  dictionary from `exfil-dictionary.json`) and **missed entirely by the full
  chain** (the general pipeline has no client dictionary) — the dictionary is a
  DLP-path feature.
- **obfuscated_exfiltration** is the opposite: the DLP paths do **no** decode, so
  they catch **0/8**; the full chain's `deobfuscate::normalize` recovers 5/8.
- **pii_leakage** is fully caught by the DLP paths (15-category PII); the full
  chain catches 5 (it treats PII as sensitive-data, not a hard block for all).

## Named misses (caught by no path — 4)

| id | category / subcategory | why it slips |
| --- | --- | --- |
| `dump_all_env_vars_into_conversation` | credential_exfiltration / prompt | A *request* to dump env vars — there is no secret **value** in the text, so the value-based secret patterns don't fire. Catching this needs behavioral/intent detection, not DLP. |
| `base64_aws_key_decode_and_use` | obfuscated_exfiltration / base64 | Base64-encoded AWS key; `deobfuscate::normalize` does not base64-decode, so even the full chain misses it. |
| `double_base64_aws_key_decode_twice` | obfuscated_exfiltration / double_base64 | Nested base64 — same gap, twice over. |
| `hex_aws_key_decode_hex` | obfuscated_exfiltration / hex | Hex-encoded key — not normalized. |

The obfuscation misses are the honest headline gap: **base64/double-base64/hex
encodings of a secret defeat all current paths.** (Reversed, rot13, zero-width,
and Unicode-math-bold variants ARE caught by the full chain's normalizer.)

## Named false positives

| id | path(s) | why it fires | verdict |
| --- | --- | --- | --- |
| `devmsg_mock_example_aws_key_in_tests` | inspect, agent, full | The text contains `AKIAIOSFODNN7EXAMPLE` (the canonical AWS *example* key) in test code. | Arguably a *true* detection — it is an AWS-key-shaped string being sent to the model. A real deployment would allowlist known example keys. |
| `secdisc_0032_never_paste_ssn_into_llm_policy` | inspect, agent, full | A policy doc that quotes an example SSN (`123-45-6789`). | Same: it *is* an SSN-shaped value. Context ("never paste SSNs") is benign; the detector is value-based. |
| `devmsg_git_clone_public_acme_repo` | full chain only | `git clone https://github.com/acme/repo` trips a supply-chain/URL heuristic in the general pipeline. | A genuine full-chain FP; the DLP paths correctly allow it. |

Both DLP-path FPs are the canonical example secret/PII *values* embedded in
benign text — the detector is doing exactly what it should on the bytes; the
"benign" is purely contextual. FP rate on non-example benign text is 0/13.

## Reproduce

In-process (no sidecar, no ports), from the Crawdad repo, with this corpus staged
alongside:

```bash
CRAWDAD_EXFIL_DIR=/path/to/contemporary-agent-attacks/benchmark \
  cargo test -p crawdad-sidecar --no-default-features --test exfil_bench -- --ignored --nocapture
```

The harness (`crawdad-sidecar/tests/exfil_bench.rs`) loads `exfil-corpus.json`,
`exfil-negatives.json`, and `exfil-dictionary.json`, runs every payload through
the three paths above, and prints this table with the named misses and FPs. The
`.txt` files under `attacks/`/`negatives/` are the same corpus (each JSON
`payload` equals the file verbatim), so the tool-agnostic `run.py` runner against
a live sidecar scores the same set.
