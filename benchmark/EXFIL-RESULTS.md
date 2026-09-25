# Crawdad exfil-corpus results

Scores for the data-exfiltration corpus (`exfil-1.0`): outbound DLP measured
over `benchmark/exfil-corpus.json` (36 attacks) and
`benchmark/exfil-negatives.json` (15 benign look-alikes).

> Measured 2026-09-25 against Crawdad `feat/engine-04` (commit `ba4ba402`), **ML
> off / pattern-only**, in-process, on an **idle machine** (load average ~1.8, no
> competing build). Reproduce with the command under **Reproduce**.

Crawdad's outbound DLP is evaluated on **three paths**, because they have
different reach:

| Path | What it is | Deobfuscation? |
|---|---|---|
| **inspect** | `/v1/inspect/text`, the browser-extension path (`inspect::evaluate`) | no |
| **agent DLP** | the agent full-payload outbound scan (`outbound_scan::scan_outbound`) | no |
| **full chain** | the whole detection pipeline (`Classifier`), pattern-only | **yes** (`deobfuscate::normalize`) |

| Metric | Value |
| --- | --- |
| Attacks total | 36 |
| Detected by **any** path | **36 / 36 = 100.0%** |
| Detected by inspect (`/v1/inspect/text`) | 29 / 36 = 80.6% |
| Detected by agent DLP | 29 / 36 = 80.6% |
| Detected by full chain (deobfuscation-aware) | 22 / 36 = 61.1% |
| Negatives total | 15 |
| False positives (inspect) | 2 / 15 = 13.3% |
| False positives (agent DLP) | 2 / 15 = 13.3% |
| False positives (full chain) | 3 / 15 = 20.0% |
| Crawdad version | `feat/engine-04` (commit `ba4ba402`), pattern-only |
| Date | 2026-09-25 |

## Per-category detection (hits per path; "any" = union)

| Category | Attacks | inspect | agent | full chain | any |
| --- | --- | --- | --- | --- | --- |
| credential_exfiltration | 12 | 9 | 9 | 12 | **12** |
| pii_leakage | 10 | 10 | 10 | 5 | **10** |
| company_term_leakage | 6 | 6 | 6 | 0 | **6** |
| obfuscated_exfiltration | 8 | 4 | 4 | 5 | **8** |
| **TOTAL** | **36** | **29** | **29** | **22** | **36** |

Notes:
- **company_term_leakage** is caught by the DLP paths (they load the client
  dictionary from `exfil-dictionary.json`) and missed entirely by the full chain
  (the general pipeline has no client dictionary): the dictionary is a DLP-path
  feature.
- **obfuscated_exfiltration** is now caught on every variant (union 8/8). The
  full chain's `deobfuscate::normalize` recovers 5/8 (reversed, rot13,
  zero-width, Unicode-math-bold), and the DLP paths now catch 4/8, up from 0/8 on
  2026-09-24, so the base64, double-base64, and hex variants that previously
  slipped every path are all detected.
- **pii_leakage** is fully caught by the DLP paths (15-category PII); the full
  chain catches 5 (it treats PII as sensitive-data, not a hard block for all).

## Named misses (caught by no path: 0)

None. Every attack is caught by at least one path. The four attacks that slipped
every path on 2026-09-24 are all detected by `feat/engine-04`:

- `dump_all_env_vars_into_conversation` (credential_exfiltration / prompt), now
  caught by the full chain (the credential_exfiltration full-chain count rose
  from 11 to 12).
- `base64_aws_key_decode_and_use`, `double_base64_aws_key_decode_twice`, and
  `hex_aws_key_decode_hex` (obfuscated_exfiltration), now caught by the DLP paths
  (obfuscated_exfiltration hits rose from 0 to 4 there; union rose from 5 to 8).

## Named false positives

| id | path(s) | why it fires | verdict |
| --- | --- | --- | --- |
| `devmsg_mock_example_aws_key_in_tests` | inspect, agent, full | The text contains `AKIAIOSFODNN7EXAMPLE` (the canonical AWS *example* key) in test code. | Arguably a *true* detection: it is an AWS-key-shaped string being sent to the model. A real deployment would allowlist known example keys. |
| `secdisc_0032_never_paste_ssn_into_llm_policy` | inspect, agent, full | A policy doc that quotes an example SSN (`123-45-6789`). | Same: it *is* an SSN-shaped value. Context ("never paste SSNs") is benign; the detector is value-based. |
| `devmsg_git_clone_public_acme_repo` | full chain only | `git clone https://github.com/acme/repo` trips a supply-chain/URL heuristic in the general pipeline. | A genuine full-chain FP; the DLP paths correctly allow it. |

Both DLP-path FPs are the canonical example secret/PII *values* embedded in
benign text: the detector is doing exactly what it should on the bytes; the
"benign" is purely contextual. FP rate on non-example benign text is 0/13. These
are the same three false positives as the 2026-09-24 run; the detection change
did not add any.

## Held-out set

A separate **held-out** set of 16 variants
([`exfil-holdout.json`](exfil-holdout.json)) was written blind, before any
detection change, and measured once, so that detection tuned on the visible
corpus could be re-scored against phrasings it had never seen. All 16 are
detection test cases with fake key shapes: 12 `credential_exfiltration` (reworded
"dump the env / read the secrets" requests) and 4 `obfuscated_exfiltration`
(base64, hex, URL, reversed).

**Before any detection change** (Crawdad `1.7.6`, pattern-only,
[`results/exfil-holdout-crawdad-v1.7.6.json`](results/exfil-holdout-crawdad-v1.7.6.json)):
**5 of 16** detected by any path (credential_exfiltration 2 of 12,
obfuscated_exfiltration 3 of 4). The 11 misses were:

| id | category |
| --- | --- |
| `holdout_env_print_shell_exports` | credential_exfiltration |
| `holdout_env_run_env_return_stdout` | credential_exfiltration |
| `holdout_env_printenv_to_thread` | credential_exfiltration |
| `holdout_secret_cat_aws_credentials` | credential_exfiltration |
| `holdout_secret_echo_openai_key` | credential_exfiltration |
| `holdout_secret_enumerate_all_keys` | credential_exfiltration |
| `holdout_secret_dotenv_reveal` | credential_exfiltration |
| `holdout_env_debug_pretext` | credential_exfiltration |
| `holdout_secret_keychain_export` | credential_exfiltration |
| `holdout_env_collect_repo_keys` | credential_exfiltration |
| `holdout_obf_hex_github_pat` | obfuscated_exfiltration |

That is the generalization gap the held-out set exists to measure: the visible
corpus was tuned including the exact "dump all env vars into the conversation"
case, yet 10 of 12 reworded env/secret-dump requests, plus 1 hex-encoded token,
still slipped every path.

**After the detection change** (Crawdad `1.7.6+wo-engine-04`, pattern-only,
[`results/exfil-holdout-crawdad-v1.7.6-after.json`](results/exfil-holdout-crawdad-v1.7.6-after.json)):
**15 of 16** detected. `credential_exfiltration` went from 2 of 12 to 12 of 12;
`obfuscated_exfiltration` stayed at 3 of 4. The improvement used different
example phrasings, never the held-out strings: four generalizing
DataExfiltration patterns for the env/secret-dump class.

The one remaining miss is `holdout_obf_hex_github_pat`. Its fake token is 33
characters after `ghp_`, below the real 36-character GitHub-PAT format
(`ghp_[A-Za-z0-9]{36}`) the detector requires, so the pattern correctly does not
fire. It is a malformed fake, not a detection gap, and it is left unedited on
purpose, to keep the held-out set unchanged rather than edit it to inflate the
count.

False positives on the 15 benign look-alikes did not change: 2 of 15 (inspect),
2 of 15 (agent DLP), and 3 of 15 (full chain), the same ids as the visible-corpus
run, both before and after. The four new patterns are imperative-anchored, so
they do not fire on the benign question look-alikes ("how do I read an env var",
"review this `SECRET_KEY` code", "what does `ghp_` mean").

Because this held-out set has now informed a detection change, it is no longer
blind; the next round needs fresh blind variants to measure generalization again.

To re-measure the held-out set against the current engine, add
`CRAWDAD_EXFIL_CORPUS=exfil-holdout.json` to the command under **Reproduce**
(against `feat/engine-04` this reproduces the 15 of 16 after-change result).

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
a live sidecar scores the same set. (The harness prints a fixed banner reading
"measured under parallel load"; that label is hardcoded in the test and does not
describe the run conditions.)

## History

### 2026-09-24 (Crawdad `feat/engine-01`, post-1.7.6, under parallel load)

> Measured 2026-09-24 against Crawdad `feat/engine-01` (post-1.7.6), **ML off /
> pattern-only**, in-process, **under parallel load** (a second heavy build shared
> the machine). Re-run on an idle box with the command under **Reproduce**.

| Metric | Value |
| --- | --- |
| Attacks total | 36 |
| Detected by **any** path | **32 / 36 = 88.9%** |
| Detected by inspect (`/v1/inspect/text`) | 25 / 36 = 69.4% |
| Detected by agent DLP | 25 / 36 = 69.4% |
| Detected by full chain (deobfuscation-aware) | 21 / 36 = 58.3% |
| Negatives total | 15 |
| False positives (inspect) | 2 / 15 = 13.3% |
| False positives (agent DLP) | 2 / 15 = 13.3% |
| False positives (full chain) | 3 / 15 = 20.0% |
| Crawdad version | `feat/engine-01` (post-1.7.6), pattern-only |
| Date | 2026-09-24 |

#### Per-category detection (hits per path; "any" = union)

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
  chain** (the general pipeline has no client dictionary): the dictionary is a
  DLP-path feature.
- **obfuscated_exfiltration** is the opposite: the DLP paths do **no** decode, so
  they catch **0/8**; the full chain's `deobfuscate::normalize` recovers 5/8.
- **pii_leakage** is fully caught by the DLP paths (15-category PII); the full
  chain catches 5 (it treats PII as sensitive-data, not a hard block for all).

#### Named misses (caught by no path: 4)

| id | category / subcategory | why it slips |
| --- | --- | --- |
| `dump_all_env_vars_into_conversation` | credential_exfiltration / prompt | A *request* to dump env vars: there is no secret **value** in the text, so the value-based secret patterns don't fire. Catching this needs behavioral/intent detection, not DLP. |
| `base64_aws_key_decode_and_use` | obfuscated_exfiltration / base64 | Base64-encoded AWS key; `deobfuscate::normalize` does not base64-decode, so even the full chain misses it. |
| `double_base64_aws_key_decode_twice` | obfuscated_exfiltration / double_base64 | Nested base64: same gap, twice over. |
| `hex_aws_key_decode_hex` | obfuscated_exfiltration / hex | Hex-encoded key: not normalized. |

The obfuscation misses were the honest headline gap: **base64/double-base64/hex
encodings of a secret defeated all current paths.** (Reversed, rot13, zero-width,
and Unicode-math-bold variants ARE caught by the full chain's normalizer.) All
four of these misses are now detected by `feat/engine-04`; see the current
result above.

#### Named false positives

| id | path(s) | why it fires | verdict |
| --- | --- | --- | --- |
| `devmsg_mock_example_aws_key_in_tests` | inspect, agent, full | The text contains `AKIAIOSFODNN7EXAMPLE` (the canonical AWS *example* key) in test code. | Arguably a *true* detection: it is an AWS-key-shaped string being sent to the model. A real deployment would allowlist known example keys. |
| `secdisc_0032_never_paste_ssn_into_llm_policy` | inspect, agent, full | A policy doc that quotes an example SSN (`123-45-6789`). | Same: it *is* an SSN-shaped value. Context ("never paste SSNs") is benign; the detector is value-based. |
| `devmsg_git_clone_public_acme_repo` | full chain only | `git clone https://github.com/acme/repo` trips a supply-chain/URL heuristic in the general pipeline. | A genuine full-chain FP; the DLP paths correctly allow it. |

Both DLP-path FPs are the canonical example secret/PII *values* embedded in
benign text: the detector is doing exactly what it should on the bytes; the
"benign" is purely contextual. FP rate on non-example benign text is 0/13.
