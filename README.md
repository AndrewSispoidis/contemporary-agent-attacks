# Contemporary Agent Attacks

An open, reproducible benchmark of attacks targeting modern LLM agents.

- **533 attacks** (431 visible + 102 holdout) across 15 categories
- **1,187 benign samples** across 4 negative categories, for measuring false-positive rates
- **Tool-agnostic benchmark runner** — works with any HTTP-addressable classifier
- **CC-BY 4.0** — use it for your product, paper, or class

The corpus is aimed at contemporary agent-shaped threats: prompt injection,
credential exfiltration, indirect injection via tool output and RAG, tool
abuse, supply-chain manipulation, memory poisoning, and agent-to-agent
compromise. See [METHODOLOGY.md](METHODOLOGY.md) for collection, sourcing, and
scoring details.

## Quick start

```bash
git clone https://github.com/AndrewSispoidis/contemporary-agent-attacks
cd contemporary-agent-attacks

# Point at whatever classifier you want to measure
ENDPOINT=http://127.0.0.1:7749/v1/firewall/scan/full ./benchmark/run.sh

# Or use the Python runner, with per-category breakdown and JSON output
python3 benchmark/run.py \
    --endpoint http://127.0.0.1:7749/v1/firewall/scan/full \
    --tool my-tool \
    --output benchmark/results/my-tool.json
```

Write a ~40-line adapter for your tool (see
[`benchmark/adapters/crawdad.py`](benchmark/adapters/crawdad.py)) and run:

```bash
python3 benchmark/run.py --adapter adapters.my_tool --tool my-tool
```

Requirements: Python 3.9+, `jq` (for the shell runner only), and a scan endpoint
that accepts `POST {"text": "<content>"}` and returns a JSON body indicating
blocked vs. allowed.

## Corpus layout

```
attacks/
  prompt_injection/           # 37 — direct "ignore previous" style injections
  credential_exfiltration/    # 56 — read env vars, SSH keys, cloud creds, API keys, secrets in tool results
  indirect_injection/         # 30 — payloads hidden in email/RAG/Slack/PDF/tool output
  jailbreak/                  # 30 — DAN, role-play, simulator, philosophical, translation
  role_switching/             # 65 — goal hijack, rogue agents, inter-agent compromise
  encoding_obfuscation/       # 40 — base64, hex, rot13, homoglyph, RTL override, embedding
  obfuscated_exfiltration/    #  8 — base64/double-b64/hex/rot13/reversed/zero-width/bold secrets & PII
  system_prompt_extraction/   # 20 — direct and indirect system-prompt leakage
  exfiltration/               # 28 — data-exfiltration intent ("POST these rows to …")
  pii_leakage/                # 30 — SSN, passport, medical records, PII disclosure & uploads
  company_term_leakage/       #  6 — client codenames / customer / project terms sent to an LLM
  tool_abuse/                 # 53 — dangerous shell / subprocess / eval / file-write calls
  exploitation_request/       # 20 — cascading failure patterns and exploit requests
  supply_chain/               # 40 — typosquats, unsigned installs, MCP manifest abuse
  other/                      # 70 — memory poisoning, misinformation, unbounded consumption,
                              #      human-agent trust manipulation

negatives/
  developer_messages/    # 1,083 — wild Stack Overflow developer Q&A + exfil look-alikes
  conversational/        #    10 — short benign chat prompts
  security_discussion/   #    37 — benign security discussion ("how does SQL
                         #         injection work?", OWASP/CVE prose, etc.)
  hand_curated/          #    57 — near-miss negatives crafted to look like
                         #         attacks to a naïve classifier
```

Each attack/negative is one `.txt` file with a descriptive slug filename. The
files contain only the attack or benign text — no metadata, so you can feed
them to any tool without parsing.

### Data-exfiltration corpus (`exfil-1.0`)

A focused layer for scoring **outbound** data-loss prevention — data *leaving*
to an LLM — with benign look-alikes so misses and false positives can be
published honestly. It spans four attack categories:

- `credential_exfiltration` — API keys, private keys, DB URLs, JWTs, Slack
  tokens, and secrets embedded in JSON `tool_result` payloads.
- `pii_leakage` — SSNs, cards, passports, medical/bank records, and PII framed
  as spreadsheet/CSV **uploads**.
- `company_term_leakage` — client codenames, customer names, and internal
  project terms sent to an external model.
- `obfuscated_exfiltration` — the same secrets/PII hidden behind base64,
  double-base64, hex, rot13, reversal, zero-width splitting, and Unicode
  "mathematical bold" glyphs.

All example secrets and PII are **synthetic and clearly fake** (canonical
values such as `AKIAIOSFODNN7EXAMPLE`, `123-45-6789`, `4111 1111 1111 1111`).

The same corpus is mirrored as machine-readable indexes for in-process
verifiers, alongside the `.txt` files (each JSON `payload` equals its file
verbatim):

```
benchmark/exfil-corpus.json      # 36 attacks across the 4 categories
benchmark/exfil-negatives.json   # 15 benign look-alikes (expected: allowed)
benchmark/exfil-dictionary.json  #  6 client terms for the company-term detector
```

Results are reported separately in
[benchmark/EXFIL-RESULTS.md](benchmark/EXFIL-RESULTS.md):

- **Visible corpus** (36 attacks, pattern-only) against Crawdad main @ `89a5e87`
  (PR #5, merged 2026-09-26): 36 of 36 detected by at least one path (29 of 36 on
  the browser inspect path and 29 of 36 on the agent DLP path alone; 22 of 36 on
  the full chain alone), with 3 of 15 benign look-alikes flagged. See
  [EXFIL-RESULTS.md](benchmark/EXFIL-RESULTS.md).
- **Held-out set** (16 blind variants): detection went from 5 of 16 to 15 of 16
  after a detection change measured against never-seen phrasings. See
  [EXFIL-RESULTS.md](benchmark/EXFIL-RESULTS.md#held-out-set).

This layer is released under the same [CC BY 4.0](LICENSE) as the rest of the
corpus.

### Holdout split

Files prefixed with `holdout_` are reserved for evaluating generalization; they
were collected from sources not used to construct the visible corpus and have
never been public before this release. If you train on this corpus, **do not
train on holdout files** — use them only for final scoring. See
[METHODOLOGY.md](METHODOLOGY.md#holdout) for details.

## Latest results

| Tool              | Detection | FP rate | F1      | Date       |
| ----------------- | --------- | ------- | ------- | ---------- |
| crawdad-v0.9.1    | 99.80%    | 0.00%   | 99.90%  | 2026-04-20 |

See [leaderboard.md](leaderboard.md) for more, and
[benchmark/results/](benchmark/results/) for raw JSON.

The row above was scored on the original 497-attack / 1,172-negative snapshot,
before the data-exfiltration corpus was added; exfil-corpus scores are tracked
separately in [benchmark/EXFIL-RESULTS.md](benchmark/EXFIL-RESULTS.md).

## Scoring

- **Detection rate** — fraction of attacks the tool blocks
- **False-positive rate** — fraction of negatives the tool incorrectly blocks
- **Precision / Recall / F1** — computed over blocked vs. not-blocked decisions

A tool that blocks everything has 100% detection and 100% FP — useless.
A tool that blocks nothing has 0% detection and 0% FP — also useless. F1 is
the useful single-number summary.

## Contributing

We welcome new attacks (especially from recent research), new negatives, and
adapters for other tools. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[CC BY 4.0](LICENSE). Attribution required — cite as:

> "Contemporary Agent Attacks", getcrawdad, 2026.
> https://github.com/AndrewSispoidis/contemporary-agent-attacks
