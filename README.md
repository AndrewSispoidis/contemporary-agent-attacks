# Contemporary Agent Attacks

An open, reproducible benchmark of attacks targeting modern LLM agents.

- **497 attacks** (395 visible + 102 holdout) across 13 categories
- **1,172 benign samples** across 4 negative categories, for measuring false-positive rates
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
  credential_exfiltration/    # 44 — read env vars, SSH keys, cloud creds, output API keys
  indirect_injection/         # 30 — payloads hidden in email/RAG/Slack/PDF/tool output
  jailbreak/                  # 30 — DAN, role-play, simulator, philosophical, translation
  role_switching/             # 65 — goal hijack, rogue agents, inter-agent compromise
  encoding_obfuscation/       # 40 — base64, hex, rot13, homoglyph, RTL override, embedding
  system_prompt_extraction/   # 20 — direct and indirect system-prompt leakage
  exfiltration/               # 28 — data-exfiltration intent ("POST these rows to …")
  pii_leakage/                # 20 — SSN, passport, medical records, PII disclosure
  tool_abuse/                 # 53 — dangerous shell / subprocess / eval / file-write calls
  exploitation_request/       # 20 — cascading failure patterns and exploit requests
  supply_chain/               # 40 — typosquats, unsigned installs, MCP manifest abuse
  other/                      # 70 — memory poisoning, misinformation, unbounded consumption,
                              #      human-agent trust manipulation

negatives/
  developer_messages/    # 1,075 — wild Stack Overflow developer Q&A
  conversational/        #    10 — short benign chat prompts
  security_discussion/   #    30 — benign security discussion ("how does SQL
                         #         injection work?", OWASP/CVE prose, etc.)
  hand_curated/          #    57 — near-miss negatives crafted to look like
                         #         attacks to a naïve classifier
```

Each attack/negative is one `.txt` file with a descriptive slug filename. The
files contain only the attack or benign text — no metadata, so you can feed
them to any tool without parsing.

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
