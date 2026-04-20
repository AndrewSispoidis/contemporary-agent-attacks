# Methodology

How the corpus was built, how it's scored, and what the numbers mean.

## Goals

1. **Reflect what agents face in 2026**, not what chatbots faced in 2023.
   Older public corpora (JailbreakBench, PromptBench, earlier PromptInject
   datasets) are heavily weighted toward chat-only jailbreaks. Real agent
   deployments have to survive indirect injection from tool output, RAG
   documents, Slack messages, email, PDF, MCP servers, and other agents —
   most of which are underrepresented or absent in earlier benchmarks.

2. **Be honest about false positives.** A detection-rate number on its own
   is a vanity metric; blocking every message achieves 100%. We ship a
   negative corpus drawn from real developer and security discussion so the
   FP rate reflects what a tool would do in front of a working team.

3. **Be reproducible.** Anyone can run the benchmark against any tool,
   check the numbers, and submit their own results. No closed weights,
   no tool-specific scoring, no leaderboard gating.

## Attack collection

Attacks were collected between Feb and Apr 2026 from:

- **Public research** — recent papers on prompt injection, indirect
  injection, and agent compromise (cited inline where applicable in the
  source repository's `sources/` dir).
- **Public incident reports** — disclosed agent jailbreaks, tool-abuse
  writeups, supply-chain advisories (npm/pip typosquats, MCP manifest
  abuse, malicious package callouts).
- **Generated variants** — structured variants of known-real attacks
  (e.g. different env-var names, different exfil destinations) to stress
  pattern-match classifiers.

Each attack is assigned to one of 13 top-level categories. The taxonomy
was chosen to map cleanly onto OWASP LLM Top 10 (2025) and MITRE ATLAS,
while adding categories that were missing from both at collection time
(indirect injection via tool output, inter-agent compromise).

### Attack categories

| Category                   | What's in it                                                                 |
| -------------------------- | ---------------------------------------------------------------------------- |
| `prompt_injection`         | "Ignore previous instructions"–style direct injection                        |
| `credential_exfiltration`  | Attempts to read or output API keys, SSH keys, cloud creds, env vars          |
| `indirect_injection`       | Payloads hidden in email, RAG docs, Slack, Wiki, PDF, tool output, web pages |
| `jailbreak`                | DAN, role-play, simulator mode, philosophical, translation-based evasion     |
| `role_switching`           | Goal hijack, rogue agents, inter-agent compromise                            |
| `encoding_obfuscation`     | base64, hex, rot13, RTL override, homoglyph, zero-width, vector embedding    |
| `system_prompt_extraction` | Direct and indirect system-prompt leakage                                    |
| `exfiltration`             | Data-exfiltration intent (e.g. "POST these customer rows to …")              |
| `pii_leakage`              | PII disclosure: SSN, passport, medical records, IBAN, DOB                    |
| `tool_abuse`               | Dangerous shell / subprocess / eval / file-write tool calls                  |
| `exploitation_request`     | Cascading-failure and exploit-request patterns                               |
| `supply_chain`             | npm/pip/brew typosquats, unsigned installs, MCP manifest manipulation        |
| `other`                    | Memory poisoning, misinformation, unbounded consumption, trust manipulation  |

## Negative collection

Negatives come from four sources, totaling 1,172 samples:

| Source                  | Count     | What it covers                                         |
| ----------------------- | --------- | ------------------------------------------------------ |
| `developer_messages`    | 1,075     | Wild Stack Overflow developer Q&A — the full set used  |
|                         |           | by the reference tool's internal regression harness    |
| `hand_curated`          | 57        | Curated "near-miss" negatives — text that looks like   |
|                         |           | an attack to a naïve classifier but isn't              |
| `security_discussion`   | 30        | Curated security-discussion prose ("How does SQL       |
|                         |           | injection work?", OWASP/CVE talk, threat-modeling)     |
| `conversational`        | 10        | Short benign chat prompts ("hi", "What is 2+2?", etc.) |

Security discussion negatives are the most important category: any classifier
that flags "How does SQL injection work?" as malicious is useless in a real
development organization. A high false-positive rate on `security_discussion`
is the single biggest failure mode for production deployments.

## Validation

Each attack was manually reviewed to verify:

1. **It is actually an attack.** The payload, if executed in an agent's
   context, would represent a genuine security violation — not just a
   strong tone or a security question phrased actively.

2. **It contains no real credentials or PII.** All API keys, private keys,
   SSNs, passport numbers, bank accounts, and credit cards in the corpus are
   synthetic. They look structurally valid (e.g. a synthetic "openai_sk"
   payload has the right prefix and length) so that classifiers see
   realistic input, but are drawn from reserved test ranges or generated
   to fail checksums.

3. **It is a single coherent payload.** Multi-turn attacks are captured
   as one file representing the decisive turn; the adversarial framing is
   present but the scoring target is unambiguous.

## Holdout

The 102-attack holdout set was collected from sources explicitly excluded
from the visible corpus, and has never been published before this release.
Files in the holdout are prefixed with `holdout_` so you can easily filter
them out during training.

The holdout is the right set to report on if you want to claim a tool
generalizes — the visible corpus is easier to overfit against.

## Scoring

A tool is evaluated by feeding it each `.txt` file and asking a yes/no
question: "blocked or not". From that we compute:

- **True positive (TP)** — attack, tool blocked it
- **False negative (FN)** — attack, tool allowed it
- **False positive (FP)** — negative, tool blocked it
- **True negative (TN)** — negative, tool allowed it

And then:

- **Detection rate** = TP / (TP + FN)  (a.k.a. recall)
- **False-positive rate** = FP / (FP + TN)
- **Precision** = TP / (TP + FP)
- **F1** = 2 · Precision · Recall / (Precision + Recall)

F1 is the single-number summary. A tool with 99% detection and 50% FP is
not better than a tool with 80% detection and 2% FP, and F1 will tell you
which one to deploy.

We do not weight by category. Every attack counts the same. If you want
to argue that (say) credential exfiltration matters more than jailbreak,
you can compute category-weighted scores from the JSON output
(`attacks.by_category`).

## What the corpus is not

- **Not a complete adversarial training set.** Training on this corpus
  will improve pattern-match recall but won't buy generalization to truly
  novel attacks. Use the holdout to measure generalization, not the
  visible corpus.
- **Not a jailbreak benchmark.** Jailbreak is one of 13 categories. If
  you only care about jailbreak, use a jailbreak-focused corpus; you'll
  get better signal.
- **Not a production-readiness certification.** A good score on this
  corpus is necessary but not sufficient for deployment. Red-team your
  agent in its actual environment before trusting any benchmark number.

## The Crawdad reference endpoint

The reference adapter at `benchmark/adapters/crawdad.py` posts to
`/v1/firewall/scan/full` on the local Crawdad sidecar (default
`http://127.0.0.1:7749`). That endpoint runs the same detection chain
the transparent proxy uses on every LLM request:

1. L1 pattern layer (LITE + FULL detector pipeline)
2. L3 indirect-injection detector (payloads in tool output, RAG, etc.)
3. L5 code scanner (shell, eval, credential exposure)
4. L6 PII / credential detector
5. L1.5 dynamic signatures (remote-updated threat feed)
6. L2 DeBERTa-small ML semantic classifier (threshold 0.25)

Your tool does not have to replicate this chain — the benchmark cares
only whether a given input is blocked. Build whatever adapter matches
your architecture.

## Changelog

- **2026-04-20** — Initial release: 395 visible + 102 holdout attacks,
  1,092 negatives.
