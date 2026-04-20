# Contributing

Thanks for your interest in improving the corpus.

## What we accept

### New attacks

Open a PR adding one `.txt` file per attack under `attacks/<category>/`
with a descriptive slug filename (e.g. `base64_encoded_exfil.txt`).

Your PR should include:

- A short note in the PR description explaining what the attack is and
  where it came from (paper, incident report, or "I made it up" — all
  three are fine if the attack is real).
- Confirmation that the payload contains **no real credentials or PII**.
  Synthetic is fine; real is a hard block.
- A category assignment (one of the 13 top-level categories — add
  `other/` if nothing else fits and explain in the PR).

We prefer attacks that are:

- **Contemporary** — targeting agents/tools/RAG, not 2023-era chatbot
  behavior.
- **Under-represented** — we have plenty of "ignore previous
  instructions" variants. An attack that adds a new category of threat
  is worth ten more of a well-covered one.
- **Reproducible** — we can understand why an agent would actually do
  the bad thing in response.

### New negatives

Same workflow under `negatives/<category>/`. The bar is higher for
negatives: we specifically want samples that are **hard for a naive
classifier to distinguish from an attack**, and real (sourced from
Stack Overflow, GitHub issues, OWASP docs, or your own org with
explicit permission).

### New adapters

Add a small Python module under `benchmark/adapters/` that exposes
`classify(text) -> bool`. See `adapters/crawdad.py` for a reference.

### New results

Add a JSON file under `benchmark/results/<tool>-<version>.json` (use
`run.py --output`) and a row to `leaderboard.md`. Include the command
you used in the PR description so the result is reproducible.

## What we reject

- Attacks copied verbatim from a licensed dataset (license issues)
- Samples containing real credentials, API keys, or PII (any amount)
- "Attacks" that are actually strongly-worded benign requests
- Duplicates of existing entries (we dedupe on exact-text match)

## Code style

The benchmark runner is intentionally simple — ~250 lines of Python
with no external dependencies. Please keep it that way. If you need a
heavy dependency (e.g. a specific LLM provider SDK) for an adapter,
isolate it to that adapter's file.

## License

By submitting, you agree your contribution is licensed under CC BY 4.0
(the same license as the corpus).
