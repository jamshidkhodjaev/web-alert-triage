# Web Triage Assistant

Web Triage Assistant correlates synthetic web alerts with access logs to produce evidence-based triage reports. It identifies suspicious path traversal attempts without automatically claiming confirmed compromise or executing response actions.

## What it does

- Reads a single alert from `fixtures/alert.json` and access records line by line from `fixtures/access_logs.jsonl`.
- Normalizes timezone-aware timestamps to UTC. Retains invalid records with diagnostics, including timestamps missing a timezone, instead of silently discarding evidence.
- Correlates logs with the alert's source IP and destination host within an inclusive time window, defaulting to **±5 minutes** around the alert timestamp.
- URL-decodes paths at most **two times**, preserves raw and normalized paths, and checks for traversal indicators in URI paths and query parameters.
- Assigns `suspicious attempt`, `no supporting evidence`, or `insufficient data`. Valid positive evidence can support an attempt verdict even when separate rows are corrupted; those rows remain visible as diagnostics.
- Generates a Markdown report and a dry-run IP-block proposal with supporting evidence IDs, a deterministic action ID, an expiry exactly 24 hours after the alert timestamp, an allowlist result, and rollback instructions. It never applies the proposed block.

## Quick start

Use Python 3.11, matching the CI configuration. From the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
python3 src/parser.py
```

The application uses the Python standard library; `requirements.txt` provides `pytest` as an optional test runner.

Choose a separate artifact directory with `--output-dir PATH` (default: `examples/`). Completed triage runs, including input failures, refresh both artifacts and a hash-based completion marker. Failed publication invalidates the marker and removes or nulls the proposal where the filesystem permits; consumers must validate the marker and check the invocation exit status. Invalid alert timestamps produce an `insufficient data` report and a null proposal. Exit code 0 means triage or input-file failure reporting completed; exit code 1 means artifacts could not be prepared or published. Invalid CLI arguments exit 2 with a clear error: no new analysis is completed, inputs are not loaded, and outputs are not changed. Any existing outputs belong to an earlier run. Invalid custom inputs never load demo evidence as a fallback.

```bash
python3 src/parser.py --output-dir /tmp/web-triage-output
```

Change the time window or specify an allowlisted IP for which no block is proposed:

```bash
python3 src/parser.py --window-minutes 1
python3 src/parser.py --allowlist-ip 192.0.2.42
```

Repeat `--allowlist-ip` to specify multiple exact IP addresses (no CIDR ranges). Allowlisting sets `allowlist_result` to `suppressed` and `proposed_action` to `none` (no block is proposed) without changing the detection verdict. Use `--alert PATH` and `--logs PATH` to supply alternate inputs.

## Example result

With the bundled fixtures, `alert-001` receives a **suspicious attempt** verdict supported by `log-006`, which requests `../../../etc/passwd` and receives HTTP 403. `log-008` is retained with a `Missing Timezone` diagnostic and cannot be reliably placed within the correlation window.

Each completed run updates:

- [`examples/report.md`](examples/report.md): executive summary, triage verdict, correlated evidence table, retained diagnostics, and limitations and uncertainties.
- [`examples/response_proposal.json`](examples/response_proposal.json): a `block_ip` proposal for `192.0.2.42`, supported by `log-006`, with `dry_run: true` and `requires_human_approval: true`. The reason explicitly states that request success is not established and requires manual review. Its action ID is stable for the same alert ID, source IP, and rule name. The fixture's expiry is `2026-10-28T12:02:30Z`.
- [`examples/completion.json`](examples/completion.json): SHA-256 hashes of both artifacts, published last. These separate replacements are not one atomic transaction.

Supporting references now include input line numbers, such as `log-006@line:6`, to disambiguate duplicate record IDs. Proposals preserve `evidence_ids` and add authoritative `evidence_refs`.

When there is no supported traversal attempt, the proposal file contains JSON `null`, replacing any previous proposal. No firewall or WAF changes are made.

## Validation

Run the test suite from the repository root:

```bash
python3 -m unittest discover -s tests -v
```

The 74 tests cover single and double URL encoding, the two-pass ceiling, backslash and terminal traversal segments, benign lookalikes, malformed escapes and UTF-8, UTC offsets and window boundaries, IP/host correlation and IPv4-mapped IPv6, retained corrupt rows and skipped blanks, stable action IDs that change with each identity field, exact 24-hour expiry after UTC normalization, deterministic artifacts, allowlist suppression, null proposals, alert defaults, CLI failure handling, stale-file replacement, Markdown escaping, and the verdict invariant. Additional review regressions cover custom input failures, unverifiable correlation, lone surrogates, duplicate IDs, excessive nesting and integers, residual backslash encoding, completion hashes, and injected preparation/replacement failures. They use temporary files and leave the bundled fixtures unchanged. Targeted mutation checks were also performed: increasing decoding from two to three passes and expiry from 24 to 48 hours each caused its regression test to fail; both mutations were restored.

GitHub Actions runs the tests and the end-to-end parser on Ubuntu with Python 3.11 for pushes to `main` and pull requests targeting `main`. CI generates artifacts in a temporary directory and diffs all three files against the working-tree examples.

## Contracts and failure behavior

See [docs/contracts.md](docs/contracts.md) for field types and validation, timestamp/IP/host normalization, evidence references, proposal fields, parsing bounds, exit codes, and artifact publication semantics. JSON nesting is capped at 64 containers and integer literals at 4,300 digits. Invalid rows retain escaped original evidence and processing continues.

## Limitations

- A keyword or traversal-pattern match does not establish successful exploitation. Neither HTTP **200** nor **403** proves whether a payload executed; application layer payload execution requires manual inspection.
- URL decoding is bounded to two passes. Invalid UTF-8 or deeper-than-two-pass encodings can hide traversal and yield `insufficient data`; application-specific parsing and other attack types may not be detected. Visible positive traversal evidence takes precedence over encoding uncertainty. A bare percent sign alone is a warning, not grounds for an inconclusive verdict.
- Reverse proxies, CDNs, NAT, and unverified `X-Forwarded-For` values can make `source_ip` unreliable. This tool does not resolve trusted proxy chains.
- Pattern matching can produce false positives, including legitimate requests containing traversal-like text. A human must review context before responding.
- The tool analyzes one alert per run; it does not aggregate incidents or track activity across alerts.
- Corrupt non-blank lines can force `insufficient data` when no positive evidence exists. Whitespace-only lines are skipped and counted; invalid records retain their raw lines and diagnostics.
- Missing or corrupted critical fields limit correlation. Invalid timestamps are retained as diagnostics rather than assigned an assumed timezone.
- IP, host, and time proximity provide correlation, not attribution or proof of causation. An IP address does not identify an individual.
- The fixtures are synthetic. These results demonstrate triage behavior, not production detection coverage. Response proposals are for review only, and the tool never automatically assigns `confirmed compromise`.
- Permission or storage failures can prevent cleanup; check exit status and completion hashes rather than trusting an old file. Use a separate output directory per concurrent run. No total file-size or memory limit is enforced.
