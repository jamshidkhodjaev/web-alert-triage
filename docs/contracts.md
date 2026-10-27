# Input and output contracts

This application analyzes one alert and one JSONL file per run. All runtime code uses the Python standard library. The formats below describe the implemented checks; they are not claims of production detection coverage.

## Alert JSON

The input must be a UTF-8 JSON object. Unknown fields are permitted.

| Field | Type | Requirement and behavior |
| --- | --- | --- |
| `alert_id` | string | Nonblank; missing/invalid values default to `unknown-alert` with an uncertainty note. Used in the action ID. |
| `timestamp` | string | Required timezone-aware ISO 8601 value accepted by `datetime.fromisoformat`; trailing `Z` is accepted. Normalized to UTC. A missing, malformed, or naive value invalidates correlation. |
| `source_ip` | string | Required IPv4 or IPv6 address accepted by `ipaddress.ip_address`. Invalid values prevent correlation. |
| `destination_host` | string | Required nonblank host identifier. Compared case-insensitively with trailing dots removed. No DNS lookup, IDNA conversion, or host/port splitting. |
| `rule_name` | string | Nonblank; missing/invalid values default to `Unknown Rule` with an uncertainty note. Used in the action ID. |

IP comparisons canonicalize addresses, including converting IPv4-mapped IPv6 to IPv4. The original strings are preserved. The default time window is inclusive at both ends, ±5 minutes. `--window-minutes` accepts finite nonnegative numbers, including fractions and zero. Datetime/window/expiry overflow makes the alert unusable. An invalid alert or unreadable file produces `insufficient data`, no supporting references, and a null proposal. Valid log rows are still retained for inspection but labeled **unverifiable**, never correlated.

## Access-log JSONL

Each nonblank line must be one JSON object. Unknown fields are permitted.

| Field | Type | Requirement and behavior |
| --- | --- | --- |
| `record_id` | string | Required nonblank ID. Duplicates produce warnings; original IDs are not changed. |
| `timestamp` | string | Required aware ISO 8601 timestamp, normalized to UTC; never assume a timezone. |
| `source_ip` | string | Required valid IP; uses the same comparison normalization as the alert. |
| `destination_host` | string | Required nonblank host identifier; same comparison as the alert. |
| `path` | string | Required nonempty URI/path. At most two URL-decoding passes; raw and normalized values are retained. |
| `method` | string | Nonblank expected; absent/invalid values are non-blocking warnings. No restriction to a particular method vocabulary. |
| `status` | integer | Expected range 100–599; booleans are not integers for this check. Absent/invalid values are non-blocking warnings. |

Missing/invalid critical fields prevent a row from supporting a verdict. Bare percent escapes, invalid method/status, and duplicate IDs are warnings, not reasons to suppress a traversal hit. Invalid percent-encoded UTF-8 is decoded with replacement characters and flagged; the raw URI is preserved. Invalid UTF-8 or residual nested encoding of dots or either slash makes a row inconclusive when no visible traversal indicators exist. Positive correlated evidence takes precedence over separate inconclusive/corrupt rows. The heuristics do not infer request success from HTTP status.

Whitespace-only lines are skipped and counted; original one-based line numbers include those lines. Invalid JSON, non-object rows, invalid timestamps, and malformed Unicode retain their exact raw line and a diagnostic. Invalid raw UTF-8 bytes are retained using Python's surrogate-escape representation and displayed as JSON escapes. Escaped lone surrogates invalidate the entire JSON value rather than being silently deleted or used as identity/path data. Malformed alerts retain the raw input in the failure report.

The decoder caps nesting at **64 containers**, counting objects and arrays outside quoted strings, and integer literals at **4,300 digits**. Decoder `ValueError` and `RecursionError` become diagnostics; subsequent lines continue. Interpreter safety limits are not disabled. These are proportionate parsing bounds, not a total memory or input-file-size limit.

Verified correlated rows passed IP, host, timestamp/window, and critical-field validation. Other retained rows are explicitly marked `unverifiable`. Valid records outside the window are counted as excluded. In-window records with a known differing IP/host are counted as uncorrelated. Parser diagnostics remain in the report even if their known identity differs.

## Evidence references

`record_id` is preserved but is not necessarily unique. The authoritative reference is:

```text
<original record_id>@line:<one-based input line number>
```

For example, `log-006@line:6` identifies one row of the selected log file. The decision adds `supporting_evidence_refs`; each analyzed row has `evidence_ref` and `correlation_status`. The proposal adds `evidence_refs`, aligned with its legacy `evidence_ids` list. Reports display the same references. Legacy ID lists remain for compatibility, but consumers must use line-qualified references when resolving evidence. References are stable for identical input bytes; inserting or reordering lines changes them. Preserve the original log file with any exported report.

## Response proposal

`response_proposal.json` is JSON `null` unless there is valid correlated traversal evidence and a usable alert. An allowlisted IP still receives a non-null **suppressed** proposal; allowlisting does not change the triage verdict.

| Field | Type | Meaning |
| --- | --- | --- |
| `action_id` | string | SHA-256 hex digest of the UTF-8 encoding of canonical JSON containing `alert_id`, `source_ip`, `rule_name`; sorted keys, compact separators, `ensure_ascii=False`. Uses preserved alert values after documented defaults, not the normalized IP or the time window. |
| `target_ip` | string | Original alert source IP. |
| `proposed_action` | string | `block_ip`, or `none` when allowlisted. Never executed. |
| `reason` | string | States that traversal was observed and success is not established; manual review is required. |
| `evidence_ids` | list of strings | Original supporting record IDs; may repeat. |
| `evidence_refs` | list of strings | Authoritative line-qualified references, in corresponding order. |
| `expires_at` | string | UTC ISO timestamp exactly 24 hours after alert time, ending in `Z`. Not 24 hours after execution; historical alerts can yield expired proposals. |
| `allowlist_result` | string | `passed` or `suppressed`. Exact IPs only, not CIDRs; normalized IP equality includes mapped IPv6. |
| `dry_run` | boolean | Always `true`. |
| `requires_human_approval` | boolean | Always `true`. |
| `rollback_instruction` | string | Manual unblock guidance; for allowlisted sources, explicitly says no block is proposed. |

Allowed verdicts are exactly `suspicious attempt`, `no supporting evidence`, and `insufficient data`. They do not establish successful exploitation.

## CLI failures and artifact publication

- Exit **0**: triage/input-file failure reporting completed, including insufficient data. Valid invocations with unreadable or malformed input files retain the existing failure-reporting behavior; no demo dataset is substituted.
- Exit **1**: artifacts could not be prepared/published. The console reports the error and any cleanup errors. An insufficient-data verdict is not itself an execution failure.
- Exit **2**: CLI argument validation failed (for example `--allowlist-ip nope`, `--window-minutes bad`, a negative/nonfinite/out-of-range window, or a missing option value). Usage and a clear error are printed to stderr, explicitly stating that no new analysis was completed and existing outputs belong to an earlier run. No input files are loaded, no output directory is created, and no artifacts—including bundled examples—are changed. Fix the arguments before treating any output as current.
- `--help` prints help and exits 0 without performing triage or changing artifacts.

A completed run writes `report.md`, `response_proposal.json`, and **`completion.json`** in `--output-dir` (default `examples/`). The marker contains SHA-256 digests keyed by the two artifact filenames. Consumers must require the marker and verify **both** hashes before treating the pair as complete. Identical inputs/configuration and input context produce byte-identical output; no wall-clock time or random run ID is added.

Publication removes the prior completion marker and proposal before preparing output. It serializes and UTF-8-encodes both artifacts before publishing either one. Each file is written to a temporary file in the output directory, flushed/fsynced, and atomically replaced. The completion marker is replaced **last**. These replacements are **not one atomic transaction**. On any handled preparation/write/replacement error, the marker is invalidated and the proposal is removed or replaced by `null`, best effort; an old report can remain but has no valid completion marker. Temporary files are cleaned up.

If permissions, storage errors, or an interrupted process prevent cleanup, old bytes may remain. A marker/hash check establishes a consistent completed artifact pair, not proof that a newly requested invocation completed: always check that invocation's exit status and console output. Do not reuse a directory for concurrent runs. This implementation does not promise crash durability across sudden power loss or protect against another process modifying outputs. It never executes a response action.
