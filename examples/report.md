# Web Triage Report

Artifact set is complete only when completion.json matches the SHA-256 hashes of both output files.

## Executive Summary

Alert **alert-001** — Suspicious URI Pattern.

Source: 192.0.2.42; destination: web.example.test.

Alert time: 2026-10-27T12:02:30+00:00. Inclusive window: 2026-10-27T11:57:30+00:00 to 2026-10-27T12:07:30+00:00.

3 valid correlated records; 1 unverifiable records retained; 1 retained diagnostic records; 0 valid records outside the time window.

0 blank lines skipped.

6 in-window records not correlated (different IP/host)

## Triage Verdict

**suspicious attempt**

Supporting evidence references: log-006@line:6.

Dry-run block proposal: allowlist check **passed**; expires 2026-10-28T12:02:30Z. No action was executed.

## Correlated Evidence Table

| Evidence reference | Record ID | UTC timestamp | Raw path | Normalized path | Indicators | HTTP status | Verdict reason | Warnings |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| log-002@line:2 | log-002 | 2026-10-27T12:00:30+00:00 | /products | /products | None | 200 | No traversal indicators detected after at most two URL decoding passes. | None |
| log-004@line:4 | log-004 | 2026-10-27T12:01:30+00:00 | /download?file=guide.pdf | /download?file=guide.pdf | None | 200 | No traversal indicators detected after at most two URL decoding passes. | None |
| log-006@line:6 | log-006 | 2026-10-27T12:02:30+00:00 | /download?file=../../../etc/passwd | /download?file=../../../etc/passwd | ../ | 403 | Directory traversal sequences detected in URI query parameters (HTTP 403) | None |

## Retained Unverifiable Records

These rows have not passed IP/host/time correlation and are not supporting evidence.

| Evidence reference | Correlation | Original raw line (JSON string) |
| --- | --- | --- |
| log-008@line:8 | unverifiable | "{\\"record&#95;id\\":\\"log-008\\",\\"timestamp\\":\\"2026-10-27T12:03:30\\",\\"source&#95;ip\\":\\"192.0.2.42\\",\\"destination&#95;host\\":\\"web.example.test\\",\\"method\\":\\"GET\\",\\"path\\":\\"/help\\",\\"status\\":200}\\n" |

## Retained Diagnostics

Diagnostic records are preserved below; they are not supporting evidence.

| Record ID | Line | Diagnostic | Original raw line (JSON string) |
| --- | --- | --- | --- |
| log-008 | 8 | Missing Timezone | "{\\"record&#95;id\\":\\"log-008\\",\\"timestamp\\":\\"2026-10-27T12:03:30\\",\\"source&#95;ip\\":\\"192.0.2.42\\",\\"destination&#95;host\\":\\"web.example.test\\",\\"method\\":\\"GET\\",\\"path\\":\\"/help\\",\\"status\\":200}\\n" |

## Limitations & Uncertainties

- URI decoding is capped at two passes; deeper encodings and other attack classes may be missed.
- Correlation uses the alert source IP, host, and time window; an IP does not identify an individual.
- Request patterns and HTTP status codes do not establish confirmed compromise.
- Rows with invalid timestamps cannot be placed within the window.
- Response proposals are dry-run only; allowlisted sources are suppressed.
- HTTP 403 indicates access was denied, but application behavior requires manual inspection.
- Retained for manual inspection; cannot reliably evaluate this row.
