"""Write reviewable triage artifacts; never execute response actions."""

import hashlib
import html
import json
import os
import tempfile
from datetime import timedelta, timezone
if __package__:
    from .input_safety import safe_text
    from .heuristics import normalize_ip
else:
    from input_safety import safe_text
    from heuristics import normalize_ip
from pathlib import Path


DEFAULT_OUTPUT_DIR = Path(__file__).resolve().parents[1] / "examples"


def build_response_proposal(filtered, decision, allowlist=()):
    """Return a dry-run proposal, or None when no supported attempt exists.

    The allowlist contains exact IP addresses. Its result is independent of the
    detection verdict. Canonical JSON and SHA-256 make the action ID repeatable.
    """
    allowed = {normalize_ip(value) for value in allowlist}
    if (decision["verdict"] != "suspicious attempt"
            or not decision["supporting_evidence_record_ids"]):
        return None
    alert = filtered["alert"]
    identity = {"alert_id": alert.get("alert_id", "unknown-alert"),
                "source_ip": alert.get("source_ip"),
                "rule_name": alert.get("rule_name", "Unknown Rule")}
    serialized = json.dumps(identity, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    action_id = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
    expires = filtered["alert_timestamp"].astimezone(timezone.utc) + timedelta(hours=24)
    suppressed = normalize_ip(alert["source_ip"]) in allowed
    return {
        "action_id": action_id,
        "target_ip": alert["source_ip"],
        "proposed_action": "none" if suppressed else "block_ip",
        "reason": "Path traversal attempt observed in correlated web logs; success of the request is not established and requires manual review.",
        "evidence_ids": list(decision["supporting_evidence_record_ids"]),
        "evidence_refs": list(decision["supporting_evidence_refs"]),
        "expires_at": expires.isoformat().replace("+00:00", "Z"),
        "allowlist_result": "suppressed" if suppressed else "passed",
        "dry_run": True,
        "requires_human_approval": True,
        "rollback_instruction": "No block is proposed because the source is allowlisted; no rollback is needed." if suppressed else (
            f"If this proposal was manually applied, remove the deny rule for {alert['source_ip']} "
            f"associated with action {action_id} from the firewall or WAF, then verify access is restored. "
            "This dry run changes no rules."
        ),
    }


def _cell(value):
    """Escape untrusted log text for Markdown tables and prose."""
    text = "—" if value is None else safe_text(value)
    text = html.escape(text, quote=False).replace("\\", "\\\\")
    for char in ("|", "`", "*", "_", "[", "]"):
        text = text.replace(char, f"&#{ord(char)};")
    return text.replace("\r", "&#13;").replace("\n", "<br>")


def _time(value):
    return value.isoformat() if value is not None else "unknown (alert timestamp invalid)"


def render_report(filtered, decision, proposal):
    alert = filtered["alert"]
    rows = [row for row in decision["analyzed_records"] if row["correlation_status"] == "correlated"]
    retained = [row for row in decision["analyzed_records"] if row["correlation_status"] != "correlated"]
    # Include all parser diagnostics, even rows whose identity cannot correlate.
    diagnostics = {row["line_number"]: (row, row["diagnostic"])
                   for row in filtered["diagnostics"]}
    for row in decision["analyzed_records"]:
        if row["diagnostic"]:
            diagnostics[row["evidence"]["line_number"]] = (row["evidence"], row["diagnostic"])
    lines = [
        "# Web Triage Report", "",
        "Artifact set is complete only when completion.json matches the SHA-256 hashes of both output files.", "",
        "## Executive Summary", "",
        f"Alert **{_cell(alert.get('alert_id'))}** — {_cell(alert.get('rule_name'))}.", "",
        f"Source: {_cell(alert.get('source_ip'))}; destination: {_cell(alert.get('destination_host'))}.", "",
        f"Alert time: {_time(filtered['alert_timestamp'])}. "
        f"Inclusive window: {_time(filtered['window_start'])} to {_time(filtered['window_end'])}.", "",
        f"{len(rows)} valid correlated records; {len(retained)} unverifiable records retained; "
        f"{len(diagnostics)} retained diagnostic records; "
        f"{filtered['excluded_count']} valid records outside the time window.", "",
        f"{filtered.get('blank_lines_skipped', 0)} blank lines skipped.", "",
        f"{decision.get('uncorrelated_count', 0)} in-window records not correlated (different IP/host)", "",
        "## Triage Verdict", "", f"**{_cell(decision['verdict'])}**", "",
        "Supporting evidence references: " + (_cell(", ".join(decision["supporting_evidence_refs"])) or "None") + ".", "",
        ("No block is proposed because the source is allowlisted." if proposal and proposal["allowlist_result"] == "suppressed" else f"Dry-run block proposal: allowlist check **{proposal['allowlist_result']}**; "
         f"expires {proposal['expires_at']}. No action was executed."
         if proposal else "No response proposed: no supported traversal attempt. The proposal file contains JSON null."),
        "", "## Correlated Evidence Table", "",
        "| Evidence reference | Record ID | UTC timestamp | Raw path | Normalized path | Indicators | HTTP status | Verdict reason | Warnings |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for row in rows:
        cells = [row["evidence_ref"], row["record_id"], row["evidence"]["parsed_timestamp"].isoformat(),
                 row["raw_path"], row["normalized_path"], ", ".join(row["matched_indicators"]) or "None",
                 row["http_status"], row["verdict_reason"], "; ".join(row.get("warnings", [])) or "None"]
        lines.append("| " + " | ".join(_cell(value) for value in cells) + " |")
    if not rows:
        lines.extend(["", "No valid correlated records."])
    if filtered.get("alert_error"):
        lines.extend(["", "### Alert/input failure", "", _cell(filtered["alert_error"]), "",
                      "Requested inputs: " + _cell(json.dumps(filtered.get("input_context", {}), ensure_ascii=True)), "",
                      "Original alert (JSON-escaped): " + _cell(json.dumps(filtered.get("raw_alert", ""), ensure_ascii=True))])
    if retained:
        lines.extend(["", "## Retained Unverifiable Records", "",
                      "These rows have not passed IP/host/time correlation and are not supporting evidence.", "",
                      "| Evidence reference | Correlation | Original raw line (JSON string) |",
                      "| --- | --- | --- |"])
        for row in retained:
            values = [row["evidence_ref"], row["correlation_status"],
                      json.dumps(row["evidence"]["raw_line"], ensure_ascii=True)]
            lines.append("| " + " | ".join(_cell(value) for value in values) + " |")
    lines.extend(["", "## Retained Diagnostics", "",
                  "Diagnostic records are preserved below; they are not supporting evidence.", "",
                  "| Record ID | Line | Diagnostic | Original raw line (JSON string) |",
                  "| --- | --- | --- | --- |"])
    for number, (row, diagnostic) in sorted(diagnostics.items()):
        values = [row["record_id"], number, diagnostic, json.dumps(row["raw_line"], ensure_ascii=True)]
        lines.append("| " + " | ".join(_cell(value) for value in values) + " |")
    if not diagnostics:
        lines.extend(["", "None."])
    lines.extend(["", "## Limitations & Uncertainties", "",
                  "- URI decoding is capped at two passes; deeper encodings and other attack classes may be missed.",
                  "- Correlation uses the alert source IP, host, and time window; an IP does not identify an individual.",
                  "- Request patterns and HTTP status codes do not establish confirmed compromise.",
                  "- Rows with invalid timestamps cannot be placed within the window.",
                  "- Response proposals are dry-run only; allowlisted sources are suppressed."])
    notes = [note for note in decision["uncertainty_notes"]
             if note != "Bounded URI inspection cannot rule out other attacks or deeper encoding."]
    existing = {line for line in lines if line.startswith("- ")}
    for note in notes:
        bullet = f"- {_cell(note)}"
        if bullet not in existing:
            lines.append(bullet)
            existing.add(bullet)
    return "\n".join(lines) + "\n"


def _atomic_write(path, data):
    """Publish one prepared byte string via a same-directory atomic replacement."""
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".triage-", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def write_artifacts(filtered, decision, allowlist=(), output_dir=DEFAULT_OUTPUT_DIR):
    """Publish two artifacts, then a deterministic hash manifest marking completion.

    The replacements are NOT a two-file transaction. Readers must validate the
    completion marker. On any failure, invalidate the marker and remove/null the
    proposal, best effort. Filesystem failures can also prevent that cleanup.
    """
    output_dir = Path(output_dir)
    report_path = output_dir / "report.md"
    proposal_path = output_dir / "response_proposal.json"
    marker = output_dir / "completion.json"
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        # Invalidate any previous run before preparation, which can itself fail.
        marker.unlink(missing_ok=True)
        proposal_path.unlink(missing_ok=True)
        proposal = build_response_proposal(filtered, decision, allowlist)
        report_bytes = render_report(filtered, decision, proposal).encode("utf-8")
        proposal_bytes = (json.dumps(proposal, indent=2, allow_nan=False) + "\n").encode("utf-8")
        manifest = {
            "report.md": hashlib.sha256(report_bytes).hexdigest(),
            "response_proposal.json": hashlib.sha256(proposal_bytes).hexdigest(),
        }
        marker_bytes = (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode("utf-8")
        _atomic_write(report_path, report_bytes)
        _atomic_write(proposal_path, proposal_bytes)
        _atomic_write(marker, marker_bytes)
    except (OSError, ValueError, TypeError, RecursionError, OverflowError) as exc:
        cleanup_errors = []
        for target in (marker, proposal_path):
            try:
                target.unlink(missing_ok=True)
            except OSError as cleanup:
                cleanup_errors.append(str(cleanup))
        try:
            _atomic_write(proposal_path, b"null\n")
        except OSError as cleanup:
            cleanup_errors.append(str(cleanup))
        detail = "; cleanup failed: " + "; ".join(cleanup_errors) if cleanup_errors else ""
        raise OSError(f"Artifact publication incomplete: {exc}{detail}") from exc
    return report_path, proposal_path
