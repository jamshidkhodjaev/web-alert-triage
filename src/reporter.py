"""Write reviewable triage artifacts; never execute response actions."""

import hashlib
import html
import json
from datetime import timedelta, timezone
if __package__:
    from .heuristics import normalize_ip
else:
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
    identity = {key: alert[key] for key in ("alert_id", "source_ip", "rule_name")}
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
    text = "—" if value is None else str(value)
    text = html.escape(text).replace("\\", "&#92;")
    for char in ("|", "`", "*", "_", "[", "]"):
        text = text.replace(char, f"&#{ord(char)};")
    return text.replace("\r", "&#13;").replace("\n", "<br>")


def render_report(filtered, decision, proposal):
    alert = filtered["alert"]
    rows = [row for row in decision["analyzed_records"] if not row["diagnostic"]]
    # Include all parser diagnostics, even rows whose identity cannot correlate.
    diagnostics = {row["line_number"]: (row, row["diagnostic"])
                   for row in filtered["diagnostics"]}
    for row in decision["analyzed_records"]:
        if row["diagnostic"]:
            diagnostics[row["evidence"]["line_number"]] = (row["evidence"], row["diagnostic"])
    lines = [
        "# Web Triage Report", "", "## Executive Summary", "",
        f"Alert **{_cell(alert.get('alert_id'))}** — {_cell(alert.get('rule_name'))}.", "",
        f"Source: {_cell(alert.get('source_ip'))}; destination: {_cell(alert.get('destination_host'))}.", "",
        f"Alert time: {filtered['alert_timestamp'].isoformat()}. "
        f"Inclusive window: {filtered['window_start'].isoformat()} to {filtered['window_end'].isoformat()}.", "",
        f"{len(rows)} valid correlated records; {len(diagnostics)} retained diagnostic records; "
        f"{filtered['excluded_count']} valid records outside the time window.", "",
        f"{filtered.get('blank_lines_skipped', 0)} blank lines skipped.", "",
        f"{decision.get('uncorrelated_count', 0)} in-window records not correlated (different IP/host)", "",
        "## Triage Verdict", "", f"**{_cell(decision['verdict'])}**", "",
        "Supporting evidence IDs: " + (_cell(", ".join(decision["supporting_evidence_record_ids"])) or "None") + ".", "",
        ("No block is proposed because the source is allowlisted." if proposal and proposal["allowlist_result"] == "suppressed" else f"Dry-run block proposal: allowlist check **{proposal['allowlist_result']}**; "
         f"expires {proposal['expires_at']}. No action was executed."
         if proposal else "No response proposed: no supported traversal attempt. The proposal file contains JSON null."),
        "", "## Correlated Evidence Table", "",
        "| Record ID | UTC timestamp | Raw path | Normalized path | Indicators | HTTP status | Verdict reason | Warnings |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for row in rows:
        cells = [row["record_id"], row["evidence"]["parsed_timestamp"].isoformat(),
                 row["raw_path"], row["normalized_path"], ", ".join(row["matched_indicators"]) or "None",
                 row["http_status"], row["verdict_reason"], "; ".join(row.get("warnings", [])) or "None"]
        lines.append("| " + " | ".join(_cell(value) for value in cells) + " |")
    if not rows:
        lines.extend(["", "No valid correlated records."])
    lines.extend(["", "## Retained Diagnostics", "",
                  "Diagnostic records are preserved below; they are not supporting evidence.", "",
                  "| Record ID | Line | Diagnostic | Original raw line (JSON string) |",
                  "| --- | --- | --- | --- |"])
    for number, (row, diagnostic) in sorted(diagnostics.items()):
        values = [row["record_id"], number, diagnostic, json.dumps(row["raw_line"], ensure_ascii=False)]
        lines.append("| " + " | ".join(_cell(value) for value in values) + " |")
    if not diagnostics:
        lines.extend(["", "None."])
    lines.extend(["", "## Limitations & Uncertainties", "",
                  "- URI decoding is capped at two passes; deeper encodings and other attack classes may be missed.",
                  "- Correlation uses the alert source IP, host, and time window; an IP does not identify an individual.",
                  "- Request patterns and HTTP status codes do not establish confirmed compromise.",
                  "- Rows with invalid timestamps cannot be placed within the window.",
                  "- Response proposals are dry-run only; allowlisted sources are suppressed."])
    lines.extend(f"- {_cell(note)}" for note in decision["uncertainty_notes"])
    return "\n".join(lines) + "\n"


def write_artifacts(filtered, decision, allowlist=(), output_dir=DEFAULT_OUTPUT_DIR):
    """Refresh both outputs, replacing stale proposals with null when unsupported."""
    proposal = build_response_proposal(filtered, decision, allowlist)
    report = render_report(filtered, decision, proposal)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    report_path = output_dir / "report.md"
    proposal_path = output_dir / "response_proposal.json"
    report_path.write_text(report, encoding="utf-8")
    proposal_path.write_text(json.dumps(proposal, indent=2) + "\n", encoding="utf-8")
    return report_path, proposal_path
