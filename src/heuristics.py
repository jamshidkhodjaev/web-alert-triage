"""Conservative URI traversal heuristics; a request is not proof of compromise."""

import re
from ipaddress import ip_address
from urllib.parse import unquote


TRAVERSAL = re.compile(
    r"(?:^|(?<=[/\\=?&;#])|(?<=%2f)|(?<=%5c))"
    r"(?:\.|%2e){2}(?:/|\\|%2f|%5c|(?=$|[?&;#]))", re.IGNORECASE
)
BAD_ESCAPE = re.compile(r"%(?![0-9a-fA-F]{2})")


def normalize_ip(value):
    address = ip_address(value)
    return getattr(address, "ipv4_mapped", None) or address


def normalize_path(raw_path):
    """Preserve the URI and decode at most twice, without collapsing dot segments."""
    if not isinstance(raw_path, str) or not raw_path:
        raise ValueError("Missing or invalid path")
    normalized = raw_path
    invalid_encoding = False
    for _ in range(2):
        try:
            decoded = unquote(normalized, errors="strict")
        except UnicodeError:
            decoded = unquote(normalized, errors="replace")
            invalid_encoding = True
        if decoded == normalized:
            break
        normalized = decoded
    return {"raw_path": raw_path, "normalized_path": normalized, "invalid_encoding": invalid_encoding}


def analyze_record(result):
    """Produce a decision for one parsed row, keeping its original evidence."""
    record = result["raw_record"]
    record = record if isinstance(record, dict) else {}
    decision = {
        "record_id": result["record_id"],
        "matched_indicators": [],
        "http_status": record.get("status"),
        "verdict_reason": "",
        "uncertainty_note": "",
        "raw_path": record.get("path"),
        "normalized_path": None,
        "diagnostic": result["diagnostic"],
        "evidence": result,
        "warnings": [],
        "invalid_encoding": False,
        "inconclusive": False,
    }
    errors = [result["diagnostic"]] if result["diagnostic"] else []
    for field in ("record_id", "destination_host"):
        if not isinstance(record.get(field), str) or not record[field].strip():
            errors.append(f"Missing or invalid {field}")
    try:
        if not isinstance(record.get("source_ip"), str):
            raise ValueError()
        ip_address(record["source_ip"])
    except ValueError:
        errors.append("Missing or invalid source_ip")
    if not isinstance(record.get("method"), str) or not record["method"].strip():
        decision["warnings"].append("Missing or invalid method")
    status = record.get("status")
    if type(status) is not int or not 100 <= status <= 599:
        decision["warnings"].append("Missing or invalid HTTP status")
    try:
        decision.update(normalize_path(record.get("path")))
        decision["matched_indicators"] = list(dict.fromkeys(
            match.group() for match in TRAVERSAL.finditer(decision["normalized_path"])
        ))
        if BAD_ESCAPE.search(record["path"]):
            decision["warnings"].append("Malformed URL escape")
    except (ValueError, UnicodeError) as exc:
        errors.append(f"Invalid path: {exc}")
    if decision["invalid_encoding"]:
        decision["warnings"].append("Invalid UTF-8 URL encoding replaced")
    residual_encoding = bool(re.search(r"%25(?:25)*2[eEfF]", decision["normalized_path"] or ""))
    decision["inconclusive"] = (decision["invalid_encoding"] or residual_encoding) and not decision["matched_indicators"]
    if errors:
        decision["diagnostic"] = "; ".join(errors)
        decision["verdict_reason"] = "Critical fields corrupted: " + decision["diagnostic"]
        decision["uncertainty_note"] = "Retained for manual inspection; cannot reliably evaluate this row."
    elif decision["matched_indicators"]:
        path, _, query = decision["normalized_path"].partition("?")
        location = "URI query parameters" if TRAVERSAL.search(query) else "URI path"
        decision["verdict_reason"] = f"Directory traversal sequences detected in {location} (HTTP {status})"
        decision["uncertainty_note"] = (
            "HTTP 403 indicates access was denied, but application behavior requires manual inspection."
            if status == 403 else
            f"HTTP {status} alone does not establish payload execution or compromise; manual inspection is required."
        )
    else:
        decision["verdict_reason"] = "No traversal indicators detected after at most two URL decoding passes."
        decision["uncertainty_note"] = "Bounded URI inspection cannot rule out other attacks or deeper encoding."
    return decision


def evaluate_alert(filtered):
    """Correlate by IP and host in the prefiltered inclusive time window.

    Valid positive evidence takes precedence over separate corrupt rows. Without
    positive evidence, potentially relevant corruption prevents a negative verdict.
    """
    alert = filtered["alert"]
    decisions = []
    alert_error = None
    try:
        if not isinstance(alert.get("source_ip"), str):
            raise ValueError()
        source_ip = normalize_ip(alert["source_ip"])
        if not isinstance(alert.get("destination_host"), str) or not alert["destination_host"].strip():
            raise ValueError()
        host = alert["destination_host"].lower().rstrip(".")
    except ValueError:
        alert_error = "Alert source IP or destination host is missing or invalid."

    uncorrelated_count = 0
    for row in filtered["records"] + filtered["diagnostics"]:
        record = row["raw_record"]
        if not alert_error and isinstance(record, dict):
            # Exclude known nonmatching identities, but retain unknown identities.
            try:
                candidate = record.get("source_ip")
                if isinstance(candidate, str) and normalize_ip(candidate) != source_ip:
                    if not row["diagnostic"]:
                        uncorrelated_count += 1
                    continue
            except ValueError:
                pass
            candidate_host = record.get("destination_host")
            if isinstance(candidate_host, str) and candidate_host.strip() and candidate_host.lower().rstrip(".") != host:
                if not row["diagnostic"]:
                    uncorrelated_count += 1
                continue
        decisions.append(analyze_record(row))

    supporting = [d["record_id"] for d in decisions
                  if d["matched_indicators"] and not d["diagnostic"]]
    corrupted = any(d["diagnostic"] or d["inconclusive"] for d in decisions)
    if alert_error:
        verdict = "insufficient data"
        supporting = []
    elif supporting:
        verdict = "suspicious attempt"
    elif not decisions or corrupted:
        verdict = "insufficient data"
    else:
        verdict = "no supporting evidence"
    notes = list(dict.fromkeys(d["uncertainty_note"] for d in decisions))
    if alert_error:
        notes.insert(0, alert_error)
    elif not decisions:
        notes.append("No logs match the alert source IP and host within the time window.")
    return {
        "uncorrelated_count": uncorrelated_count,
        "alert_id": alert.get("alert_id"),
        "verdict": verdict,
        "supporting_evidence_record_ids": supporting,
        "analyzed_records": decisions,
        "uncertainty_notes": notes,
    }
