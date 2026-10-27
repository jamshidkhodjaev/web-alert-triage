"""Read web access JSONL without dropping records that fail normalization."""

import argparse
import json
import math
from datetime import datetime, timedelta, timezone
from pathlib import Path
from ipaddress import ip_address

if __package__:
    from .heuristics import evaluate_alert
    from .reporter import write_artifacts
else:
    from heuristics import evaluate_alert
    from reporter import write_artifacts


DEFAULT_LOG_PATH = Path(__file__).resolve().parents[1] / "fixtures/access_logs.jsonl"
DEFAULT_ALERT_PATH = DEFAULT_LOG_PATH.with_name("alert.json")


def parse_timestamp(value):
    """Return an aware UTC datetime; never assume a timezone for naive input."""
    if not isinstance(value, str) or not value:
        raise ValueError("Malformed Timestamp: expected a non-empty string")
    # Explicit conversion also supports Python versions before 3.11.
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValueError("Malformed Timestamp: invalid ISO 8601 value") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("Missing Timezone")
    try:
        return parsed.astimezone(timezone.utc)
    except (ValueError, OverflowError) as exc:
        raise ValueError("Malformed Timestamp: outside UTC datetime range") from exc


def parse_access_logs(path=DEFAULT_LOG_PATH, stats=None):
    """Yield one result per line, including invalid JSON; count and skip whitespace-only lines.

    Each result retains the unchanged decoded raw_record and exact raw_line.
    parsed_timestamp is None on failure; diagnostic describes that failure.
    line_number identifies evidence even when a record_id cannot be recovered.
    File access errors propagate to the caller; row errors remain in results.
    """
    with open(path, encoding="utf-8", errors="surrogateescape", newline="") as source:
        for line_number, raw_line in enumerate(source, start=1):
            if not raw_line.strip():
                if stats is not None:
                    stats["blank_lines_skipped"] = stats.get("blank_lines_skipped", 0) + 1
                continue
            result = {
                "record_id": None,
                "line_number": line_number,
                "raw_record": None,
                "raw_line": raw_line,
                "parsed_timestamp": None,
                "diagnostic": None,
            }
            try:
                if any(0xDC80 <= ord(char) <= 0xDCFF for char in raw_line):
                    raise json.JSONDecodeError("Invalid UTF-8 input bytes", raw_line, 0)
                record = json.loads(raw_line)
            except json.JSONDecodeError as exc:
                result["diagnostic"] = f"Invalid JSON: {exc.msg}"
            else:
                result["raw_record"] = record
                if not isinstance(record, dict):
                    result["diagnostic"] = "Invalid Record: expected a JSON object"
                else:
                    result["record_id"] = record.get("record_id")
                    try:
                        if "timestamp" not in record:
                            raise ValueError("Missing Timestamp")
                        result["parsed_timestamp"] = parse_timestamp(record["timestamp"])
                    except ValueError as exc:
                        result["diagnostic"] = str(exc)
            yield result


def filter_logs_for_alert(
    log_path=DEFAULT_LOG_PATH, alert_path=DEFAULT_ALERT_PATH, window_minutes=5
):
    """Retain input failures and evidence so every triage can generate artifacts."""
    alert = {}
    alert_error = None
    alert_timestamp = start = end = None
    notes = []
    try:
        with open(alert_path, encoding="utf-8") as source:
            alert = json.load(source)
        if not isinstance(alert, dict):
            alert = {}
            raise ValueError("Alert must be a JSON object")
        alert_timestamp = parse_timestamp(alert.get("timestamp"))
        if not math.isfinite(window_minutes) or window_minutes < 0:
            raise ValueError("Window minutes must be finite and non-negative")
        window = timedelta(minutes=window_minutes)
        start, end = alert_timestamp - window, alert_timestamp + window
        # Proposal expiry must also fit in the supported datetime range.
        alert_timestamp + timedelta(hours=24)
    except (OSError, ValueError, OverflowError) as exc:
        alert_error = f"Alert error: {exc}"
        alert_timestamp = start = end = None
    for key, fallback in (("alert_id", "unknown-alert"), ("rule_name", "Unknown Rule")):
        if not isinstance(alert.get(key), str) or not alert[key].strip():
            alert[key] = fallback
            notes.append(f"Missing or invalid {key}; using {fallback}.")
    matches, diagnostics = [], []
    excluded_count = 0
    stats = {"blank_lines_skipped": 0}
    input_error = None
    try:
        for result in parse_access_logs(log_path, stats):
            if result["diagnostic"] is not None:
                diagnostics.append(result)
            elif alert_error or start <= result["parsed_timestamp"] <= end:
                matches.append(result)
            else:
                excluded_count += 1
    except (OSError, UnicodeError) as exc:
        input_error = f"Log input error: {exc}"
    return {
        "alert": alert, "alert_error": alert_error, "input_error": input_error,
        "uncertainty_notes": notes, "alert_timestamp": alert_timestamp,
        "window_start": start, "window_end": end, "records": matches,
        "diagnostics": diagnostics, "excluded_count": excluded_count,
        "blank_lines_skipped": stats["blank_lines_skipped"],
    }


def allowlist_ip(value):
    try:
        return str(ip_address(value))
    except ValueError as exc:
        raise argparse.ArgumentTypeError("expected an exact IPv4 or IPv6 address (no CIDR)") from exc


class TriageArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError(message)


def main(argv=None):
    cli = TriageArgumentParser(description=__doc__)
    cli.add_argument("--window-minutes", type=float, default=5)
    cli.add_argument("--alert", type=Path, default=DEFAULT_ALERT_PATH)
    cli.add_argument("--logs", type=Path, default=DEFAULT_LOG_PATH)
    cli.add_argument("--allowlist-ip", action="append", default=[], type=allowlist_ip,
                     help="Exact IP address; repeat for multiple addresses (no CIDR)")
    cli.add_argument("--output-dir", type=Path, default=DEFAULT_LOG_PATH.parent.parent / "examples")
    try:
        args = cli.parse_args(argv)
        filtered = filter_logs_for_alert(args.logs, args.alert, args.window_minutes)
    except ValueError as exc:
        # Recover the destination even if another argument fails validation.
        destination = TriageArgumentParser(add_help=False)
        destination.add_argument("--output-dir", type=Path, default=DEFAULT_LOG_PATH.parent.parent / "examples")
        try:
            recovered, _ = destination.parse_known_args(argv)
            output_dir = recovered.output_dir
        except ValueError:
            output_dir = DEFAULT_LOG_PATH.parent.parent / "examples"
        args = argparse.Namespace(output_dir=output_dir, allowlist_ip=[])
        filtered = filter_logs_for_alert()
        filtered.update(alert_error=f"Argument error: {exc}", alert_timestamp=None,
                        window_start=None, window_end=None)

    decision = evaluate_alert(filtered)
    print(f"Verdict: {decision['verdict']}")
    try:
        report_path, proposal_path = write_artifacts(
            filtered, decision, args.allowlist_ip, args.output_dir)
    except OSError as exc:
        print(f"Unable to write triage artifacts: {exc}")
        return 1
    print(json.dumps(decision, indent=2, default=lambda value: value.isoformat()))
    print(f"Report: {report_path}")
    print(f"Dry-run response proposal: {proposal_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
