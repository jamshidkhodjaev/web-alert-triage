"""Read web access JSONL without dropping records that fail normalization."""

import argparse
import json
import math
from datetime import datetime, timedelta, timezone
from pathlib import Path

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
    with open(path, encoding="utf-8", newline="") as source:
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
    """Return matches within an inclusive +/- window and separate diagnostics.

    Invalid log rows cannot be placed in the window, so retain them separately.
    An invalid alert or window raises ValueError rather than guessing a time.
    """
    if not math.isfinite(window_minutes) or window_minutes < 0:
        raise ValueError("Window minutes must be finite and non-negative")
    with open(alert_path, encoding="utf-8") as source:
        alert = json.load(source)
    if not isinstance(alert, dict) or "timestamp" not in alert:
        raise ValueError("Alert must be a JSON object with a timestamp")
    alert_timestamp = parse_timestamp(alert["timestamp"])
    try:
        window = timedelta(minutes=window_minutes)
        start = alert_timestamp - window
        end = alert_timestamp + window
    except OverflowError as exc:
        raise ValueError("Time window exceeds the supported datetime range") from exc

    matches = []
    diagnostics = []
    excluded_count = 0
    stats = {"blank_lines_skipped": 0}
    for result in parse_access_logs(log_path, stats):
        if result["diagnostic"] is not None:
            diagnostics.append(result)
        elif start <= result["parsed_timestamp"] <= end:
            matches.append(result)
        else:
            excluded_count += 1
    return {
        "alert": alert,
        "alert_timestamp": alert_timestamp,
        "window_start": start,
        "window_end": end,
        "records": matches,
        "diagnostics": diagnostics,
        "excluded_count": excluded_count,
        "blank_lines_skipped": stats["blank_lines_skipped"],
    }


if __name__ == "__main__":
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--window-minutes", type=float, default=5,
                     help="Minutes before and after the alert (default: 5)")
    cli.add_argument("--alert", type=Path, default=DEFAULT_ALERT_PATH)
    cli.add_argument("--logs", type=Path, default=DEFAULT_LOG_PATH)
    cli.add_argument("--allowlist-ip", action="append", default=[],
                     help="Suppress proposals for this exact IP (repeat for multiple IPs)")
    args = cli.parse_args()
    try:
        filtered = filter_logs_for_alert(args.logs, args.alert, args.window_minutes)
    except (OSError, ValueError) as exc:
        cli.exit(1, f"Verdict: insufficient data\nUnable to filter logs: {exc}\n")
    for result in filtered["diagnostics"]:
        print(
            f"Warning: record_id={result['record_id']!r}, "
            f"line={result['line_number']}: {result['diagnostic']}"
        )
    print(f"Window (inclusive): {filtered['window_start'].isoformat()} "
          f"to {filtered['window_end'].isoformat()}")
    print(f"Successfully parsed records within window: {len(filtered['records'])}")
    print(f"Records outside window: {filtered['excluded_count']}")
    print(f"Records with diagnostic warnings (time unknown): {len(filtered['diagnostics'])}")
    decision = evaluate_alert(filtered)
    try:
        report_path, proposal_path = write_artifacts(filtered, decision, args.allowlist_ip)
    except (OSError, ValueError, OverflowError, KeyError) as exc:
        cli.exit(1, f"Unable to generate triage artifacts: {exc}\n")
    # Datetimes live in retained evidence; serialize those as ISO 8601 for the CLI.
    print(json.dumps(decision, indent=2, default=lambda value: value.isoformat()))
    print(f"Report: {report_path}")
    print(f"Dry-run response proposal: {proposal_path}")
