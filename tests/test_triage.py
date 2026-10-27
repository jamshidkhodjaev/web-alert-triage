"""Pipeline regression tests using isolated JSON/JSONL files.

Run from the repository root: python3 -m unittest discover -s tests -v
or: python3 -m pytest
"""

import hashlib
import os
from unittest.mock import patch

import contextlib
import io
import json
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from src.heuristics import evaluate_alert, normalize_path
from src.parser import filter_logs_for_alert, main
from src.input_safety import bounded_json_loads, MAX_JSON_DEPTH
from src.reporter import build_response_proposal, write_artifacts, render_report


class TriageTests(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.alert_path = Path(directory.name) / "alert.json"
        self.log_path = Path(directory.name) / "access_logs.jsonl"
        self.alert = {
            "alert_id": "test-alert-001",
            "timestamp": "2026-10-27T12:00:00Z",
            "source_ip": "192.0.2.42",
            "destination_host": "web.example.test",
            "rule_name": "Suspicious URI Pattern",
        }
        self.alert_path.write_text(json.dumps(self.alert), encoding="utf-8")

    def record(self, **overrides):
        record = {
            "record_id": "test-log-001",
            "timestamp": self.alert["timestamp"],
            "source_ip": self.alert["source_ip"],
            "destination_host": self.alert["destination_host"],
            "method": "GET",
            "path": "/",
            "status": 200,
        }
        record.update(overrides)
        return record

    def triage(self, *records):
        self.log_path.write_text(
            "".join(json.dumps(record) + "\n" for record in records), encoding="utf-8"
        )
        filtered = filter_logs_for_alert(self.log_path, self.alert_path, window_minutes=5)
        return filtered, evaluate_alert(filtered)

    def test_path_traversal_is_suspicious_attempt(self):
        _, decision = self.triage(self.record(path="../../../etc/passwd", status=403))
        self.assertEqual(decision["verdict"], "suspicious attempt")
        self.assertEqual(decision["supporting_evidence_record_ids"], ["test-log-001"])
        row = decision["analyzed_records"][0]
        self.assertIn("../", row["matched_indicators"])
        self.assertEqual(row["raw_path"], "../../../etc/passwd")
        self.assertEqual(row["http_status"], 403)

    def test_benign_paths_have_no_supporting_evidence(self):
        for path in ("/", "/products", "/search?q=hello%20world&page=2", "/view?page=..."):
            with self.subTest(path=path):
                _, decision = self.triage(self.record(path=path))
                self.assertEqual(decision["verdict"], "no supporting evidence")
                self.assertEqual(decision["supporting_evidence_record_ids"], [])
                self.assertEqual(decision["analyzed_records"][0]["matched_indicators"], [])

    def test_records_ten_minutes_beyond_window_are_excluded(self):
        # The window is 11:55–12:05; these are ten minutes beyond each edge.
        for timestamp in ("2026-10-27T11:45:00Z", "2026-10-27T12:15:00Z"):
            with self.subTest(timestamp=timestamp):
                outside = self.record(timestamp=timestamp, path="../../../etc/passwd")
                filtered, decision = self.triage(outside)
                self.assertEqual(filtered["records"], [])
                self.assertEqual(filtered["excluded_count"], 1)
                self.assertEqual(decision["verdict"], "insufficient data")
                self.assertEqual(decision["analyzed_records"], [])
                # An excluded attack must not taint a benign in-window record.
                _, decision = self.triage(outside, self.record(record_id="inside"))
                self.assertEqual(decision["verdict"], "no supporting evidence")
                self.assertEqual(decision["supporting_evidence_record_ids"], [])

    def test_missing_timezone_retains_diagnostic_and_continues(self):
        broken = self.record(timestamp="2026-10-27T12:00:00")
        filtered, decision = self.triage(broken, self.record(record_id="next-valid"))
        self.assertEqual(len(filtered["diagnostics"]), 1)
        diagnostic = filtered["diagnostics"][0]
        self.assertEqual(diagnostic["record_id"], "test-log-001")
        self.assertEqual(diagnostic["diagnostic"], "Missing Timezone")
        self.assertIsNone(diagnostic["parsed_timestamp"])
        self.assertEqual(diagnostic["raw_record"], broken)
        self.assertEqual(json.loads(diagnostic["raw_line"]), broken)
        self.assertEqual(filtered["records"][0]["record_id"], "next-valid")
        self.assertEqual(decision["verdict"], "insufficient data")

    def test_allowlisted_ip_suppresses_response_proposal(self):
        filtered, decision = self.triage(self.record(path="../../../etc/passwd"))
        proposal = build_response_proposal(filtered, decision, [self.alert["source_ip"]])
        self.assertEqual(proposal["allowlist_result"], "suppressed")
        self.assertEqual(proposal["target_ip"], self.alert["source_ip"])
        self.assertEqual(proposal["evidence_ids"], ["test-log-001"])
        self.assertIs(proposal["dry_run"], True)
        self.assertEqual(decision["verdict"], "suspicious attempt")
        unsuppressed = build_response_proposal(filtered, decision, ["192.0.2.99"])
        self.assertEqual(unsuppressed["allowlist_result"], "passed")
        self.assertEqual(proposal["action_id"], unsuppressed["action_id"])

    def check_path(self, path, verdict):
        filtered, decision = self.triage(self.record(path=path))
        self.assertEqual(decision["verdict"], verdict)
        return filtered, decision

    def test_single_encoded(self):
        self.check_path('%2e%2e%2fetc/passwd', 'suspicious attempt')

    def test_double_encoded(self):
        self.check_path('%252e%252e%252fetc/passwd', 'suspicious attempt')

    def test_backslash(self):
        self.check_path('..\\..\\etc\\passwd', 'suspicious attempt')

    def test_query_dotdot(self):
        self.check_path('/d?file=..', 'suspicious attempt')

    def test_encoded_query_dotdot(self):
        self.check_path('/d?file=%2e%2e', 'suspicious attempt')

    def test_semicolon_segment(self):
        self.check_path('/a/..;/', 'suspicious attempt')

    def test_three_dots(self):
        self.check_path('.../x', 'no supporting evidence')

    def test_filename_dots(self):
        self.check_path('file../x', 'no supporting evidence')

    def test_trailing_percent(self):
        self.check_path('../../etc/passwd%', 'suspicious attempt')

    def test_invalid_utf8_attack(self):
        self.check_path('../../etc/passwd%ff', 'suspicious attempt')

    def test_overlong_utf8(self):
        self.check_path('%c0%ae%c0%ae/', 'insufficient data')

    def test_benign_percent(self):
        self.check_path('/promo?discount=50%', 'no supporting evidence')

    def test_four_pass_encoding_stops_after_two(self):
        path = "%2525252e%2525252e%2525252f"
        # Two decodes leave %252e%252e%252f, not ../; residual encoding is inconclusive.
        normalized = normalize_path(path)
        self.assertEqual(normalized["raw_path"], path)
        self.assertEqual(normalized["normalized_path"], "%252e%252e%252f")
        # A third decoding pass would produce %2e%2e%2f, violating the bound.
        self.assertNotEqual(normalized["normalized_path"], "%2e%2e%2f")
        _, decision = self.check_path(path, "insufficient data")
        self.assertEqual(decision["supporting_evidence_record_ids"], [])

    def test_offset_normalizes_to_utc(self):
        filtered, _ = self.triage(self.record(timestamp="2026-10-27T14:00:00+02:00"))
        self.assertEqual(filtered["records"][0]["parsed_timestamp"].isoformat(), "2026-10-27T12:00:00+00:00")

    def test_window_boundary_inside(self):
        filtered, _ = self.triage(self.record(timestamp="2026-10-27T12:05:00Z"))
        self.assertEqual(len(filtered["records"]), 1)

    def test_window_boundary_outside(self):
        filtered, _ = self.triage(self.record(timestamp="2026-10-27T12:05:01Z"))
        self.assertEqual(filtered["excluded_count"], 1)

    def test_garbage_timestamp(self):
        filtered, decision = self.triage(self.record(timestamp="garbage"))
        self.assertEqual(decision["verdict"], "insufficient data")
        self.assertIn("Malformed Timestamp", filtered["diagnostics"][0]["diagnostic"])
        self.assertIn("garbage", filtered["diagnostics"][0]["raw_line"])

    def test_null_timestamp(self):
        filtered, decision = self.triage(self.record(timestamp=None))
        self.assertEqual(decision["verdict"], "insufficient data")
        self.assertIsNone(filtered["diagnostics"][0]["raw_record"]["timestamp"])
        self.assertTrue(filtered["diagnostics"][0]["raw_line"])

    def assert_rewritten(self, filtered, decision):
        output = self.alert_path.parent / "output"
        output.mkdir(exist_ok=True)
        for name in ("report.md", "response_proposal.json"):
            (output / name).write_text("STALE suspicious", encoding="utf-8")
        paths = write_artifacts(filtered, decision, output_dir=output)
        for path in paths:
            self.assertNotIn("STALE", path.read_text())
        before = [path.read_bytes() for path in paths]
        write_artifacts(filtered, decision, output_dir=output)
        self.assertEqual(before, [path.read_bytes() for path in paths])
        return paths

    def test_naive_alert_rewrites_both_files(self):
        self.alert["timestamp"] = "2026-10-27T12:00:00"
        self.alert_path.write_text(json.dumps(self.alert))
        filtered, decision = self.triage(self.record(path="../x"))
        self.assertEqual(decision["verdict"], "insufficient data")
        self.assertIsNone(filtered["window_start"])
        report, proposal = self.assert_rewritten(filtered, decision)
        self.assertIsNone(json.loads(proposal.read_text()))
        self.assertIn("unknown (alert timestamp invalid)", report.read_text())

    def test_different_ip_counted(self):
        _, decision = self.triage(self.record(source_ip="192.0.2.99", path="../x"))
        self.assertEqual(decision["uncorrelated_count"], 1)
        self.assertEqual(decision["verdict"], "insufficient data")

    def test_different_host_counted(self):
        _, decision = self.triage(self.record(destination_host="other.test", path="../x"))
        self.assertEqual(decision["uncorrelated_count"], 1)
        self.assertEqual(decision["verdict"], "insufficient data")

    def test_host_case_and_trailing_dot(self):
        _, decision = self.triage(self.record(destination_host="WEB.EXAMPLE.TEST.", path="../x"))
        self.assertEqual(decision["verdict"], "suspicious attempt")

    def test_ipv4_mapped_ipv6(self):
        _, decision = self.triage(self.record(source_ip="::ffff:192.0.2.42", path="../x"))
        self.assertEqual(decision["verdict"], "suspicious attempt")

    def test_trailing_blank_line(self):
        self.triage(self.record())
        with self.log_path.open("a") as stream:
            stream.write(" \n")
        filtered = filter_logs_for_alert(self.log_path, self.alert_path)
        self.assertEqual(filtered["blank_lines_skipped"], 1)
        self.assertEqual(evaluate_alert(filtered)["verdict"], "no supporting evidence")

    def test_truncated_json_retained(self):
        self.triage(self.record())
        with self.log_path.open("a") as stream:
            stream.write('{"record_id":')
        filtered = filter_logs_for_alert(self.log_path, self.alert_path)
        self.assertEqual(filtered["diagnostics"][0]["raw_line"], '{"record_id":')
        self.assertEqual(evaluate_alert(filtered)["verdict"], "insufficient data")

    def test_action_id_stable_across_window(self):
        filtered, decision = self.triage(self.record(path="../x"))
        first = build_response_proposal(filtered, decision)
        self.assertEqual(first, build_response_proposal(filtered, decision))
        changed = filter_logs_for_alert(self.log_path, self.alert_path, window_minutes=1)
        self.assertEqual(first["action_id"], build_response_proposal(changed, evaluate_alert(changed))["action_id"])

    def test_allowlist_no_action_and_human_approval(self):
        filtered, decision = self.triage(self.record(path="../x"))
        proposal = build_response_proposal(filtered, decision, [self.alert["source_ip"]])
        self.assertEqual(proposal["proposed_action"], "none")
        self.assertTrue(proposal["requires_human_approval"])
        self.assertTrue(proposal["dry_run"])
        self.assertIn("No block is proposed", proposal["rollback_instruction"])

    def test_benign_null_proposal(self):
        filtered, decision = self.triage(self.record())
        self.assertIsNone(build_response_proposal(filtered, decision))

    def test_missing_rule_name(self):
        del self.alert["rule_name"]
        self.alert_path.write_text(json.dumps(self.alert))
        filtered, decision = self.triage(self.record(path="../x"))
        self.assertEqual(filtered["alert"]["rule_name"], "Unknown Rule")
        self.assertTrue(build_response_proposal(filtered, decision))
        self.assertTrue(any("Unknown Rule" in note for note in decision["uncertainty_notes"]))

    def test_proposal_does_not_claim_compromise(self):
        filtered, decision = self.triage(self.record(path="../x"))
        self.assertNotIn("confirmed" + " compromise", json.dumps(build_response_proposal(filtered, decision)))

    def test_verdict_invariant(self):
        for records in ([], [self.record()], [self.record(path="../x")],
                        [self.record(timestamp=None)], [self.record(), self.record(path="../x%ff")]):
            with self.subTest(records=records):
                _, decision = self.triage(*records)
                self.assertIn(decision["verdict"], {"suspicious attempt", "no supporting evidence", "insufficient data"})

    def test_suspicious_artifacts_rewritten(self):
        filtered, decision = self.triage(self.record(path="../x"))
        self.assert_rewritten(filtered, decision)

    def test_benign_artifacts_rewritten(self):
        filtered, decision = self.triage(self.record())
        _, proposal = self.assert_rewritten(filtered, decision)
        self.assertIsNone(json.loads(proposal.read_text()))

    def test_report_escapes_log_path(self):
        filtered, decision = self.triage(self.record(path="/a|[x](http://evil.test)<script>"))
        report = render_report(filtered, decision, None)
        self.assertIn("&#124;", report)
        self.assertIn("&#91;x&#93;", report)
        self.assertIn("&lt;script&gt;", report)
        self.assertNotIn("[x](http://evil.test)", report)
        self.assertNotIn("<script>", report)

    def test_cli_alert_error_completes(self):
        self.triage(self.record())
        self.alert_path.write_text("null")
        output = self.alert_path.parent / "cli-output"
        with contextlib.redirect_stdout(io.StringIO()) as console:
            code = main(["--alert", str(self.alert_path), "--logs", str(self.log_path), "--output-dir", str(output)])
        self.assertEqual(code, 0)
        self.assertIn("Verdict: insufficient data", console.getvalue())
        self.assertTrue((output / "report.md").exists())
        self.assertIsNone(json.loads((output / "response_proposal.json").read_text()))

    def test_invalid_method_and_status_are_warnings(self):
        _, decision = self.triage(self.record(path="../x", method=None, status=None))
        self.assertEqual(decision["verdict"], "suspicious attempt")
        self.assertEqual(len(decision["analyzed_records"][0]["warnings"]), 2)

    def test_positive_evidence_wins_over_inconclusive(self):
        _, decision = self.triage(self.record(path="%ff"), self.record(record_id="positive", path="../x"))
        self.assertEqual(decision["verdict"], "suspicious attempt")
        self.assertEqual(decision["supporting_evidence_record_ids"], ["positive"])

    def run_custom_cli(self, *extra):
        output = self.alert_path.parent / "custom-output"
        args = ["--alert", str(self.alert_path), "--logs", str(self.log_path),
                "--output-dir", str(output), *extra]
        with contextlib.redirect_stdout(io.StringIO()) as console:
            code = main(args)
        return code, output, console.getvalue()

    def assert_argument_error_preserves_outputs(self, *arguments):
        output = self.alert_path.parent / "previous-output"
        output.mkdir(exist_ok=True)
        previous = {name: ("earlier run: " + name).encode() for name in
                    ("report.md", "response_proposal.json", "completion.json")}
        for name, data in previous.items():
            (output / name).write_bytes(data)
        with patch('src.parser.filter_logs_for_alert') as load_inputs, \
                patch('src.parser.write_artifacts') as publish, \
                contextlib.redirect_stdout(io.StringIO()) as stdout, \
                contextlib.redirect_stderr(io.StringIO()) as stderr:
            code = main(["--alert", str(self.alert_path), "--logs", str(self.log_path),
                         "--output-dir", str(output), *arguments])
        self.assertEqual(code, 2)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("error:", stderr.getvalue())
        self.assertIn("No new analysis was completed", stderr.getvalue())
        self.assertIn("Existing outputs belong to an earlier run", stderr.getvalue())
        load_inputs.assert_not_called()
        publish.assert_not_called()
        self.assertEqual({path.name: path.read_bytes() for path in output.iterdir()}, previous)

    def test_bad_window_never_substitutes_demo_evidence(self):
        self.assert_argument_error_preserves_outputs("--window-minutes", "bad")

    def test_bad_allowlist_preserves_outputs(self):
        self.assert_argument_error_preserves_outputs("--allowlist-ip", "nope")

    def test_invalid_window_values_are_argument_errors(self):
        for value in ("-1", "nan", "inf", "1e100"):
            with self.subTest(value=value):
                self.assert_argument_error_preserves_outputs("--window-minutes", value)

    def test_argument_error_without_output_dir_does_not_touch_examples(self):
        with patch('src.parser.filter_logs_for_alert') as load_inputs, \
                patch('src.parser.write_artifacts') as publish, \
                contextlib.redirect_stderr(io.StringIO()) as stderr:
            code = main(["--allowlist-ip", "nope"])
        self.assertEqual(code, 2)
        self.assertIn("exact IPv4 or IPv6", stderr.getvalue())
        load_inputs.assert_not_called()
        publish.assert_not_called()

    def test_expiry_is_exactly_24_hours_after_normalized_alert(self):
        self.alert["timestamp"] = "2026-10-27T01:30:00+02:00"
        self.alert_path.write_text(json.dumps(self.alert))
        filtered, decision = self.triage(self.record(path="../x"))
        proposal = build_response_proposal(filtered, decision)
        expiry = datetime.fromisoformat(proposal["expires_at"].replace("Z", "+00:00"))
        alert_utc = datetime(2026, 10, 26, 23, 30, tzinfo=timezone.utc)
        self.assertEqual(filtered["alert_timestamp"], alert_utc)
        self.assertEqual(expiry - alert_utc, timedelta(hours=24))
        self.assertEqual(proposal["expires_at"], "2026-10-27T23:30:00Z")

    def test_action_id_stable_for_identical_identity(self):
        filtered, decision = self.triage(self.record(path="../x"))
        first = build_response_proposal(filtered, decision)["action_id"]
        again = filter_logs_for_alert(self.log_path, self.alert_path)
        self.assertEqual(first, build_response_proposal(again, evaluate_alert(again))["action_id"])
        identity = {key: self.alert[key] for key in ("alert_id", "source_ip", "rule_name")}
        expected = hashlib.sha256(json.dumps(identity, sort_keys=True, separators=(",", ":"),
                                             ensure_ascii=False).encode("utf-8")).hexdigest()
        self.assertEqual(first, expected)

    def assert_identity_changes_action_id(self, field, value):
        filtered, decision = self.triage(self.record(path="../x"))
        original = build_response_proposal(filtered, decision)["action_id"]
        self.alert[field] = value
        self.alert_path.write_text(json.dumps(self.alert))
        filtered, decision = self.triage(self.record(path="../x"))
        changed = build_response_proposal(filtered, decision)["action_id"]
        self.assertNotEqual(original, changed)

    def test_changed_alert_id_changes_action_id(self):
        self.assert_identity_changes_action_id("alert_id", "another-alert")

    def test_changed_rule_name_changes_action_id(self):
        self.assert_identity_changes_action_id("rule_name", "Another Rule")

    def test_changed_source_ip_changes_action_id(self):
        self.assert_identity_changes_action_id("source_ip", "192.0.2.99")

    def test_oversized_integer_is_retained_and_next_row_processed(self):
        self.log_path.write_text('9' * 5000 + '\n' + json.dumps(self.record(record_id="CUSTOM-ONLY")) + '\n')
        code, output, console = self.run_custom_cli()
        self.assertEqual(code, 0)
        report = (output / "report.md").read_text()
        self.assertIn("integer exceeds 4300 digits", report)
        self.assertIn('9' * 5000, report)
        self.assertIn("CUSTOM-ONLY", report)
        self.assertNotIn("log-006", report + console)
        self.assertNotIn("Argument error", report)

    def test_invalid_alert_never_labels_unrelated_record_correlated(self):
        self.alert["timestamp"] = "invalid"
        self.alert_path.write_text(json.dumps(self.alert))
        filtered, decision = self.triage(self.record(timestamp="2020-01-01T00:00:00Z", source_ip="192.0.2.99"))
        self.assertEqual(filtered["records"], [])
        self.assertEqual(len(filtered["retained_records"]), 1)
        self.assertEqual(decision["analyzed_records"][0]["correlation_status"], "unverifiable")
        report = render_report(filtered, decision, None)
        self.assertIn("0 valid correlated records", report)
        self.assertIn("Retained Unverifiable Records", report)
        self.assertEqual(decision["supporting_evidence_refs"], [])

    def test_invalid_alert_identity_prevents_correlation(self):
        self.alert["source_ip"] = "invalid-ip"
        self.alert_path.write_text(json.dumps(self.alert))
        filtered, decision = self.triage(self.record(source_ip="192.0.2.42", path="../x"))
        self.assertEqual(decision["verdict"], "insufficient data")
        self.assertEqual(decision["analyzed_records"][0]["correlation_status"], "unverifiable")
        self.assertIn("0 valid correlated records", render_report(filtered, decision, None))
        self.assertIsNone(build_response_proposal(filtered, decision))

    def test_lone_surrogate_log_preserved_safely(self):
        filtered, decision = self.triage(self.record(path="/x\ud800"))
        row = filtered["diagnostics"][0]
        self.assertIn("Malformed Unicode", row["diagnostic"])
        self.assertIn(r"\ud800", row["raw_line"])
        report, proposal = self.assert_rewritten(filtered, decision)
        self.assertIn(r"\ud800", report.read_text())
        self.assertIsNone(json.loads(proposal.read_text()))

    def test_lone_surrogate_alert_preserved_safely(self):
        self.alert["alert_id"] = "bad\ud800"
        self.alert_path.write_text(json.dumps(self.alert))
        filtered, decision = self.triage(self.record(path="../x"))
        self.assertEqual(decision["verdict"], "insufficient data")
        report, proposal = self.assert_rewritten(filtered, decision)
        self.assertIn(r"\ud800", report.read_text())
        self.assertIn("Malformed Unicode", report.read_text())
        self.assertIsNone(json.loads(proposal.read_text()))

    def test_surrogate_row_does_not_hide_separate_positive(self):
        filtered, decision = self.triage(self.record(path="/x\ud800"), self.record(record_id="positive", path="../x"))
        self.assertEqual(decision["verdict"], "suspicious attempt")
        self.assertEqual(build_response_proposal(filtered, decision)["evidence_refs"], ["positive@line:2"])
        self.assert_rewritten(filtered, decision)

    def test_duplicate_ids_are_disambiguated(self):
        filtered, decision = self.triage(self.record(), self.record(path="../x"))
        self.assertEqual(decision["verdict"], "suspicious attempt")
        self.assertTrue(all(any("Duplicate" in warning for warning in row["warnings"])
                            for row in decision["analyzed_records"]))
        self.assertEqual(decision["supporting_evidence_record_ids"], ["test-log-001"])
        self.assertEqual(decision["supporting_evidence_refs"], ["test-log-001@line:2"])
        proposal = build_response_proposal(filtered, decision)
        self.assertEqual(proposal["evidence_refs"], decision["supporting_evidence_refs"])
        report = render_report(filtered, decision, proposal)
        self.assertIn("test-log-001@line:1", report)
        self.assertIn("test-log-001@line:2", report)

    def test_deep_json_retained_and_next_row_processed(self):
        raw = '[' * 2000 + '0' + ']' * 2000
        self.log_path.write_text(raw + '\n' + json.dumps(self.record(path="../x")) + '\n')
        filtered = filter_logs_for_alert(self.log_path, self.alert_path)
        self.assertEqual(filtered["diagnostics"][0]["raw_line"], raw + '\n')
        self.assertIn("nesting exceeds", filtered["diagnostics"][0]["diagnostic"])
        decision = evaluate_alert(filtered)
        self.assertEqual(decision["verdict"], "suspicious attempt")
        self.assert_rewritten(filtered, decision)
        code, _, console = self.run_custom_cli()
        self.assertEqual(code, 0)
        self.assertIn("suspicious attempt", console)

    def test_json_depth_boundary(self):
        self.assertIsInstance(bounded_json_loads('[' * MAX_JSON_DEPTH + '0' + ']' * MAX_JSON_DEPTH), list)
        with self.assertRaisesRegex(ValueError, "nesting exceeds"):
            bounded_json_loads('[' * (MAX_JSON_DEPTH + 1) + '0' + ']' * (MAX_JSON_DEPTH + 1))
        self.assertEqual(bounded_json_loads(json.dumps('[' * 2000)), '[' * 2000)

    def test_deep_alert_becomes_insufficient_data(self):
        self.alert_path.write_text('[' * 2000 + '0' + ']' * 2000)
        filtered, decision = self.triage(self.record())
        self.assertEqual(decision["verdict"], "insufficient data")
        self.assert_rewritten(filtered, decision)

    def test_residual_backslash_is_uncertain(self):
        for path in ('..%2525255csecret', '..%2525255Csecret'):
            with self.subTest(path=path):
                self.assertEqual(normalize_path(path)["normalized_path"].lower(), '..%255csecret')
                self.check_path(path, "insufficient data")

    def test_residual_encoding_positive_wins(self):
        _, decision = self.triage(self.record(path='..%2525255csecret'), self.record(record_id="positive", path="../x"))
        self.assertEqual(decision["verdict"], "suspicious attempt")

    def test_benign_encoded_urls_not_inconclusive(self):
        for path in ('/a%20b', '/search?q=%252520', '/search?q=100%25', '/x%252541'):
            with self.subTest(path=path):
                self.check_path(path, "no supporting evidence")

    def test_backslash_two_pass_boundary_detected(self):
        self.check_path('..%255Csecret', "suspicious attempt")

    def test_completion_marker_checks_artifact_bytes(self):
        filtered, decision = self.triage(self.record(path="../x"))
        paths = self.assert_rewritten(filtered, decision)
        marker = paths[0].parent / "completion.json"
        first = marker.read_bytes()
        hashes = json.loads(first)
        for path in paths:
            self.assertEqual(hashes[path.name], hashlib.sha256(path.read_bytes()).hexdigest())
        write_artifacts(filtered, decision, output_dir=marker.parent)
        self.assertEqual(first, marker.read_bytes())

    def assert_publication_failure_safe(self, failure):
        filtered, decision = self.triage(self.record(path="../x"))
        output = self.alert_path.parent / "publication"
        write_artifacts(filtered, decision, output_dir=output)
        with failure:
            with self.assertRaises(OSError):
                write_artifacts(filtered, decision, output_dir=output)
        self.assertFalse((output / "completion.json").exists())
        proposal = output / "response_proposal.json"
        self.assertTrue(not proposal.exists() or json.loads(proposal.read_text()) is None)
        self.assertEqual(list(output.glob('.triage-*')), [])

    def test_preparation_failure_invalidates_old_proposal(self):
        self.assert_publication_failure_safe(patch('src.reporter.render_report', side_effect=ValueError('serialization failure')))

    def test_report_replace_failure_invalidates_old_proposal(self):
        replace = os.replace
        def fail(source, target):
            if Path(target).name == 'report.md':
                raise OSError('report replacement failure')
            return replace(source, target)
        self.assert_publication_failure_safe(patch('src.reporter.os.replace', side_effect=fail))

    def test_proposal_replace_failure_invalidates_old_proposal(self):
        replace = os.replace
        def fail(source, target):
            if Path(target).name == 'response_proposal.json':
                raise OSError('proposal replacement failure')
            return replace(source, target)
        self.assert_publication_failure_safe(patch('src.reporter.os.replace', side_effect=fail))

    def test_marker_replace_failure_invalidates_proposal(self):
        replace = os.replace
        def fail(source, target):
            if Path(target).name == 'completion.json':
                raise OSError('marker replacement failure')
            return replace(source, target)
        self.assert_publication_failure_safe(patch('src.reporter.os.replace', side_effect=fail))

    def test_write_failure_returns_nonzero(self):
        self.triage(self.record())
        with patch('src.reporter.os.replace', side_effect=OSError('disk failure')):
            code, output, console = self.run_custom_cli()
        self.assertEqual(code, 1)
        self.assertIn('Artifact publication incomplete', console)
        self.assertFalse((output / 'completion.json').exists())

    def test_report_replacement_never_truncates_previous_report(self):
        filtered, decision = self.triage(self.record())
        output = self.alert_path.parent / "atomic"
        write_artifacts(filtered, decision, output_dir=output)
        before = (output / 'report.md').read_bytes()
        with patch('src.reporter.os.replace', side_effect=OSError('disk failure')):
            with self.assertRaises(OSError):
                write_artifacts(filtered, decision, output_dir=output)
        self.assertEqual(before, (output / 'report.md').read_bytes())

    def test_malformed_alert_then_benign_replaces_prior_positive(self):
        output = self.alert_path.parent / "sequence"
        filtered, decision = self.triage(self.record(path='../x'))
        write_artifacts(filtered, decision, output_dir=output)
        self.alert_path.write_text('{')
        filtered, decision = self.triage(self.record())
        write_artifacts(filtered, decision, output_dir=output)
        self.assertIsNone(json.loads((output / 'response_proposal.json').read_text()))
        self.alert_path.write_text(json.dumps(self.alert))
        filtered, decision = self.triage(self.record())
        write_artifacts(filtered, decision, output_dir=output)
        self.assertIn('no supporting evidence', (output / 'report.md').read_text())
        self.assertIsNone(json.loads((output / 'response_proposal.json').read_text()))

    def test_cleanup_permission_failure_is_explicit(self):
        filtered, decision = self.triage(self.record(path="../x"))
        output = self.alert_path.parent / "permissions"
        write_artifacts(filtered, decision, output_dir=output)
        with patch('src.reporter.Path.unlink', side_effect=PermissionError('cleanup denied')):
            with patch('src.reporter._atomic_write', side_effect=PermissionError('write denied')):
                with self.assertRaisesRegex(OSError, 'cleanup failed'):
                    write_artifacts(filtered, decision, output_dir=output)
        # If the filesystem denies all cleanup, old files can remain: callers
        # must check the failed invocation, not merely trust an existing marker.
        self.assertTrue((output / 'completion.json').exists())


if __name__ == "__main__":
    unittest.main()
