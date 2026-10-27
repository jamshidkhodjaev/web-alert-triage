"""Pipeline regression tests using isolated JSON/JSONL files.

Run from the repository root: python3 -m unittest discover -s tests -v
or: python3 -m pytest
"""

import contextlib
import io
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from src.heuristics import evaluate_alert, normalize_path
from src.parser import filter_logs_for_alert, main
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
        self.assertEqual(normalize_path(path)["normalized_path"], "%252e%252e%252f")
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


if __name__ == "__main__":
    unittest.main()
