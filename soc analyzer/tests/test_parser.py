import json
from pathlib import Path

import pytest

from analyzer.parser import parse_line, parse_log_file


def test_parses_ssh_iso_line():
    event = parse_line("2026-09-01 02:45:04 sshd[1]: Failed password for root from 185.220.101.45 port 22 ssh2", 1)
    assert event["user"] == "root"
    assert event["status"] == "failed"
    assert event["ip"] == "185.220.101.45"


def test_parses_apache_line():
    event = parse_line('192.0.2.5 - - [01/Sep/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 12', 1)
    assert event["action"] == "GET"
    assert event["status"] == "success"


def test_parses_json_line():
    line = json.dumps({"@timestamp": "2026-09-02T10:00:00Z", "username": "alex", "source_ip": "192.0.2.7", "outcome": "failure"})
    assert parse_line(line, 1)["status"] == "failed"


def test_parses_csv_line():
    event = parse_line("2026-09-02T10:00:00Z,alex,192.0.2.8,US,login,success", 1)
    assert event["country"] == "US"


def test_parses_generic_firewall_block():
    event = parse_line("2026-09-01 12:03:00 kernel: [UFW BLOCK] IN=eth0 SRC=45.155.204.12 DST=10.0.0.5", 1)
    assert event["action"] == "firewall"
    assert event["status"] == "failed"


def test_parses_sudo_fields():
    event = parse_line(
        "2026-09-01 12:00:00 sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=wget http://example.test/a",
        1,
    )
    assert event["user"] == "alice"
    assert event["tty"] == "pts/0"
    assert event["pwd"] == "/home/alice"
    assert event["command"].startswith("wget ")


def test_parses_host_prefixed_sudo_fields():
    event = parse_line(
        "Jun 12 03:15:02 web01 sudo: root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/wget http://example.test/a -O /tmp/a",
        1,
    )
    assert event["user"] == "root"
    assert event["action"] == "privilege"
    assert event["command"].endswith("-O /tmp/a")


def test_parses_syslog_process_as_unclassified():
    event = parse_line("2026-09-01 12:00:00 host1 auditd[42]: policy decision recorded", 1)
    assert event["event_type"] == "unclassified"
    assert event["process"] == "auditd"
    assert event["pid"] == "42"


def test_tracks_ssh_session_duration(tmp_path: Path):
    log = tmp_path / "session.log"
    log.write_text(
        "2026-09-01 12:00:00 host1 sshd[42]: pam_unix(sshd:session): session opened for user alice(uid=1000)\n"
        "2026-09-01 12:02:05 host1 sshd[42]: pam_unix(sshd:session): session closed for user alice\n",
        encoding="utf-8",
    )
    events, errors = parse_log_file(log)
    assert not errors
    assert events[0]["event_type"] == "ssh_session"
    assert events[1]["session_duration_seconds"] == 125


def test_propagates_auth_ip_through_ssh_session(tmp_path: Path):
    log = tmp_path / "session-context.log"
    log.write_text(
        "Jun 12 03:14:41 web01 sshd[10333]: Accepted password for root from 185.220.101.47 port 51522 ssh2\n"
        "Jun 12 03:14:41 web01 sshd[10333]: pam_unix(sshd:session): session opened for user root by (uid=0)\n"
        "Jun 12 03:15:02 web01 sudo: root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/tmp/update.sh\n"
        "Jun 12 03:15:40 web01 sshd[10333]: pam_unix(sshd:session): session closed for user root\n",
        encoding="utf-8",
    )
    events, errors = parse_log_file(log)
    assert not errors
    assert events[1]["ip"] == "185.220.101.47"
    assert events[2]["ip"] == "185.220.101.47"
    assert events[3]["ip"] == "185.220.101.47"
    assert events[2]["session_pid"] == "10333"


def test_normalizes_new_log_event_types():
    log = Path("tests/fixtures/sample_incident.log")
    events, errors = parse_log_file(log)
    assert not errors
    assert next(event for event in events if event.get("event_type") == "geoip_change")["ip"] == "41.202.19.63"
    assert len([event for event in events if event.get("event_type") == "firewall_block"]) == 7
    assert len([event for event in events if event.get("event_type") == "beacon"]) == 4
    assert next(event for event in events if event.get("event_type") == "web_access")["ip"] == "41.202.19.63"


def test_malformed_lines_fail_gracefully(tmp_path: Path):
    log = tmp_path / "bad.log"
    log.write_text("not a supported event\n", encoding="utf-8")
    events, errors = parse_log_file(log)
    assert events == []
    assert errors == ["Line 1: unsupported log format; no recognized timestamp or structured fields"]


@pytest.mark.parametrize("line", [
    "2026-09-01 sshd: Failed password",
    "192.0.2.5 - - malformed apache entry",
    '{"timestamp":"not-a-date","ip":"192.0.2.1"}',
    "not,a,valid,csv,row",
    "2026-09-01 12:00:00 unrelated: no source address",
])
def test_each_supported_format_rejects_malformed_input(line):
    assert parse_line(line, 1) is None
