from collections import defaultdict
from datetime import datetime, timedelta
import re
from statistics import median

from config import (
    ACCOUNT_TAKEOVER_THRESHOLD,
    ACCOUNT_TAKEOVER_WINDOW_MINUTES,
    BRUTE_FORCE_THRESHOLD,
    BRUTE_FORCE_WINDOW_MINUTES,
    CORRELATION_WINDOW_SECONDS,
    POST_AUTH_COMMAND_WINDOW_SECONDS,
    SUSPICIOUS_IPS,
)

ATTACK_MAP = {
    "brute_force": {"technique_id": "T1110", "technique": "Brute Force", "tactic": "Credential Access"},
    "brute_force_escalated": {"technique_id": "T1110", "technique": "Brute Force", "tactic": "Credential Access"},
    "account_takeover": {"technique_id": "T1110", "technique": "Brute Force", "tactic": "Credential Access"},
    "suspicious_ip": {"technique_id": "T1071", "technique": "Application Layer Protocol", "tactic": "Command and Control"},
    "unusual_time": {"technique_id": "T1078", "technique": "Valid Accounts", "tactic": "Initial Access"},
    "country_change": {"technique_id": "T1078", "technique": "Valid Accounts", "tactic": "Initial Access"},
    "privilege_escalation": {"technique_id": "T1548", "technique": "Abuse Elevation Control Mechanism", "tactic": "Privilege Escalation"},
    "lolbin_execution": {"technique_id": "T1218", "technique": "System Binary Proxy Execution", "tactic": "Defense Evasion"},
    "c2_beaconing": {"technique_id": "T1071", "technique": "Application Layer Protocol", "tactic": "Command and Control"},
    "data_exfiltration": {"technique_id": "T1041", "technique": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"},
    "network_scan": {"technique_id": "T1046", "technique": "Network Service Scanning", "tactic": "Discovery"},
    "web_attack": {"technique_id": "T1190", "technique": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "post_auth_download_execute": {"technique_id": "T1105", "technique": "Ingress Tool Transfer", "tactic": "Command and Control"},
}
WEB_ATTACK_PATTERNS = re.compile(r"(?:'\s*OR\s*'?[0-9]+['\"]?\s*=|UNION\s+SELECT|<script>|%3Cscript%3E|\.\./|;\s*DROP(?:\s+TABLE)?)", re.IGNORECASE)


def _finding(alert_type, severity, event, message, confidence="medium"):
    return {
        "type": alert_type,
        "severity": severity,
        "user": event["user"],
        "ip": event["ip"],
        "timestamp": event["timestamp"],
        "line": event.get("line"),
        "message": message,
        "confidence": confidence,
        "mitre": ATTACK_MAP[alert_type],
    }


def circular_hour_diff(h1: float, h2: float) -> float:
    diff = abs(h1 - h2) % 24.0
    return min(diff, 24.0 - diff)


def _timestamp(event):
    return datetime.fromisoformat(event["timestamp"])


def _correlate(findings):
    groups = defaultdict(list)
    for finding in findings:
        key = finding["user"] if finding["user"] != "unknown" else finding["ip"]
        groups[key].append(finding)
    for key, related in groups.items():
        types = sorted({finding["type"] for finding in related})
        times = [datetime.fromisoformat(finding["timestamp"]) for finding in related]
        if len(types) < 2 or max(times) - min(times) > timedelta(minutes=30):
            continue
        incident_id = f"INC-{key}-{min(item['line'] for item in related):04d}"
        for finding in related:
            finding["correlation"] = {
                "incident_id": incident_id,
                "related_detection_types": types,
                "window_minutes": 30,
            }


def detect(events: list[dict]) -> list[dict]:
    findings = []
    failed_by_ip = defaultdict(list)
    user_countries = defaultdict(set)
    user_hours = defaultdict(list)
    privilege_events = []

    for event in events:
        timestamp = _timestamp(event)
        user_hours[event["user"]].append(timestamp.hour + timestamp.minute / 60)
        if event["status"].lower() == "failed":
            failed_by_ip[event["ip"]].append(event)
        if event["country"].upper() not in {"UNKNOWN", "UN", "N/A", "-"}:
            user_countries[event["user"]].add(event["country"])
        if event["ip"] in SUSPICIOUS_IPS:
            findings.append(_finding("suspicious_ip", "high", event,
                                     f"Connection from known suspicious IP {event['ip']}", "high"))
        content = f"{event.get('request', '')} {event.get('raw', '')}"
        web_attack = WEB_ATTACK_PATTERNS.search(content)
        if web_attack:
            findings.append(_finding("web_attack", "high", event,
                                     "Web attack payload detected in request content", "high"))
        action = event["action"].lower()
        if action == "process" and event["status"] == "alert":
            findings.append(_finding("lolbin_execution", "high", event,
                                     "Suspicious LOLBin or encoded PowerShell execution detected", "high"))
        elif action == "privilege" and event["status"] == "alert":
            privilege_events.append(event)
        elif action == "data_transfer" and event["status"] == "alert":
            if not event.get("command"):
                findings.append(_finding("data_exfiltration", "high", event,
                                         "Potential large outbound transfer or external network connection", "medium"))
        elif action == "c2" and event["status"] == "alert":
            if event.get("event_type") != "beacon":
                findings.append(_finding("c2_beaconing", "medium", event,
                                         "Potential command-and-control beacon or heartbeat", "medium"))
        elif action == "firewall" and event["status"] == "failed":
            if event.get("event_type") != "firewall_block":
                findings.append(_finding("network_scan", "medium", event,
                                         f"Firewall blocked connection from {event['ip']}", "medium"))
        elif action == "country_change" and event["status"] == "alert":
            findings.append(_finding("country_change", "high", event,
                                     f"GeoIP changed from {event.get('previous_country', 'unknown')} to {event.get('country', 'unknown')} for {event['user']}", "high"))
        elif event["status"] == "alert" and not web_attack:
            findings.append(_finding("c2_beaconing", "medium", event,
                                     "Security log reported suspicious external activity", "low"))

    # A user-specific baseline avoids treating every off-hours event as suspicious.
    for user, hours in user_hours.items():
        if len(hours) < 3:
            continue
        baseline = median(hours)
        absolute_deviations = [circular_hour_diff(hour, baseline) for hour in hours]
        mad = median(absolute_deviations)
        allowed_deviation = max(2.0, mad * 3)
        for event in events:
            if event["user"] != user or event["status"] not in {"success", "failed"}:
                continue
            hour = _timestamp(event).hour + _timestamp(event).minute / 60
            if circular_hour_diff(hour, baseline) > allowed_deviation:
                findings.append(_finding("unusual_time", "medium", event,
                                         f"Login at {hour:04.1f} UTC deviates from {user}'s usual {baseline:04.1f} UTC pattern"))

    for ip, failures in failed_by_ip.items():
        failures.sort(key=_timestamp)
        last_alert_time = None
        for index in range(len(failures) - BRUTE_FORCE_THRESHOLD + 1):
            window = failures[index:index + BRUTE_FORCE_THRESHOLD]
            if _timestamp(window[-1]) - _timestamp(window[0]) <= timedelta(minutes=BRUTE_FORCE_WINDOW_MINUTES):
                if last_alert_time is None or _timestamp(window[-1]) - last_alert_time > timedelta(minutes=BRUTE_FORCE_WINDOW_MINUTES):
                    findings.append(_finding("brute_force", "critical", window[-1],
                                             f"{len(window)} failed login attempts within {BRUTE_FORCE_WINDOW_MINUTES} minutes", "high"))
                    last_alert_time = _timestamp(window[-1])
        escalation_size = BRUTE_FORCE_THRESHOLD * 2
        last_esc_time = None
        for index in range(len(failures) - escalation_size + 1):
            window = failures[index:index + escalation_size]
            if _timestamp(window[-1]) - _timestamp(window[0]) <= timedelta(minutes=BRUTE_FORCE_WINDOW_MINUTES):
                if last_esc_time is None or _timestamp(window[-1]) - last_esc_time > timedelta(minutes=BRUTE_FORCE_WINDOW_MINUTES):
                    findings.append(_finding("brute_force_escalated", "critical", window[-1],
                                             f"{len(window)} failed login attempts reached at least 2x the threshold of {BRUTE_FORCE_THRESHOLD}", "high"))
                    last_esc_time = _timestamp(window[-1])

    login_events = [event for event in events if event["action"].lower() == "login" and event["status"].lower() in {"success", "failed"}]
    suspicious_logins = []
    for success in login_events:
        if success["status"].lower() != "success":
            continue
        preceding_failures = [failure for failure in failed_by_ip[success["ip"]]
                              if failure["user"] == success["user"]
                              and _timestamp(failure) <= _timestamp(success)
                              and _timestamp(success) - _timestamp(failure) <= timedelta(minutes=ACCOUNT_TAKEOVER_WINDOW_MINUTES)]
        if len(preceding_failures) >= ACCOUNT_TAKEOVER_THRESHOLD:
            findings.append(_finding("account_takeover", "critical", success,
                                     f"Successful authentication followed {len(preceding_failures)} failed attempts from {success['ip']} for {success['user']}", "high"))
            suspicious_logins.append(success)
        elif success["ip"] in SUSPICIOUS_IPS or not any(
            event["user"] == success["user"] and event["ip"] == success["ip"]
            and _timestamp(event) < _timestamp(success) for event in login_events
        ):
            suspicious_logins.append(success)

    download_commands = re.compile(r"\b(?:wget|curl)\b.*?(?:-O|-o)\s+(?P<path>/[^\s;]+)", re.IGNORECASE)
    chmod_commands = re.compile(r"\bchmod\s+\+x\s+(?P<path>/[^\s;]+)", re.IGNORECASE)
    execute_command = re.compile(r"^\s*(?P<path>/[^\s;]+)(?:\s|$)")
    chain_lines = set()

    def session_key(event):
        return event.get("session_pid") or (event.get("host"), event.get("user"), event.get("ip"))

    for login in suspicious_logins:
        login_session = login.get("pid") or (login.get("host"), login.get("user"), login.get("ip"))
        commands = sorted([event for event in events
                           if event["action"].lower() == "privilege"
                           and event.get("user") == login.get("user")
                           and event.get("command")
                           and session_key(event) == login_session
                           and 0 <= (_timestamp(event) - _timestamp(login)).total_seconds() <= POST_AUTH_COMMAND_WINDOW_SECONDS], key=_timestamp)
        for index, command_event in enumerate(commands):
            download_match = download_commands.search(command_event["command"])
            if not download_match:
                continue
            chain = commands[index + 1:index + 3]
            chmod_match = chmod_commands.search(chain[0]["command"]) if len(chain) >= 1 else None
            execute_match = execute_command.match(chain[1]["command"]) if len(chain) >= 2 else None
            if not chmod_match or not execute_match:
                continue
            if not (download_match.group("path") == chmod_match.group("path") == execute_match.group("path")):
                continue
            finding = _finding("post_auth_download_execute", "critical", chain[1],
                               "Suspicious post-auth download, chmod, and execution chain", "high")
            finding["mitre_techniques"] = [
                {"technique_id": "T1105", "technique": "Ingress Tool Transfer"},
                {"technique_id": "T1204", "technique": "User Execution"},
            ]
            findings.append(finding)
            chain_lines.update(event.get("line") for event in [command_event, *chain])
            break

    archive_commands = re.compile(r"\b(?:tar|zip|gzip)\b", re.IGNORECASE)
    transfer_commands = re.compile(r"\b(?:curl\b.*\s-T\s|scp\b|ftp\b.*\b(?:put|upload)\b|rsync\b)", re.IGNORECASE)
    external_ip = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
    suspicious_endpoints = {match.group(0) for event in events
                            for match in external_ip.finditer(event.get("command", ""))}
    suspicious_endpoints.update(event["ip"] for event in events if event["action"].lower() == "c2" and event["ip"] != "UNKNOWN")
    exfil_lines = set()
    command_sessions = defaultdict(list)
    for event in events:
        if event.get("action") == "privilege" and event.get("command"):
            command_sessions[session_key(event)].append(event)
    for commands in command_sessions.values():
        commands.sort(key=_timestamp)
        for index, archive in enumerate(commands):
            if not archive_commands.search(archive["command"]):
                continue
            for transfer in commands[index + 1:]:
                if (_timestamp(transfer) - _timestamp(archive)).total_seconds() > CORRELATION_WINDOW_SECONDS:
                    break
                transfer_ips = set(external_ip.findall(transfer["command"]))
                if transfer_commands.search(transfer["command"]) and transfer_ips & suspicious_endpoints:
                    findings.append(_finding("data_exfiltration", "high", transfer,
                                             "Archive operation followed by outbound transfer to a suspicious external endpoint", "high"))
                    exfil_lines.update({archive.get("line"), transfer.get("line")})
                    break

    scan_groups = defaultdict(list)
    for event in events:
        if event.get("event_type") == "firewall_block" and event.get("destination_port") is not None:
            scan_groups[(event["ip"], event.get("destination_ip"))].append(event)
    for (source_ip, destination_ip), blocked in scan_groups.items():
        blocked.sort(key=_timestamp)
        for index in range(len(blocked) - 3):
            window = blocked[index:index + 4]
            if (_timestamp(window[-1]) - _timestamp(window[0])).total_seconds() <= 10 and len({item["destination_port"] for item in window}) >= 4:
                findings.append(_finding("network_scan", "medium", window[-1],
                                         f"{len({item['destination_port'] for item in window})} destination ports scanned on {destination_ip} from {source_ip}", "high"))
                break

    beacon_groups = defaultdict(list)
    for event in events:
        if event.get("event_type") == "beacon":
            beacon_groups[(event["ip"], event.get("destination_port"))].append(event)
    for (endpoint, port), beacons in beacon_groups.items():
        beacons.sort(key=_timestamp)
        for index in range(len(beacons) - 2):
            window = beacons[index:index + 3]
            intervals = [(b - a).total_seconds() for a, b in zip(map(_timestamp, window), map(_timestamp, window[1:]))]
            if max(intervals) - min(intervals) <= 60:
                findings.append(_finding("c2_beaconing", "medium", window[-1],
                                         f"Periodic outbound beaconing to {endpoint}:{port}", "high"))
                break

    for event in privilege_events:
        if event.get("line") in chain_lines or event.get("line") in exfil_lines:
            continue
        findings.append(_finding("privilege_escalation", "critical", event,
                                 "User or privilege-management activity requires review", "high"))

    for user, countries in user_countries.items():
        if len(countries) > 1:
            user_events = [event for event in events if event["user"] == user]
            latest = max(user_events, key=_timestamp)
            findings.append(_finding("country_change", "high", latest,
                                     f"Account accessed from {', '.join(sorted(countries))}", "medium"))
    _correlate(findings)
    return findings


def calculate_risk(events: list[dict], findings: list[dict]) -> int:
    weights = {"critical": 30, "high": 20, "medium": 10, "low": 5}
    failed = sum(event["status"].lower() == "failed" for event in events)
    return min(100, sum(weights.get(item["severity"], 0) for item in findings) + min(10, failed))
