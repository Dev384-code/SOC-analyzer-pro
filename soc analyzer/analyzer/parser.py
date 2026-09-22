import csv
import json
import re
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path

NORMALIZED_PATTERN = re.compile(
    r"^(?P<timestamp>\S+)\s+user=(?P<user>\S+)\s+ip=(?P<ip>\S+)"
    r"\s+country=(?P<country>\S+)\s+action=(?P<action>\S+)\s+status=(?P<status>\S+)$"
)
SSH_PATTERN = re.compile(
    r"^(?P<timestamp>(?:\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}|[A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+))\s+"
    r"(?:(?P<host>\S+)\s+)?sshd(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<verb>Failed|Accepted)\s+\S+\s+for\s+(?:invalid\s+user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>[^\s]+)"
)
SUDO_PATTERN = re.compile(
    r"^(?P<timestamp>(?:\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}|[A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+))\s+"
    r"(?:(?P<host>\S+)\s+)?sudo(?:\[(?P<pid>\d+)\])?:\s+(?P<user>\S+)\s*:\s*"
    r"TTY=(?P<tty>[^;]+)\s*;\s*PWD=(?P<pwd>[^;]+)\s*;\s*"
    r"(?:USER=(?P<target_user>[^;]+)\s*;\s*)?COMMAND=(?P<command>.+)$"
)
SYSLOG_PROCESS_PATTERN = re.compile(
    r"^(?P<timestamp>(?:\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}|[A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+))\s+"
    r"(?P<host>\S+)\s+(?P<process>[\w.-]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.*)$"
)
APACHE_PATTERN = re.compile(
    r"^(?P<ip>[^\s]+)\s+\S+\s+\S+\s+\[(?P<timestamp>[^]]+)\]\s+"
    r"\"(?P<request>[^\"]+)\"\s+(?P<status>\d{3})"
)
ISO_PREFIX_PATTERN = re.compile(r"^(?P<timestamp>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})\s+(?P<body>.*)$")
IP_PATTERN = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
WEB_ACTION_PATTERN = re.compile(r"(?:\"(?:GET|POST|PUT|DELETE|PATCH)\s+|/(?:wp-|admin|login|search|product))", re.IGNORECASE)


def _iso_timestamp(value: str, syslog: bool = False) -> str:
    if syslog:
        year = datetime.now(timezone.utc).year
        parsed = datetime.strptime(f"{year} {value}", "%Y %b %d %H:%M:%S")
    else:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.isoformat()


def _event(timestamp, user, ip, country, action, status, line_number):
    normalized_status = str(status).lower()
    if normalized_status in {"ok", "allowed", "accepted", "success", "succeeded", "200", "201"}:
        normalized_status = "success"
    elif normalized_status in {"failed", "failure", "denied", "block", "blocked", "error", "401", "403"}:
        normalized_status = "failed"
    return {"timestamp": _iso_timestamp(timestamp), "user": user or "unknown", "ip": ip,
            "country": country or "UNKNOWN", "action": action or "login",
            "status": normalized_status, "line": line_number}


def _parse_json(line, line_number):
    try:
        value = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(value, dict):
        return None
    timestamp = value.get("timestamp") or value.get("time") or value.get("@timestamp")
    ip = value.get("ip") or value.get("source_ip") or value.get("client_ip") or value.get("src_ip")
    user = value.get("user") or value.get("username") or value.get("account")
    status = value.get("status") or value.get("result") or value.get("outcome")
    if isinstance(value.get("success"), bool):
        status = "success" if value["success"] else "failed"
    if timestamp and ip and status:
        return _event(str(timestamp), str(user or "unknown"), str(ip), str(value.get("country", "UNKNOWN")),
                      str(value.get("action") or value.get("event") or "login"), str(status), line_number)
    return None


def _parse_csv(line, line_number):
    try:
        fields = next(csv.reader(StringIO(line)))
    except (csv.Error, StopIteration):
        return None
    if len(fields) != 6 or fields[0].lower() in {"timestamp", "time", "date"}:
        return None
    try:
        timestamp, user, ip, country, action, status = [field.strip() for field in fields]
        _iso_timestamp(timestamp)
    except (ValueError, TypeError):
        return None
    return _event(timestamp, user, ip, country, action, status, line_number)


def _parse_generic_security_line(line, line_number):
    match = ISO_PREFIX_PATTERN.match(line)
    if not match:
        return None
    body = match.group("body")
    ip_match = IP_PATTERN.search(body)
    lowered = body.lower()
    supported_without_ip = any(keyword in lowered for keyword in ("sudo", "usermod", "useradd", "powershell", "lolbin"))
    if not ip_match and not supported_without_ip:
        return None
    user_match = re.search(r"(?:for|user|account|host)\s+(?:user\s+)?([A-Za-z0-9_.-]+)", body, re.IGNORECASE)
    if not user_match:
        user_match = re.search(r"\(([A-Za-z0-9_.-]+)\)", body)
    if "failed" in lowered or "block" in lowered or "denied" in lowered:
        status = "failed"
    elif "accepted" in lowered or "success" in lowered:
        status = "success"
    else:
        status = "alert"
    if "sudo" in lowered or "usermod" in lowered or "useradd" in lowered:
        action = "privilege"
    elif "process" in lowered or "powershell" in lowered or "lolbin" in lowered:
        action = "process"
    elif "transfer" in lowered or "outbound" in lowered or "bytes_out" in lowered:
        action = "data_transfer"
    elif "beacon" in lowered or "heartbeat" in lowered or "c2" in lowered:
        action = "c2"
    elif "ufw" in lowered or "firewall" in lowered:
        action = "firewall"
    else:
        action = "security_event"
    return _event(match.group("timestamp"), user_match.group(1) if user_match else "unknown",
                  ip_match.group(0) if ip_match else "UNKNOWN", "UNKNOWN", action, status, line_number)


def _parse_sudo_line(line, line_number):
    match = SUDO_PATTERN.match(line)
    if not match:
        return None
    values = match.groupdict()
    timestamp = values["timestamp"]
    if not timestamp[0].isdigit():
        timestamp = _iso_timestamp(timestamp, syslog=True)
    event = _event(timestamp, values["user"], "UNKNOWN", "UNKNOWN", "privilege", "alert", line_number)
    event.update({
        "host": values.get("host"),
        "pid": values.get("pid"),
        "tty": values["tty"].strip(),
        "pwd": values["pwd"].strip(),
        "command": values["command"].strip(),
        "target_user": (values.get("target_user") or "").strip(),
    })
    return event


def _parse_syslog_process_line(line, line_number):
    match = SYSLOG_PROCESS_PATTERN.match(line)
    if not match:
        return None
    values = match.groupdict()
    timestamp = values["timestamp"]
    if not timestamp[0].isdigit():
        timestamp = _iso_timestamp(timestamp, syslog=True)
    event = _event(timestamp, "unknown", "UNKNOWN", "UNKNOWN", "unclassified", "info", line_number)
    event.update({
        "host": values["host"],
        "process": values["process"],
        "pid": values.get("pid"),
        "message": values["message"],
        "event_type": "unclassified",
    })
    message = values["message"]
    if values["process"].lower() in {"nginx", "apache", "httpd"}:
        access_match = APACHE_PATTERN.match(message)
        if access_match:
            access = access_match.groupdict()
            status_code = int(access["status"])
            event.update({
                "ip": access["ip"],
                "action": access["request"].split()[0],
                "status": "failed" if status_code in {401, 403} else "success",
                "request": access["request"],
                "event_type": "web_access",
            })
    elif values["process"].lower() == "kernel" and "ufw block" in message.lower():
        source_ip = re.search(r"\bSRC=(?P<ip>[^\s]+)", message)
        destination_ip = re.search(r"\bDST=(?P<ip>[^\s]+)", message)
        destination_port = re.search(r"\bDPT=(?P<port>\d+)", message)
        if source_ip and destination_ip and destination_port:
            event.update({
                "ip": source_ip.group("ip"),
                "action": "firewall",
                "status": "failed",
                "destination_ip": destination_ip.group("ip"),
                "destination_port": int(destination_port.group("port")),
                "event_type": "firewall_block",
            })
    elif values["process"].lower() in {"geoip", "geolocation"}:
        geo_match = re.search(
            r"login for user (?P<user>\S+) previously seen from (?P<previous>[A-Za-z]{2,})[, ]+now seen from (?P<current>[A-Za-z]{2,})",
            message,
            re.IGNORECASE,
        )
        if geo_match:
            event.update({
                "user": geo_match.group("user"),
                "action": "country_change",
                "status": "alert",
                "previous_country": geo_match.group("previous").upper(),
                "country": geo_match.group("current").upper(),
                "event_type": "geoip_change",
            })
    elif "beacon" in message.lower() or "check-in" in message.lower():
        endpoint = re.search(r"\b(?P<ip>(?:\d{1,3}\.){3}\d{1,3}):(?P<port>\d+)\b", message)
        if endpoint:
            event.update({
                "ip": endpoint.group("ip"),
                "action": "c2",
                "status": "alert",
                "destination_port": int(endpoint.group("port")),
                "event_type": "beacon",
            })
    return event


def _parse_session_line(line, line_number):
    event = _parse_syslog_process_line(line, line_number)
    if not event or event["process"] != "sshd":
        return None
    match = re.search(r"pam_unix\(sshd:session\): session (opened|closed) for user ([^\s(]+)", event["message"])
    if not match:
        return None
    state, user = match.groups()
    event.update({
        "user": user,
        "action": "session",
        "status": "success" if state == "opened" else "info",
        "session_state": state,
        "event_type": "ssh_session",
    })
    return event


def parse_line(line: str, line_number: int) -> dict | None:
    stripped = line.strip()
    match = NORMALIZED_PATTERN.match(stripped)
    if match:
        values = match.groupdict()
        event = _event(values["timestamp"], values["user"], values["ip"], values["country"],
                   values["action"], values["status"], line_number)
        event["raw"] = stripped
        return event

    json_event = _parse_json(stripped, line_number)
    if json_event:
        json_event["raw"] = stripped
        return json_event

    csv_event = _parse_csv(stripped, line_number)
    if csv_event:
        csv_event["raw"] = stripped
        return csv_event

    match = SSH_PATTERN.match(stripped)
    if match:
        values = match.groupdict()
        syslog_timestamp = not values["timestamp"][0].isdigit()
        event = _event(_iso_timestamp(values["timestamp"], syslog=syslog_timestamp), values["user"], values["ip"], "UNKNOWN", "login",
                      "success" if values["verb"].lower() == "accepted" else "failed", line_number)
        event["host"] = values.get("host")
        event["pid"] = values.get("pid")
        event["raw"] = stripped
        return event

    sudo_event = _parse_sudo_line(stripped, line_number)
    if sudo_event:
        sudo_event["raw"] = stripped
        return sudo_event

    session_event = _parse_session_line(stripped, line_number)
    if session_event:
        session_event["raw"] = stripped
        return session_event

    process_event = _parse_syslog_process_line(stripped, line_number)
    if process_event:
        process_event["raw"] = stripped
        return process_event

    match = APACHE_PATTERN.match(stripped)
    if match:
        values = match.groupdict()
        status_code = int(values["status"])
        event = _event(datetime.strptime(values["timestamp"], "%d/%b/%Y:%H:%M:%S %z").isoformat(),
                       "unknown", values["ip"], "UNKNOWN", values["request"].split()[0],
                       "failed" if status_code in {401, 403} else "success", line_number)
        event["request"] = values["request"]
        event["raw"] = stripped
        return event

    generic_event = _parse_generic_security_line(stripped, line_number)
    if generic_event:
        generic_event["raw"] = stripped
    return generic_event


def parse_log_file(path: Path) -> tuple[list[dict], list[str]]:
    events = []
    errors = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        event = parse_line(line, line_number)
        if event:
            events.append(event)
        else:
            errors.append(f"Line {line_number}: unsupported log format; no recognized timestamp or structured fields")
    auth_contexts = {}
    active_sessions = {}
    for event in events:
        host = event.get("host")
        pid = event.get("pid")
        if event.get("action") == "login":
            if event["status"] == "success":
                auth_contexts[(host, pid)] = {
                    "user": event["user"],
                    "ip": event["ip"],
                    "host": host,
                    "pid": pid,
                    "timestamp": event["timestamp"],
                }
            continue
        if event.get("event_type") == "ssh_session":
            context = auth_contexts.get((host, pid))
            if context is None:
                candidates = [item for item in auth_contexts.values()
                              if item["host"] == host and item["user"] == event["user"]
                              and item["timestamp"] <= event["timestamp"]]
                context = max(candidates, key=lambda item: item["timestamp"], default=None)
            if context:
                event["ip"] = context["ip"]
                event["session_source_ip"] = context["ip"]
                event["session_pid"] = context["pid"]
            key = (host, event["user"])
            if event["session_state"] == "opened":
                active_sessions[key] = event
            elif key in active_sessions:
                opened = active_sessions.pop(key)
                event["session_duration_seconds"] = int(
                    (datetime.fromisoformat(event["timestamp"]) - datetime.fromisoformat(opened["timestamp"])).total_seconds()
                )
                event["session_source_ip"] = opened.get("session_source_ip", event["ip"])
                event["ip"] = event["session_source_ip"]
            continue
        if event.get("user") != "unknown" and host:
            candidates = [session for (session_host, session_user), session in active_sessions.items()
                          if session_host == host and session_user == event["user"]]
            if candidates:
                session = max(candidates, key=lambda item: item["timestamp"])
                event["ip"] = session.get("session_source_ip", session["ip"])
                event["session_source_ip"] = event["ip"]
                event["session_pid"] = session.get("session_pid", session.get("pid"))
    return events, errors
