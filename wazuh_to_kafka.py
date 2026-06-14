import json
import subprocess
import re
from kafka import KafkaProducer

ALERT_FILE = "/var/ossec/logs/alerts/alerts.json"
TOPIC = "security-alerts"
BROKER = "127.0.0.1:9092"

producer = KafkaProducer(
    bootstrap_servers=BROKER,
    value_serializer=lambda v: json.dumps(v).encode("utf-8")
)

print("WAZUH -> KAFKA STARTED")


def extract_ip_from_log(full_log):
    if not full_log:
        return "unknown"

    patterns = [
        r"from\s+(\d+\.\d+\.\d+\.\d+)",
        r"rhost=(\d+\.\d+\.\d+\.\d+)",
        r"srcip=(\d+\.\d+\.\d+\.\d+)",
        r"(\d+\.\d+\.\d+\.\d+)",
    ]

    for pattern in patterns:
        match = re.search(pattern, full_log)
        if match:
            return match.group(1)

    return "unknown"


process = subprocess.Popen(
    ["sudo", "tail", "-F", "-n", "0", ALERT_FILE],
    stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL,
    text=True,
    bufsize=1,
)

for raw_line in process.stdout:
    line = raw_line.rstrip("\n").strip()
    if not line:
        continue

    try:
        alert = json.loads(line)
    except json.JSONDecodeError:
        continue

    data = alert.get("data", {})
    full_log = alert.get("full_log", "")
    full_log_lower = full_log.lower()

    rule = alert.get("rule", {})
    rule_id = str(rule.get("id", ""))
    rule_desc = rule.get("description", "").lower()
    rule_groups = rule.get("groups", [])
    rule_groups_lower = [str(g).lower() for g in rule_groups]

    timestamp = alert.get("timestamp", "")

    src_ip = (
        data.get("srcip")
        or data.get("src_ip")
        or data.get("src")
        or extract_ip_from_log(full_log)
        or "unknown"
    )

    agent_name = alert.get("agent", {}).get("name", "")
    hostname = (
        agent_name
        or alert.get("predecoder", {}).get("hostname", "")
        or alert.get("manager", {}).get("name", "unknown_host")
    )

    # 1. SSH Brute Force / failed SSH authentication
    if (
        rule_id in ("5760", "5763", "2502", "5503", "5710", "5712")
        or "authentication_failed" in rule_groups_lower
        or "sshd" in rule_groups_lower and "failed" in rule_desc
        or "failed password" in full_log_lower
        or "authentication failure" in full_log_lower
        or "more authentication failures" in full_log_lower
        or "invalid user" in full_log_lower
    ):
        event_type = "ssh_bruteforce"
        severity = "HIGH"
        log_msg = full_log or rule_desc

    # 2. Login SSH réussi
    elif (
        rule_id in ("5715", "5716")
        or "accepted password" in full_log_lower
        or "accepted publickey" in full_log_lower
        or (
            "authentication_success" in rule_groups_lower
            and "sshd" in rule_groups_lower
        )
    ):
        event_type = "login_success"
        severity = "MEDIUM"
        log_msg = full_log or rule_desc

    # 3. Privilege escalation sudo/su
    elif (
        rule_id in ("5402", "5403", "5404", "5407", "5408")
        or "sudo" in rule_groups_lower
        or "pam" in rule_groups_lower
        or "privilege_escalation" in rule_groups_lower
        or "privilege-escalation" in rule_groups_lower
        or "sudo" in full_log_lower
        or "su:" in full_log_lower
        or "session opened for user root" in full_log_lower
        or "pam_unix(sudo:session)" in full_log_lower
        or "pam_unix(su:session)" in full_log_lower
        or "command=/usr/bin/su" in full_log_lower
        or "command=su" in full_log_lower
    ):
        event_type = "privilege_escalation"
        severity = "HIGH"
        log_msg = full_log or rule_desc

    # 4. Accès fichiers sensibles
    elif (
        rule_id in ("550", "554", "556")
        or "/etc/shadow" in full_log_lower
        or "/etc/passwd" in full_log_lower
        or "/etc/sudoers" in full_log_lower
        or "syscheck" in rule_groups_lower
    ):
        event_type = "sensitive_file_access"
        severity = "HIGH"
        log_msg = full_log or rule_desc

    # 5. Scan réseau
    elif (
        rule_id in ("40101", "40102", "40110", "40111")
        or "scan" in rule_desc
        or "port scan" in rule_desc
        or "nmap" in full_log_lower
    ):
        event_type = "port_scan"
        severity = "MEDIUM"
        log_msg = full_log or rule_desc

    else:
        continue

    event = {
        "event_type": event_type,
        "severity": severity,
        "source_ip": src_ip,
        "agent_id": hostname,
        "hostname": hostname,
        "log": log_msg,
        "timestamp": timestamp,
        "rule_id": rule_id,
        "rule_groups": rule_groups,
    }

    print(
        "SEND | " + event_type
        + " | ip=" + src_ip
        + " | host=" + hostname
        + " | rule=" + rule_id
    )

    producer.send(TOPIC, event)
    producer.flush()
