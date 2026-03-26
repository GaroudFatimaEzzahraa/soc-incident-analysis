import json
from typing import Any, Dict, List, Optional


def get_nested(data: Dict[str, Any], path: List[str], default=None):
    """
    Safely get a nested value from a dictionary.
    Example:
        get_nested(alert, ["rule", "id"])
    """
    current = data
    for key in path:
        if isinstance(current, dict) and key in current:
            current = current[key]
        else:
            return default
    return current


def infer_event_type(rule_description: str, full_log: str) -> str:
    """
    Infer a simplified event type from Wazuh alert content.
    """
    rule_desc = (rule_description or "").lower()
    log_text = (full_log or "").lower()
    text = f"{rule_desc} {log_text}"

    # PAM session events first
    if "pam: login session opened" in rule_desc or "session opened for user" in log_text:
        return "login_session_opened"

    if "pam: login session closed" in rule_desc or "session closed for user" in log_text:
        return "login_session_closed"

    # SSH authentication events
    if "sshd" in text and ("authentication success" in text or "accepted password" in text):
        return "ssh_success"

    if "sshd" in text and (
        "authentication failed" in text
        or "failed password" in text
        or "invalid user" in text
    ):
        return "ssh_failed"

    # Sudo events
    if "successful sudo to root executed" in rule_desc:
        return "sudo_root_executed"

    if "sudo" in text:
        return "sudo_activity"

    # Generic fallback
    return "other"


def is_relevant_alert(processed_alert: Dict[str, Any]) -> bool:
    """
    Keep only alerts useful for correlation in this project.
    You can relax this later if needed.
    """
    useful_event_types = {
        "login_session_opened",
        "login_session_closed",
        "ssh_success",
        "ssh_failed",
        "sudo_root_executed",
        "sudo_activity",
    }

    useful_rule_ids = {
        "5501",  # PAM: Login session opened
        "5502",  # PAM: Login session closed
        "5715",  # sshd: authentication success
        "5716",  # sshd: authentication failed (may vary depending on ruleset)
        "5402",  # Successful sudo to ROOT executed
    }

    event_type = processed_alert.get("event_type")
    rule_id = processed_alert.get("rule_id")

    return event_type in useful_event_types or rule_id in useful_rule_ids


def preprocess_alert(raw_alert: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convert a raw Wazuh alert into a simplified normalized alert.
    """
    timestamp = raw_alert.get("timestamp")

    rule_id = str(get_nested(raw_alert, ["rule", "id"], "unknown"))
    rule_level = get_nested(raw_alert, ["rule", "level"], 0)
    rule_description = get_nested(raw_alert, ["rule", "description"], "unknown")

    agent_name = get_nested(raw_alert, ["agent", "name"], "unknown")
    agent_ip = get_nested(raw_alert, ["agent", "ip"], "unknown")

    src_ip = get_nested(raw_alert, ["data", "srcip"])
    if src_ip is None:
        src_ip = get_nested(raw_alert, ["srcip"], None)

    dst_user = get_nested(raw_alert, ["data", "dstuser"])
    if dst_user is None:
        dst_user = get_nested(raw_alert, ["dstuser"], None)

    full_log = raw_alert.get("full_log", "")

    mitre_id = get_nested(raw_alert, ["rule", "mitre", "id"], [])
    mitre_tactic = get_nested(raw_alert, ["rule", "mitre", "tactic"], [])
    mitre_technique = get_nested(raw_alert, ["rule", "mitre", "technique"], [])

    event_type = infer_event_type(rule_description, full_log)

    processed_alert = {
        "timestamp": timestamp,
        "rule_id": rule_id,
        "rule_level": rule_level,
        "rule_description": rule_description,
        "agent_name": agent_name,
        "agent_ip": agent_ip,
        "src_ip": src_ip,
        "dst_user": dst_user,
        "event_type": event_type,
        "full_log": full_log,
        "mitre_id": mitre_id,
        "mitre_tactic": mitre_tactic,
        "mitre_technique": mitre_technique,
    }

    return processed_alert


def format_pretty(alert: Dict[str, Any]) -> str:
    """
    Pretty-print a preprocessed alert.
    """
    return json.dumps(alert, indent=2, ensure_ascii=False)
