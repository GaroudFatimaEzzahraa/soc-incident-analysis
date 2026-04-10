# preprocessing.py
# Rôle : transformer une alerte Wazuh brute (JSON complexe)
# en un dictionnaire simple et normalisé utilisable par la corrélation.

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


# ─────────────────────────────────────────────────────────────
# MITRE_FALLBACK
# Utilisé uniquement si Wazuh n'a pas fourni le mapping MITRE.
# ─────────────────────────────────────────────────────────────
MITRE_FALLBACK: Dict[str, Dict[str, str]] = {
    "ssh_failed":            {"tactic": "Credential Access",    "technique": "T1110", "technique_name": "Brute Force"},
    "ssh_success":           {"tactic": "Initial Access",       "technique": "T1078", "technique_name": "Valid Accounts"},
    "login_session_opened":  {"tactic": "Initial Access",       "technique": "T1078", "technique_name": "Valid Accounts"},
    "login_session_closed":  {"tactic": "Defense Evasion",      "technique": "T1078", "technique_name": "Account Logoff"},
    "sudo_root_executed":    {"tactic": "Privilege Escalation", "technique": "T1548", "technique_name": "Abuse Elevation Control"},
    "sudo_activity":         {"tactic": "Privilege Escalation", "technique": "T1548", "technique_name": "Abuse Elevation Control"},
    "file_added":            {"tactic": "Defense Evasion",      "technique": "T1565", "technique_name": "Data Manipulation"},
    "file_modified":         {"tactic": "Defense Evasion",      "technique": "T1565", "technique_name": "Data Manipulation"},
    "process_created":       {"tactic": "Execution",            "technique": "T1059", "technique_name": "Command and Scripting Interpreter"},
    "network_connection":    {"tactic": "Command and Control",  "technique": "T1071", "technique_name": "Application Layer Protocol"},
    "other":                 {"tactic": "Unknown",              "technique": "T0000", "technique_name": "Unknown"},
}

# ─────────────────────────────────────────────────────────────
# Rule IDs considérés intéressants pour la corrélation
# ─────────────────────────────────────────────────────────────
RELEVANT_RULE_IDS = {
    "5501", "5502", "5715", "5716", "5710",
    "5402", "5403", "2502", "2503",
}

# ─────────────────────────────────────────────────────────────
# Mapping rule_id -> event_type
# ─────────────────────────────────────────────────────────────
RULE_ID_TO_EVENT_TYPE: Dict[str, str] = {
    "5715": "ssh_success",
    "5716": "ssh_failed",
    "5710": "ssh_failed",
    "5501": "login_session_opened",
    "5502": "login_session_closed",
    "5402": "sudo_root_executed",
    "5403": "sudo_activity",
    "2502": "file_added",
    "2503": "file_modified",
}


def get_nested(data: Dict[str, Any], path: List[str], default=None) -> Any:
    current = data
    for key in path:
        if isinstance(current, dict) and key in current:
            current = current[key]
        else:
            return default
    return current


def parse_timestamp(raw_ts: Optional[str]) -> Optional[str]:
    if not raw_ts:
        return None

    try:
        ts = str(raw_ts).replace("Z", "+00:00").replace("+0000", "+00:00")
        dt = datetime.fromisoformat(ts)
        return dt.astimezone(timezone.utc).isoformat()
    except (ValueError, TypeError):
        return raw_ts


def infer_event_type(rule_id: str, rule_description: str, full_log: str) -> str:
    if rule_id in RULE_ID_TO_EVENT_TYPE:
        return RULE_ID_TO_EVENT_TYPE[rule_id]

    desc = (rule_description or "").lower()
    log = (full_log or "").lower()
    text = f"{desc} {log}"

    if "pam" in text and "session opened" in text:
        return "login_session_opened"
    if "pam" in text and "session closed" in text:
        return "login_session_closed"
    if "sshd" in text and ("accepted password" in text or "accepted publickey" in text):
        return "ssh_success"
    if "sshd" in text and ("failed password" in text or "invalid user" in text):
        return "ssh_failed"
    if "sudo" in text and "root" in text and "command" in text:
        return "sudo_root_executed"
    if "sudo" in text:
        return "sudo_activity"
    if "file added" in text or "new file" in text:
        return "file_added"
    if "file modified" in text or "modified" in text:
        return "file_modified"
    if "process created" in text or "new process" in text:
        return "process_created"
    if "connection" in text or "network" in text:
        return "network_connection"
    return "other"


def extract_src_ip(raw_alert: Dict[str, Any]) -> Optional[str]:
    candidates = [
        get_nested(raw_alert, ["data", "srcip"]),
        get_nested(raw_alert, ["data", "src_ip"]),
        get_nested(raw_alert, ["srcip"]),
    ]
    for ip in candidates:
        if ip and str(ip) not in ("127.0.0.1", "::1", "unknown", ""):
            return str(ip)
    return None


def extract_dst_user(raw_alert: Dict[str, Any]) -> Optional[str]:
    candidates = [
        get_nested(raw_alert, ["data", "dstuser"]),
        get_nested(raw_alert, ["data", "dstUser"]),
        get_nested(raw_alert, ["dstuser"]),
    ]
    for user in candidates:
        if user and str(user) not in ("unknown", ""):
            return str(user)
    return None


def preprocess_alert(raw_alert: Dict[str, Any]) -> Dict[str, Any]:
    rule_id = str(get_nested(raw_alert, ["rule", "id"], "0"))
    rule_level = int(get_nested(raw_alert, ["rule", "level"], 0))
    rule_description = get_nested(raw_alert, ["rule", "description"], "") or ""
    full_log = raw_alert.get("full_log", "") or ""

    event_type = infer_event_type(rule_id, rule_description, full_log)

    mitre_raw = get_nested(raw_alert, ["rule", "mitre"], {}) or {}
    mitre_ids = mitre_raw.get("id", [])
    mitre_tacts = mitre_raw.get("tactic", [])
    mitre_techs = mitre_raw.get("technique", [])

    if mitre_tacts:
        mitre_tactic = mitre_tacts[0] if isinstance(mitre_tacts, list) else mitre_tacts
        mitre_technique = (
            mitre_ids[0] if isinstance(mitre_ids, list) and mitre_ids else mitre_ids
        ) or MITRE_FALLBACK.get(event_type, MITRE_FALLBACK["other"])["technique"]
        mitre_technique_name = (
            mitre_techs[0] if isinstance(mitre_techs, list) and mitre_techs else mitre_techs
        ) or MITRE_FALLBACK.get(event_type, MITRE_FALLBACK["other"])["technique_name"]
    else:
        fb = MITRE_FALLBACK.get(event_type, MITRE_FALLBACK["other"])
        mitre_tactic = fb["tactic"]
        mitre_technique = fb["technique"]
        mitre_technique_name = fb["technique_name"]

    return {
        "timestamp": parse_timestamp(raw_alert.get("timestamp")),
        "rule_id": rule_id,
        "rule_level": rule_level,
        "rule_description": rule_description,
        "event_type": event_type,
        "agent_name": get_nested(raw_alert, ["agent", "name"], "unknown"),
        "agent_ip": get_nested(raw_alert, ["agent", "ip"], "unknown"),
        "src_ip": extract_src_ip(raw_alert),
        "dst_user": extract_dst_user(raw_alert),
        "full_log": full_log,
        "mitre_tactic": mitre_tactic,
        "mitre_technique": mitre_technique,
        "mitre_technique_name": mitre_technique_name,
    }


def is_relevant_alert(alert: Dict[str, Any]) -> bool:
    useful_event_types = {
        "ssh_failed", "ssh_success",
        "login_session_opened", "login_session_closed",
        "sudo_root_executed", "sudo_activity",
        "file_added", "file_modified",
        "process_created", "network_connection",
    }
    return (
        alert.get("event_type") in useful_event_types
        or alert.get("rule_id") in RELEVANT_RULE_IDS
        or int(alert.get("rule_level", 0)) >= 7
    )


def format_pretty(alert: Dict[str, Any]) -> str:
    return json.dumps(alert, indent=2, ensure_ascii=False)
