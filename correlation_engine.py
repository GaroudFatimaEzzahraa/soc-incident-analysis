# correlation_engine.py

import json
import logging
import signal
import time
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from kafka import KafkaConsumer
from preprocessing import preprocess_alert, is_relevant_alert


# ============================================================
# CONFIGURATION
# ============================================================
KAFKA_TOPIC = "security-alerts"
KAFKA_BROKER = "localhost:9092"
KAFKA_GROUP_ID = "correlation-engine-final"


WINDOW_SECONDS = 300
FLUSH_CHECK_INTERVAL = 2

SSH_FAIL_MIN = 5
SUDO_MIN = 3

INCIDENT_OUTPUT_FILE = "incident_output.json"


# ============================================================
# LOGGING
# ============================================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("correlation_engine")
logging.getLogger("kafka").setLevel(logging.WARNING)


# ============================================================
# GLOBAL RUN FLAG
# ============================================================
RUNNING = True


def handle_shutdown(signum, frame):
    global RUNNING
    log.info("Signal d'arrêt reçu. Finalisation en cours...")
    RUNNING = False


signal.signal(signal.SIGINT, handle_shutdown)
signal.signal(signal.SIGTERM, handle_shutdown)


# ============================================================
# MITRE + SCORING
# ============================================================
MITRE_MAP = {
    "ssh_failed":           {"tactic": "Credential Access",    "technique": "T1110"},
    "ssh_success":          {"tactic": "Initial Access",       "technique": "T1078"},
    "login_session_opened": {"tactic": "Initial Access",       "technique": "T1078"},
    "login_session_closed": {"tactic": "Defense Evasion",      "technique": "T1078"},
    "sudo_root_executed":   {"tactic": "Privilege Escalation", "technique": "T1548"},
    "sudo_activity":        {"tactic": "Privilege Escalation", "technique": "T1548"},
    "file_modified":        {"tactic": "Defense Evasion",      "technique": "T1565"},
    "process_created":      {"tactic": "Execution",            "technique": "T1059"},
    "network_connection":   {"tactic": "Command and Control",  "technique": "T1071"},
    "other":                {"tactic": "Unknown",              "technique": "T0000"},
}

TACTIC_SCORE = {
    "Reconnaissance": 10,
    "Initial Access": 30,
    "Credential Access": 25,
    "Privilege Escalation": 40,
    "Defense Evasion": 35,
    "Execution": 30,
    "Command and Control": 45,
    "Lateral Movement": 50,
    "Exfiltration": 60,
    "Unknown": 5,
}


# ============================================================
# HELPERS
# ============================================================
def safe_json_deserializer(m: Optional[bytes]) -> Optional[Dict[str, Any]]:
    try:
        if m is None:
            return None

        text = m.decode("utf-8", errors="replace").strip()
        if not text:
            return None

        return json.loads(text)

    except json.JSONDecodeError:
        return None
    except Exception:
        return None


def parse_ts(ts: Optional[str]) -> datetime:
    if not ts:
        return datetime.now(tz=timezone.utc)
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except ValueError:
        return datetime.now(tz=timezone.utc)


def enrich_mitre(alert: Dict[str, Any]) -> Dict[str, Any]:
    enriched = dict(alert)

    if not enriched.get("mitre_tactic"):
        event_type = enriched.get("event_type", "other")
        mitre = MITRE_MAP.get(event_type, MITRE_MAP["other"])
        enriched["mitre_tactic"] = mitre["tactic"]
        enriched["mitre_technique"] = mitre["technique"]

    return enriched


def compute_severity(alerts: List[Dict[str, Any]]) -> str:
    score = 0

    for a in alerts:
        tactic = a.get("mitre_tactic", "Unknown")
        base = TACTIC_SCORE.get(tactic, 5)
        level = int(a.get("rule_level", 0))
        score += base + level

    if score >= 150:
        return "CRITICAL"
    if score >= 80:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"


def save_incidents_to_file(incidents: List[Dict[str, Any]]) -> None:
    try:
        with open(INCIDENT_OUTPUT_FILE, "w", encoding="utf-8") as f:
            json.dump(incidents, f, indent=2, ensure_ascii=False)
    except Exception as e:
        log.error("Erreur d'écriture de %s : %s", INCIDENT_OUTPUT_FILE, e)


# ============================================================
# CORRELATION KEY
# ============================================================
def choose_correlation_key(alert: Dict[str, Any]) -> str:
    """
    Clé de corrélation adaptée à ton lab :
    - si src_ip + dst_user existent => meilleur contexte
    - sinon src_ip + agent_name
    - sinon agent_name + dst_user
    - sinon agent_name
    """
    src_ip = alert.get("src_ip")
    dst_user = alert.get("dst_user")
    agent_name = alert.get("agent_name") or "unknown-agent"

    if src_ip and dst_user:
        return f"{src_ip}::{dst_user}"

    if src_ip:
        return f"{src_ip}::{agent_name}"

    if dst_user:
        return f"{agent_name}::{dst_user}"

    return agent_name


# ============================================================
# CORRELATION RULES
# ============================================================
def rule_full_kill_chain(alerts: List[Dict[str, Any]]) -> Optional[str]:
    event_types = [a.get("event_type") for a in alerts]

    if (
        event_types.count("ssh_failed") >= 3
        and ("ssh_success" in event_types or "login_session_opened" in event_types)
        and "sudo_root_executed" in event_types
    ):
        return "FULL_KILL_CHAIN"

    return None


def rule_brute_force_success(alerts: List[Dict[str, Any]]) -> Optional[str]:
    event_types = [a.get("event_type") for a in alerts]

    if event_types.count("ssh_failed") >= SSH_FAIL_MIN and (
        "ssh_success" in event_types or "login_session_opened" in event_types
    ):
        return "BRUTE_FORCE_SUCCESS"

    return None


def rule_ssh_brute_force(alerts: List[Dict[str, Any]]) -> Optional[str]:
    count = sum(1 for a in alerts if a.get("event_type") == "ssh_failed")
    if count >= SSH_FAIL_MIN:
        return "SSH_BRUTE_FORCE"
    return None


def rule_privilege_escalation(alerts: List[Dict[str, Any]]) -> Optional[str]:
    sorted_alerts = sorted(alerts, key=lambda a: a.get("timestamp") or "")
    conn_types = {"ssh_success", "login_session_opened"}

    idx_conn = next(
        (i for i, a in enumerate(sorted_alerts) if a.get("event_type") in conn_types),
        None
    )
    idx_sudo = next(
        (i for i, a in enumerate(sorted_alerts) if a.get("event_type") == "sudo_root_executed"),
        None
    )

    if idx_conn is not None and idx_sudo is not None and idx_conn < idx_sudo:
        return "PRIVILEGE_ESCALATION_AFTER_LOGIN"

    return None


def rule_repeated_sudo(alerts: List[Dict[str, Any]]) -> Optional[str]:
    count = sum(1 for a in alerts if a.get("event_type") == "sudo_root_executed")
    if count >= SUDO_MIN:
        return "REPEATED_SUDO_ROOT"
    return None


RULES = [
    rule_full_kill_chain,
    rule_brute_force_success,
    rule_privilege_escalation,
    rule_ssh_brute_force,
    rule_repeated_sudo,
]


def apply_rules(alerts: List[Dict[str, Any]]) -> Optional[str]:
    for rule_fn in RULES:
        result = rule_fn(alerts)
        if result:
            return result
    return None


# ============================================================
# INCIDENT BUILDER (incident brut corrélé)
# ============================================================
def build_incident(key: str, alerts: List[Dict[str, Any]], rule: str) -> Dict[str, Any]:
    sorted_alerts = sorted(alerts, key=lambda a: a.get("timestamp") or "")
    enriched = [enrich_mitre(a) for a in sorted_alerts]

    tactics_chain = []
    for alert in enriched:
        tactic = alert.get("mitre_tactic")
        if tactic and tactic not in tactics_chain:
            tactics_chain.append(tactic)

    techniques = []
    for alert in enriched:
        technique = alert.get("mitre_technique")
        if technique and technique not in techniques:
            techniques.append(technique)

    attacker_ip = next((a.get("src_ip") for a in enriched if a.get("src_ip")), None)
    target_user = next((a.get("dst_user") for a in enriched if a.get("dst_user")), None)
    target_agent = next((a.get("agent_name") for a in enriched if a.get("agent_name")), "unknown")

    return {
        "incident_id": str(uuid.uuid4())[:8].upper(),
        "rule_triggered": rule,
        "correlation_key": key,
        "severity": compute_severity(enriched),
        "alert_count": len(enriched),
        "time_start": enriched[0].get("timestamp"),
        "time_end": enriched[-1].get("timestamp"),
        "target_agent": target_agent,
        "attacker_ip": attacker_ip,
        "target_user": target_user,
        "tactics_chain": tactics_chain,
        "techniques": techniques,
        "event_sequence": [a.get("event_type") for a in enriched],
        "alerts": enriched,
    }


# ============================================================
# WINDOW MANAGER
# ============================================================
class CorrelationWindow:
    def __init__(self):
        self.buffer: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self.window_start: Dict[str, datetime] = {}
        self.incidents: List[Dict[str, Any]] = []

    def add(self, alert: Dict[str, Any]) -> None:
        key = choose_correlation_key(alert)
        now = parse_ts(alert.get("timestamp"))

        if key not in self.window_start:
            self.window_start[key] = now

        self.buffer[key].append(alert)

    def flush_expired(self) -> None:
        now = datetime.now(tz=timezone.utc)
        keys_to_flush = []

        for key, start_time in self.window_start.items():
            elapsed = (now - start_time).total_seconds()
            if elapsed >= WINDOW_SECONDS:
                keys_to_flush.append(key)

        for key in keys_to_flush:
            self._flush(key)

    def _flush(self, key: str) -> None:
        alerts = self.buffer.get(key, [])

        if not alerts:
            self.buffer.pop(key, None)
            self.window_start.pop(key, None)
            return

        rule = apply_rules(alerts)

        if rule:
            incident = build_incident(key, alerts, rule)
            self.incidents.append(incident)

            # Sauvegarde immédiate -> important pour le futur IncidentReconstructor
            save_incidents_to_file(self.incidents)

            log.info(
                "INCIDENT | id=%s | rule=%s | severity=%s | alerts=%d | key=%s",
                incident["incident_id"],
                incident["rule_triggered"],
                incident["severity"],
                incident["alert_count"],
                incident["correlation_key"],
            )

        self.buffer.pop(key, None)
        self.window_start.pop(key, None)

    def flush_all(self) -> None:
        for key in list(self.buffer.keys()):
            self._flush(key)


# ============================================================
# MAIN LOOP
# ============================================================
def run() -> List[Dict[str, Any]]:
    log.info("Démarrage | topic=%s | broker=%s", KAFKA_TOPIC, KAFKA_BROKER)

    consumer = KafkaConsumer(
        KAFKA_TOPIC,
        bootstrap_servers=KAFKA_BROKER,
        value_deserializer=safe_json_deserializer,
        auto_offset_reset="latest",
        group_id=KAFKA_GROUP_ID,
        consumer_timeout_ms=1000,
    )

    window = CorrelationWindow()
    total = 0
    skipped = 0
    last_flush_check = time.time()

    try:
        while RUNNING:
            got_message = False

            for msg in consumer:
                got_message = True
                raw_alert = msg.value

                if raw_alert is None:
                    skipped += 1
                    continue

                if not isinstance(raw_alert, dict):
                    skipped += 1
                    continue

                try:
                    alert = preprocess_alert(raw_alert)
                except Exception as e:
                    log.warning("Prétraitement échoué, message ignoré : %s", e)
                    skipped += 1
                    continue

                if not is_relevant_alert(alert):
                    skipped += 1
                    continue

                total += 1
                window.add(alert)

            now = time.time()
            if now - last_flush_check >= FLUSH_CHECK_INTERVAL:
                window.flush_expired()
                last_flush_check = now

            if not got_message:
                time.sleep(0.2)

    except Exception as e:
        log.exception("Erreur pendant la consommation Kafka : %s", e)

    finally:
        window.flush_all()
        consumer.close()
        save_incidents_to_file(window.incidents)

        log.info(
            "Fin | traitées=%d | ignorées=%d | incidents=%d",
            total,
            skipped,
            len(window.incidents),
        )

    return window.incidents


if __name__ == "__main__":
    run()
    log.info("Sauvegardé -> %s", INCIDENT_OUTPUT_FILE)
