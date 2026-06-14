import json
import requests
import re
import logging
import atexit
import os
from kafka import KafkaConsumer, KafkaProducer

from db import init_db, save_incident
from ml_analyzer import analyze_incident_ml

INPUT_TOPIC = "reconstructed-incidents"
OUTPUT_TOPIC = "final-incidents"
KAFKA_BROKER = "localhost:9092"
OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "mistral"
OUTPUT_FILE = "/home/wazuh/pfe_soc_project/final_report.json"

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("SOC_AI_v7")

consumer = KafkaConsumer(
    INPUT_TOPIC,
    bootstrap_servers=KAFKA_BROKER,
    value_deserializer=lambda m: json.loads(m.decode("utf-8")),
    auto_offset_reset="latest",
    enable_auto_commit=False,
    group_id="soc-ai-group-v7"
)

producer = KafkaProducer(
    bootstrap_servers=KAFKA_BROKER,
    value_serializer=lambda v: json.dumps(v).encode("utf-8"),
)

atexit.register(lambda: producer.flush())
init_db()

_attacker_history = {}

SEVERITY_SCORES = {
    "CRITICAL": 100,
    "HIGH": 75,
    "MEDIUM": 50,
    "LOW": 25,
}

MITRE_MAPPING = {
    "SSH_BRUTE_FORCE": {
        "tactic": "Credential Access",
        "technique": "T1110",
        "technique_name": "Brute Force"
    },
    "SUCCESSFUL_LOGIN": {
        "tactic": "Initial Access",
        "technique": "T1078",
        "technique_name": "Valid Accounts"
    },
    "MULTIPLE_SUCCESSFUL_LOGINS": {
        "tactic": "Initial Access",
        "technique": "T1078",
        "technique_name": "Valid Accounts"
    },
    "FULL_KILL_CHAIN": {
        "tactic": "Multiple Tactics",
        "technique": "Multi-stage intrusion",
        "technique_name": "Full Kill Chain"
    },
    "NETWORK_RECONNAISSANCE": {
        "tactic": "Discovery",
        "technique": "T1046",
        "technique_name": "Network Service Discovery"
    },
    "DATA_EXFILTRATION_ATTEMPT": {
        "tactic": "Exfiltration",
        "technique": "T1041",
        "technique_name": "Exfiltration Over C2 Channel"
    }
}


def get_mitre_mapping(attack_type):
    return MITRE_MAPPING.get(attack_type, {
        "tactic": "Unknown",
        "technique": "Unknown",
        "technique_name": "Unknown"
    })


def record_attacker(ip):
    if ip and ip not in ("unknown", "internal"):
        _attacker_history[ip] = _attacker_history.get(ip, 0) + 1


def attacker_recidivism(ip):
    return _attacker_history.get(ip, 0)


def compute_priority(severity, confidence, alert_count, attacker_ip):
    try:
        s = SEVERITY_SCORES.get(str(severity).upper(), 25)
        c = max(0, min(100, float(confidence or 70)))
        a = min(100, (int(alert_count or 1) / 50) * 100)
        r = min(100, (attacker_recidivism(attacker_ip) / 5) * 100)

        priority = 0.40 * s + 0.30 * c + 0.20 * a + 0.10 * r
        return round(min(priority, 100))

    except Exception:
        return 70


def save_to_file(final):
    try:
        if os.path.exists(OUTPUT_FILE):
            with open(OUTPUT_FILE, "r") as f:
                data = json.load(f)
        else:
            data = []

        if not isinstance(data, list):
            data = []

        data.append(final)
        data = data[-50:]

        with open(OUTPUT_FILE, "w") as f:
            json.dump(data, f, indent=2)

        log.info("Incident backup JSON sauvegarde : %s", final.get("id"))

    except Exception as e:
        log.error("Erreur sauvegarde JSON : %s", e)


def clean_confidence(value):
    try:
        return int(max(0, min(100, float(value))))
    except Exception:
        return 70


def extract_json(text):
    try:
        if not text:
            return None

        text = text.strip()
        text = text.replace("```json", "").replace("```", "").strip()

        try:
            return json.loads(text)
        except Exception:
            pass

        match = re.search(r"\{[\s\S]*\}", text)
        if match:
            return json.loads(match.group(0))

        return None

    except Exception as e:
        log.error("Erreur parsing JSON : %s", e)
        return None


def build_compact_timeline(incident):
    timeline = incident.get("timeline", [])
    compact = []

    for step in timeline[:5]:
        compact.append({
            "step": step.get("step"),
            "event": step.get("event"),
            "time": step.get("time"),
            "src_ip": step.get("src_ip"),
            "target": step.get("target")
        })

    return compact


def build_xai_prompt(incident):
    compact_timeline = build_compact_timeline(incident)

    return f"""
Return ONLY valid JSON. No markdown.

Analyze this SOC incident:

attack_type={incident.get("attack_type")}
severity={incident.get("severity")}
attacker_ip={incident.get("attacker_ip")}
target_host={incident.get("target_agent")}
alert_count={incident.get("alert_count")}
duration={incident.get("duration")}
timeline={json.dumps(compact_timeline)}

Required JSON:
{{
  "summary": "short summary",
  "risk_level": "HIGH",
  "confidence": 85,
  "explanation": [
    "reason 1",
    "reason 2",
    "reason 3"
  ],
  "recommended_action": [
    "action 1",
    "action 2",
    "action 3"
  ]
}}

Rules:
risk_level must be CRITICAL, HIGH, MEDIUM, or LOW.
confidence must be integer 0-100.
Use short English sentences.
"""


def fallback_analysis(incident):
    attack = incident.get("attack_type", "Unknown")
    attacker_ip = incident.get("attacker_ip", "unknown")
    target_agent = incident.get("target_agent", "unknown_host")
    alert_count = incident.get("alert_count", 0)

    return {
        "summary": f"{attack} detected from {attacker_ip} targeting {target_agent}.",
        "risk_level": incident.get("severity", "HIGH"),
        "confidence": 70,
        "explanation": [
            f"Attack type identified as {attack}.",
            f"{alert_count} correlated alerts were observed.",
            f"The same source IP targeted host {target_agent}."
        ],
        "recommended_action": [
            f"Review authentication logs on {target_agent}.",
            f"Monitor the source IP {attacker_ip}.",
            "Apply containment if malicious activity is confirmed."
        ]
    }


def validate_analysis(analysis, incident):
    if not isinstance(analysis, dict):
        return None

    attack = incident.get("attack_type", "Unknown")
    severity = incident.get("severity", "HIGH")

    summary = analysis.get("summary") or f"{attack} detected."

    risk = str(analysis.get("risk_level", severity)).upper()
    if risk not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        risk = severity

    confidence = clean_confidence(analysis.get("confidence", 70))

    explanation = analysis.get("explanation", [])
    if not isinstance(explanation, list) or len(explanation) == 0:
        explanation = [
            "The incident matches a known SOC attack pattern.",
            "Multiple correlated alerts were observed.",
            "Manual SOC analyst review is recommended."
        ]

    recommended_action = analysis.get("recommended_action", [])
    if not isinstance(recommended_action, list) or len(recommended_action) == 0:
        recommended_action = [
            "Review logs on the targeted host.",
            "Monitor the attacker IP.",
            "Apply containment if malicious activity is confirmed."
        ]

    return {
        "summary": summary,
        "risk_level": risk,
        "confidence": confidence,
        "explanation": explanation[:5],
        "recommended_action": recommended_action[:5]
    }


def call_llm(prompt):
    try:
        res = requests.post(
            OLLAMA_URL,
            json={
                "model": MODEL,
                "prompt": prompt,
                "stream": False,
                "format": "json",
                "options": {
                    "temperature": 0,
                    "num_predict": 220,
                    "num_ctx": 1024
                }
            },
            timeout=300
        )

        if res.status_code != 200:
            log.error("Erreur Ollama HTTP %s : %s", res.status_code, res.text)
            return None

        text = res.json().get("response", "")
        log.info("RAW OLLAMA RESPONSE = %s", text)

        return extract_json(text)

    except requests.exceptions.Timeout:
        log.error("Erreur LLM : timeout Ollama.")
        return None

    except Exception as e:
        log.error("Erreur LLM : %s", e)
        return None


log.info("SOC AI v7 DEMARRE : SQLite + MITRE + XAI + ML")

for msg in consumer:
    try:
        incident = msg.value

        log.info(
            "Incident recu | id=%s | type=%s | target=%s",
            incident.get("incident_id"),
            incident.get("attack_type"),
            incident.get("target_agent")
        )

        raw_analysis = call_llm(build_xai_prompt(incident))
        analysis = validate_analysis(raw_analysis, incident)

        if not analysis:
            log.warning("LLM indisponible ou JSON invalide - fallback active")
            analysis = fallback_analysis(incident)
            engine = "Fallback"
        else:
            engine = "LLM"

        confidence = clean_confidence(analysis.get("confidence", 70))

        priority = compute_priority(
            severity=incident.get("severity", "HIGH"),
            confidence=confidence,
            alert_count=incident.get("alert_count", 1),
            attacker_ip=incident.get("attacker_ip", "")
        )

        record_attacker(incident.get("attacker_ip", ""))

        attack_type = incident.get("attack_type")

        ml_result = analyze_incident_ml({
            "type": attack_type,
            "severity": incident.get("severity"),
            "alert_count": incident.get("alert_count", 0),
            "priority": priority,
            "confidence": confidence,
        })

        final = {
            "id": incident.get("incident_id"),
            "type": attack_type,
            "severity": incident.get("severity"),
            "ip": incident.get("attacker_ip"),
            "target_agent": incident.get("target_agent", "unknown_host"),

            "time_start": incident.get("time_start"),
            "time_end": incident.get("time_end"),
            "duration": incident.get("duration", "N/A"),
            "alert_count": incident.get("alert_count", 0),
            "timeline": incident.get("timeline", []),

            "summary": analysis.get("summary"),
            "risk": analysis.get("risk_level"),
            "confidence": confidence,
            "explanation": analysis.get("explanation", []),
            "recommended_action": analysis.get("recommended_action", []),

            "mitre": get_mitre_mapping(attack_type),
            "ml": ml_result,

            "priority": priority,
            "status": "OPEN",
            "engine": engine
        }

        save_to_file(final)
        save_incident(final)

        producer.send(OUTPUT_TOPIC, final)
        producer.flush()

        log.info(
            "FINAL | id=%s | type=%s | status=%s | engine=%s | ml=%s score=%s",
            final.get("id"),
            final.get("type"),
            final.get("status"),
            final.get("engine"),
            ml_result.get("prediction"),
            ml_result.get("anomaly_score")
        )

        try:
            consumer.commit()
        except Exception as e:
            log.warning("Erreur commit Kafka : %s", e)

    except Exception as e:
        log.error("Erreur globale : %s", e)
