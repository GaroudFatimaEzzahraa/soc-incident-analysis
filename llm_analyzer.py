# llm_analyzer.py
# Rôle :
# Lire les incidents reconstruits
# Ajouter une analyse LLM + threat context
# Générer final_report.json

import json
import requests
import logging
from typing import Dict, List, Any

# ============================================================
# CONFIGURATION
# ============================================================
INPUT_FILE = "reconstructed_incidents.json"
OUTPUT_FILE = "final_report.json"
OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "mistral"

# Exemple simple blacklist (optionnel)
BLACKLIST = ["1.2.3.4"]


# ============================================================
# LOGGING
# ============================================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("llm_analyzer")


# ============================================================
# LOAD / SAVE
# ============================================================
def load_incidents() -> List[Dict[str, Any]]:
    try:
        with open(INPUT_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        log.error("Erreur lecture %s: %s", INPUT_FILE, e)
        return []


def save_results(data: List[Dict[str, Any]]) -> None:
    try:
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        log.info("Résultat sauvegardé -> %s", OUTPUT_FILE)
    except Exception as e:
        log.error("Erreur sauvegarde: %s", e)


# ============================================================
# THREAT CONTEXT (simple mais efficace)
# ============================================================
def classify_ip(ip: str) -> Dict[str, str]:
    if not ip:
        return {"ip_reputation": "unknown"}

    if ip in BLACKLIST:
        return {"ip_reputation": "malicious"}

    if ip.startswith("192.168") or ip.startswith("10.") or ip.startswith("172."):
        return {"ip_reputation": "internal"}

    return {"ip_reputation": "external"}


# ============================================================
# PROMPT BUILDER
# ============================================================
def build_prompt(incident: Dict[str, Any]) -> str:
    return f"""
You are a cybersecurity SOC analyst.

Analyze the following incident and respond ONLY in JSON format.

Incident:
- Attack type: {incident.get('attack_type')}
- Severity: {incident.get('severity')}
- Source IP: {incident.get('summary', {}).get('attacker_ip')}
- Target machine: {incident.get('summary', {}).get('target_agent')}
- Target user: {incident.get('summary', {}).get('target_user')}
- Alerts: {incident.get('summary', {}).get('alert_count')}
- MITRE techniques: {incident.get('mitre', {}).get('techniques')}

Respond STRICTLY in JSON:

{{
  "summary": "...",
  "explanation": "...",
  "risk_level": "LOW | MEDIUM | HIGH | CRITICAL",
  "recommendations": ["...", "..."]
}}
"""


# ============================================================
# CALL OLLAMA
# ============================================================
def call_ollama(prompt: str) -> Dict[str, Any]:
    try:
        response = requests.post(
            OLLAMA_URL,
            json={
                "model": MODEL,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": 0.3
                }
            },
            timeout=180
        )

        response.raise_for_status()

        text = response.json().get("response", "").strip()

        try:
            return json.loads(text)
        except json.JSONDecodeError:
            log.warning("Réponse non JSON, fallback activé.")
            return {
                "summary": text[:200],
                "explanation": text,
                "risk_level": "UNKNOWN",
                "recommendations": []
            }

    except Exception as e:
        log.error("Erreur LLM: %s", e)
        return {
            "summary": "Erreur LLM",
            "explanation": str(e),
            "risk_level": "UNKNOWN",
            "recommendations": []
        }


# ============================================================
# MAIN PROCESS
# ============================================================
def run() -> List[Dict[str, Any]]:
    log.info("Démarrage LLM Analyzer...")

    incidents = load_incidents()

    if not incidents:
        log.warning("Aucun incident trouvé.")
        return []

    final_results = []

    for incident in incidents:
        incident_id = incident.get("incident_id")
        log.info("Analyse incident %s...", incident_id)

        # ===== LLM =====
        prompt = build_prompt(incident)
        analysis = call_ollama(prompt)

        # ===== THREAT CONTEXT =====
        attacker_ip = incident.get("summary", {}).get("attacker_ip")
        threat_context = classify_ip(attacker_ip)

        result = {
            "incident_id": incident_id,
            "attack_type": incident.get("attack_type"),
            "severity": incident.get("severity"),

            "summary": incident.get("summary"),
            "mitre": incident.get("mitre"),

            "threat_context": threat_context,

            "ai_analysis": {
                "summary": analysis.get("summary"),
                "explanation": analysis.get("explanation"),
                "risk_level": analysis.get("risk_level"),
                "recommendations": analysis.get("recommendations"),
            }
        }

        final_results.append(result)

    save_results(final_results)

    log.info("Fin analyse LLM | %d incident(s)", len(final_results))

    return final_results


# ============================================================
# ENTRY POINT
# ============================================================
if __name__ == "__main__":
    run()
