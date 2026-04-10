# incident_reconstructor.py
# Rôle :
# Lire les incidents bruts produits par correlation_engine.py,
# reconstruire une fiche d'incident lisible et structurée,
# puis sauvegarder le résultat dans reconstructed_incidents.json

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("incident_reconstructor")

INPUT_FILE = "incident_output.json"
OUTPUT_FILE = "reconstructed_incidents.json"


# ============================================================
# Descriptions par règle déclenchée
# ============================================================
RULE_DESCRIPTIONS: Dict[str, Dict[str, str]] = {
    "SSH_BRUTE_FORCE": {
        "attack_type": "Brute Force SSH",
        "description": (
            "Une attaque par force brute SSH a été détectée sur la machine cible. "
            "L'attaquant a effectué plusieurs tentatives d'authentification échouées "
            "dans un intervalle très court, ce qui suggère l'utilisation d'un outil automatisé."
        ),
    },
    "BRUTE_FORCE_SUCCESS": {
        "attack_type": "Compromission après Brute Force SSH",
        "description": (
            "Une séquence de brute force SSH suivie d'une connexion réussie a été détectée. "
            "Cela indique qu'un compte valide a probablement été compromis."
        ),
    },
    "PRIVILEGE_ESCALATION_AFTER_LOGIN": {
        "attack_type": "Élévation de privilèges après authentification",
        "description": (
            "Une élévation de privilèges a été observée après une connexion réussie. "
            "L'attaquant ou l'utilisateur compromis a exécuté une commande sudo vers root."
        ),
    },
    "FULL_KILL_CHAIN": {
        "attack_type": "Chaîne d'attaque complète",
        "description": (
            "Une chaîne d'attaque complète a été détectée : tentatives répétées d'accès SSH, "
            "connexion réussie, puis élévation de privilèges. "
            "Ce scénario représente une compromission avancée de la machine cible."
        ),
    },
    "REPEATED_SUDO_ROOT": {
        "attack_type": "Activité sudo root répétée",
        "description": (
            "Plusieurs actions sudo root ont été détectées dans une courte période. "
            "Ce comportement peut indiquer une activité malveillante, un script automatisé "
            "ou l'usage abusif d'un compte privilégié."
        ),
    },
}

DEFAULT_RULE_INFO = {
    "attack_type": "Incident de sécurité",
    "description": "Un incident de sécurité a été détecté sur la machine cible.",
}


# ============================================================
# Descriptions lisibles par type d'événement
# ============================================================
EVENT_DESCRIPTIONS: Dict[str, str] = {
    "ssh_failed": "Tentative de connexion SSH échouée",
    "ssh_success": "Connexion SSH réussie",
    "login_session_opened": "Session utilisateur ouverte",
    "login_session_closed": "Session utilisateur fermée",
    "sudo_root_executed": "Commande sudo root exécutée",
    "sudo_activity": "Activité sudo détectée",
    "file_modified": "Fichier modifié",
    "file_added": "Fichier ajouté",
    "process_created": "Processus créé",
    "network_connection": "Connexion réseau détectée",
    "other": "Événement générique",
}


# ============================================================
# Utilitaires temps
# ============================================================
def parse_ts(ts: Optional[str]) -> Optional[datetime]:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except ValueError:
        return None


def format_ts(ts: Optional[str]) -> str:
    dt = parse_ts(ts)
    if not dt:
        return ts or "inconnu"
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def compute_duration_seconds(time_start: Optional[str], time_end: Optional[str]) -> int:
    dt_start = parse_ts(time_start)
    dt_end = parse_ts(time_end)
    if not dt_start or not dt_end:
        return 0
    return max(0, int((dt_end - dt_start).total_seconds()))


# ============================================================
# Timeline
# ============================================================
def build_timeline(alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    sorted_alerts = sorted(
        alerts,
        key=lambda a: parse_ts(a.get("timestamp")) or datetime.min.replace(tzinfo=timezone.utc),
    )

    timeline: List[Dict[str, Any]] = []

    for i, alert in enumerate(sorted_alerts, start=1):
        event_type = alert.get("event_type", "other")
        timeline.append({
            "step": i,
            "timestamp": format_ts(alert.get("timestamp")),
            "raw_timestamp": alert.get("timestamp"),
            "event_type": event_type,
            "event_label": EVENT_DESCRIPTIONS.get(event_type, "Événement détecté"),
            "rule_id": alert.get("rule_id"),
            "rule_level": alert.get("rule_level"),
            "rule_description": alert.get("rule_description"),
            "src_ip": alert.get("src_ip"),
            "dst_user": alert.get("dst_user"),
            "agent_name": alert.get("agent_name"),
            "mitre_tactic": alert.get("mitre_tactic"),
            "mitre_technique": alert.get("mitre_technique"),
            "mitre_technique_name": alert.get("mitre_technique_name"),
        })

    return timeline


# ============================================================
# Progression de l'attaque
# ============================================================
def build_attack_progression(alerts: List[Dict[str, Any]]) -> List[str]:
    event_types = [a.get("event_type") for a in alerts]
    progression: List[str] = []

    if "ssh_failed" in event_types:
        progression.append("Tentatives répétées d'authentification SSH")
    if "ssh_success" in event_types or "login_session_opened" in event_types:
        progression.append("Obtention d'un accès valide à la machine")
    if "sudo_root_executed" in event_types or "sudo_activity" in event_types:
        progression.append("Élévation ou usage de privilèges élevés")
    if "file_modified" in event_types or "file_added" in event_types:
        progression.append("Modification du système ou des fichiers")
    if "process_created" in event_types:
        progression.append("Exécution ou lancement de processus")
    if "network_connection" in event_types:
        progression.append("Activité réseau potentiellement suspecte")

    if not progression:
        progression.append("Séquence d'activité suspecte détectée")

    return progression


# ============================================================
# Statistiques
# ============================================================
def build_statistics(incident: Dict[str, Any]) -> Dict[str, Any]:
    alerts = incident.get("alerts", [])
    duration_seconds = compute_duration_seconds(
        incident.get("time_start"),
        incident.get("time_end"),
    )

    event_counts: Dict[str, int] = {}
    unique_src_ips = set()
    unique_users = set()
    max_rule_level = 0

    for alert in alerts:
        event_type = alert.get("event_type", "other")
        event_counts[event_type] = event_counts.get(event_type, 0) + 1

        if alert.get("src_ip"):
            unique_src_ips.add(str(alert["src_ip"]))

        if alert.get("dst_user"):
            unique_users.add(str(alert["dst_user"]))

        try:
            max_rule_level = max(max_rule_level, int(alert.get("rule_level", 0)))
        except (TypeError, ValueError):
            pass

    return {
        "total_alerts": len(alerts),
        "duration_seconds": duration_seconds,
        "unique_src_ips": sorted(unique_src_ips),
        "unique_users": sorted(unique_users),
        "unique_techniques_count": len(set(incident.get("techniques", []))),
        "event_counts": event_counts,
        "max_rule_level": max_rule_level,
    }


# ============================================================
# Recommandations déterministes
# ============================================================
def build_recommendations(incident: Dict[str, Any]) -> List[str]:
    recommendations: List[str] = []
    rule = incident.get("rule_triggered")
    attacker_ip = incident.get("attacker_ip")
    target_user = incident.get("target_user")

    if attacker_ip:
        recommendations.append(f"Vérifier puis bloquer l'adresse IP source suspecte : {attacker_ip}.")
    else:
        recommendations.append("Identifier précisément la source de l'activité suspecte.")

    if rule in {"SSH_BRUTE_FORCE", "BRUTE_FORCE_SUCCESS", "FULL_KILL_CHAIN"}:
        recommendations.append("Vérifier les journaux SSH et rechercher d'autres tentatives similaires.")
        recommendations.append("Contrôler la robustesse des mots de passe et envisager une rotation des identifiants exposés.")
        recommendations.append("Activer ou renforcer les mécanismes anti-brute-force et limiter les tentatives SSH.")

    if rule in {"BRUTE_FORCE_SUCCESS", "PRIVILEGE_ESCALATION_AFTER_LOGIN", "FULL_KILL_CHAIN"}:
        recommendations.append("Examiner les sessions ouvertes et confirmer si un compte a été compromis.")
        recommendations.append("Rechercher les commandes exécutées après authentification pour mesurer l'impact.")

    if rule in {"PRIVILEGE_ESCALATION_AFTER_LOGIN", "REPEATED_SUDO_ROOT", "FULL_KILL_CHAIN"}:
        recommendations.append("Auditer l'utilisation de sudo et vérifier les privilèges du compte concerné.")
        recommendations.append("Contrôler les fichiers sensibles, les accès root et les traces de persistance.")

    if target_user:
        recommendations.append(f"Vérifier l'activité récente du compte utilisateur ciblé : {target_user}.")

    # Suppression des doublons en gardant l'ordre
    unique_recommendations = list(dict.fromkeys(recommendations))
    return unique_recommendations


# ============================================================
# Narratif
# ============================================================
def build_narrative(
    incident: Dict[str, Any],
    progression: List[str],
    statistics: Dict[str, Any],
) -> str:
    attacker = incident.get("attacker_ip") or "source inconnue"
    target = incident.get("target_agent") or "cible inconnue"
    severity = incident.get("severity", "UNKNOWN")
    alert_count = incident.get("alert_count", 0)
    time_start = format_ts(incident.get("time_start"))
    time_end = format_ts(incident.get("time_end"))
    duration_seconds = statistics.get("duration_seconds", 0)

    tactics_chain = incident.get("tactics_chain", [])
    techniques = incident.get("techniques", [])

    rule_info = RULE_DESCRIPTIONS.get(
        incident.get("rule_triggered", ""),
        DEFAULT_RULE_INFO,
    )

    progression_text = " -> ".join(progression)
    tactics_text = " -> ".join(tactics_chain) if tactics_chain else "non déterminée"
    techniques_text = ", ".join(techniques) if techniques else "non déterminées"

    return (
        f"Un incident de type '{rule_info['attack_type']}' a été détecté avec un niveau de sévérité "
        f"{severity}. La source suspecte {attacker} a ciblé la machine '{target}' entre {time_start} "
        f"et {time_end}, sur une durée estimée à {duration_seconds} seconde(s). "
        f"L'incident regroupe {alert_count} alerte(s) corrélée(s). "
        f"La progression observée est la suivante : {progression_text}. "
        f"La chaîne MITRE ATT&CK identifiée est : {tactics_text}. "
        f"Les techniques associées sont : {techniques_text}."
    )


# ============================================================
# Reconstruction d'un incident
# ============================================================
def reconstruct_incident(raw_incident: Dict[str, Any]) -> Dict[str, Any]:
    alerts = raw_incident.get("alerts", [])
    rule = raw_incident.get("rule_triggered", "")
    rule_info = RULE_DESCRIPTIONS.get(rule, DEFAULT_RULE_INFO)

    timeline = build_timeline(alerts)
    progression = build_attack_progression(alerts)
    statistics = build_statistics(raw_incident)
    recommendations = build_recommendations(raw_incident)
    narrative = build_narrative(raw_incident, progression, statistics)

    reconstructed = {
        "incident_id": raw_incident.get("incident_id"),
        "status": "OPEN",
        "severity": raw_incident.get("severity"),
        "rule_triggered": rule,
        "attack_type": rule_info["attack_type"],
        "description": rule_info["description"],

        "summary": {
            "attacker_ip": raw_incident.get("attacker_ip"),
            "target_agent": raw_incident.get("target_agent"),
            "target_user": raw_incident.get("target_user"),
            "time_start": format_ts(raw_incident.get("time_start")),
            "time_end": format_ts(raw_incident.get("time_end")),
            "duration_seconds": statistics["duration_seconds"],
            "alert_count": raw_incident.get("alert_count", len(alerts)),
        },

        "mitre": {
            "tactics_chain": raw_incident.get("tactics_chain", []),
            "techniques": raw_incident.get("techniques", []),
        },

        "statistics": statistics,
        "attack_progression": progression,
        "attack_narrative": narrative,
        "recommendations": recommendations,
        "timeline": timeline,
    }

    log.info(
        "Incident reconstruit | id=%s | type=%s | severity=%s | steps=%d",
        reconstructed["incident_id"],
        reconstructed["attack_type"],
        reconstructed["severity"],
        len(timeline),
    )

    return reconstructed


# ============================================================
# Lecture / écriture fichiers
# ============================================================
def load_raw_incidents(input_file: str) -> List[Dict[str, Any]]:
    try:
        with open(input_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        if isinstance(data, list):
            return data

        log.warning("Le contenu de %s n'est pas une liste JSON.", input_file)
        return []

    except FileNotFoundError:
        log.error("Fichier introuvable : %s", input_file)
        return []
    except json.JSONDecodeError as e:
        log.error("JSON invalide dans %s : %s", input_file, e)
        return []


def save_reconstructed_incidents(output_file: str, incidents: List[Dict[str, Any]]) -> None:
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(incidents, f, indent=2, ensure_ascii=False)


# ============================================================
# Main
# ============================================================
def run(input_file: str = INPUT_FILE, output_file: str = OUTPUT_FILE) -> List[Dict[str, Any]]:
    log.info("Démarrage incident_reconstructor | input=%s", input_file)

    raw_incidents = load_raw_incidents(input_file)

    if not raw_incidents:
        log.info("Aucun incident à reconstruire.")
        return []

    reconstructed_list: List[Dict[str, Any]] = []

    for raw in raw_incidents:
        try:
            reconstructed = reconstruct_incident(raw)
            reconstructed_list.append(reconstructed)
        except Exception as e:
            log.exception(
                "Erreur pendant la reconstruction de l'incident %s : %s",
                raw.get("incident_id", "UNKNOWN"),
                e,
            )

    try:
        save_reconstructed_incidents(output_file, reconstructed_list)
        log.info("Résultat sauvegardé -> %s", output_file)
    except Exception as e:
        log.error("Erreur de sauvegarde : %s", e)

    log.info("Fin | %d incident(s) reconstruit(s)", len(reconstructed_list))
    return reconstructed_list


if __name__ == "__main__":
    run()
