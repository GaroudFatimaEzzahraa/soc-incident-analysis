import os
import json
import sqlite3
import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

DB_PATH = "/home/wazuh/pfe_soc_project/soc_incidents.db"
MODEL_PATH = "/home/wazuh/pfe_soc_project/isolation_forest_model.joblib"

SEVERITY_SCORE = {
    "LOW": 25,
    "MEDIUM": 50,
    "HIGH": 75,
    "CRITICAL": 100,
}

ATTACK_TYPE_SCORE = {
    "SUCCESSFUL_LOGIN": 20,
    "MULTIPLE_SUCCESSFUL_LOGINS": 45,
    "SSH_BRUTE_FORCE": 70,
    "NETWORK_RECONNAISSANCE": 60,
    "DATA_EXFILTRATION_ATTEMPT": 85,
    "FULL_KILL_CHAIN": 100,
}


def safe_int(value, default=0):
    try:
        return int(value)
    except Exception:
        return default


def extract_features(incident):
    severity = str(incident.get("severity", "LOW")).upper().strip()
    attack_type = str(
        incident.get("type") or incident.get("attack_type") or "UNKNOWN"
    ).upper().strip()

    alert_count = safe_int(incident.get("alert_count", 1), 1)
    priority = safe_int(incident.get("priority", 0), 0)
    confidence = safe_int(incident.get("confidence", 70), 70)

    severity_score = SEVERITY_SCORE.get(severity, 25)
    attack_score = ATTACK_TYPE_SCORE.get(attack_type, 30)

    return [
        alert_count,
        priority,
        confidence,
        severity_score,
        attack_score,
    ]


def load_training_data():
    if not os.path.exists(DB_PATH):
        return []

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    try:
        cur.execute("SELECT data FROM incidents")
        rows = cur.fetchall()
    except Exception:
        conn.close()
        return []

    conn.close()

    features = []

    for row in rows:
        try:
            incident = json.loads(row[0])
            features.append(extract_features(incident))
        except Exception:
            continue

    return features


def train_model():
    features = load_training_data()

    if len(features) < 10:
        features = [
            [1, 25, 70, 25, 20],
            [2, 35, 75, 25, 20],
            [3, 45, 80, 50, 45],
            [5, 60, 85, 75, 70],
            [8, 70, 85, 75, 70],
            [10, 80, 90, 75, 70],
            [12, 90, 90, 100, 100],
            [15, 95, 95, 100, 100],
        ]

    X = np.array(features)

    model = IsolationForest(
        n_estimators=100,
        contamination=0.20,
        random_state=42
    )

    model.fit(X)
    joblib.dump(model, MODEL_PATH)

    return model


def load_or_train_model():
    if os.path.exists(MODEL_PATH):
        try:
            return joblib.load(MODEL_PATH)
        except Exception:
            return train_model()

    return train_model()


def analyze_incident_ml(incident):
    try:
        attack_type = str(
            incident.get("type") or incident.get("attack_type") or "UNKNOWN"
        ).upper().strip()

        severity = str(incident.get("severity", "LOW")).upper().strip()
        alert_count = safe_int(incident.get("alert_count", 1), 1)
        priority = safe_int(incident.get("priority", 0), 0)
        confidence = safe_int(incident.get("confidence", 70), 70)

        # Règles SOC pour test réel PFE
        if attack_type == "FULL_KILL_CHAIN":
            return {
                "model": "Hybrid ML: IsolationForest + SOC Rule",
                "anomaly_score": 95,
                "prediction": "ANOMALOUS",
                "features": {
                    "alert_count": alert_count,
                    "priority": priority,
                    "confidence": confidence,
                    "severity_score": 100,
                    "attack_type_score": 100,
                }
            }

        if attack_type == "SSH_BRUTE_FORCE" and alert_count >= 5:
            return {
                "model": "Hybrid ML: IsolationForest + SOC Rule",
                "anomaly_score": 75,
                "prediction": "ANOMALOUS",
                "features": {
                    "alert_count": alert_count,
                    "priority": priority,
                    "confidence": confidence,
                    "severity_score": 75,
                    "attack_type_score": 70,
                }
            }

        model = load_or_train_model()
        features = np.array([extract_features(incident)])

        prediction = model.predict(features)[0]
        raw_score = model.decision_function(features)[0]

        anomaly_score = int(max(0, min(100, (1 - raw_score) * 50)))

        label = "ANOMALOUS" if prediction == -1 or anomaly_score >= 70 else "NORMAL"

        return {
            "model": "IsolationForest",
            "anomaly_score": anomaly_score,
            "prediction": label,
            "features": {
                "alert_count": int(features[0][0]),
                "priority": int(features[0][1]),
                "confidence": int(features[0][2]),
                "severity_score": int(features[0][3]),
                "attack_type_score": int(features[0][4]),
            }
        }

    except Exception as e:
        return {
            "model": "IsolationForest",
            "anomaly_score": 0,
            "prediction": "UNKNOWN",
            "error": str(e)
        }
