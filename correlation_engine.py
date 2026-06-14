import json
import logging
import time
import uuid
import threading
from datetime import datetime, timezone
from collections import defaultdict
from kafka import KafkaConsumer, KafkaProducer

KAFKA_TOPIC = "security-alerts"
INCIDENT_TOPIC = "security-incidents"
KAFKA_BROKER = "localhost:9092"

WINDOW = 180
THRESHOLD = 5
COOLDOWN = 10

LOGIN_MEDIUM_THRESHOLD = 3
LOGIN_TRACKER_WINDOW = 60
LOW_LOGIN_DELAY = 8

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("SOC_ENGINE_v6")


def _extract_ip(alert):
    ip = alert.get("source_ip")

    if not ip or ip == "unknown":
        log_data = alert.get("log", "")

        if "from" in log_data:
            try:
                ip = log_data.split("from ")[1].split(" ")[0]
            except Exception:
                ip = "internal"
        else:
            ip = "internal"

    return ip


def _extract_host(alert):
    return alert.get("agent_id") or alert.get("hostname") or "unknown_host"


def _unwrap_alerts(bucket_alerts):
    return [e["alert"] for e in bucket_alerts]


def _add_timestamp(alert):
    if "timestamp" not in alert or not alert.get("timestamp"):
        alert["timestamp"] = datetime.now(timezone.utc).isoformat()
    return alert


def make_correlation_key(alert):
    ip = _extract_ip(alert)
    event = alert.get("event_type", "unknown")
    host = _extract_host(alert)
    return f"{ip}::{event}::{host}"


def make_attack_key(ip, host):
    return f"{ip}::{host}"


class CorrelationBucket:
    def __init__(self):
        self.alerts = []
        self.event_sequence = []
        self.last_incident_time = 0.0
        self.low_timer = None


class SOCEngineV6:

    def __init__(self):
        self.buckets = defaultdict(CorrelationBucket)

        self.kill_chain_tracker = defaultdict(lambda: {
            "attacker_ip": None,
            "events": set(),
            "alerts": [],
            "last_time": 0.0,
        })

        self.login_tracker = defaultdict(lambda: [])
        self.lock = threading.RLock()

        self.producer = KafkaProducer(
            bootstrap_servers=KAFKA_BROKER,
            value_serializer=lambda v: json.dumps(v).encode("utf-8"),
        )

        log.info("SOC Engine v6 initialise")

    def process(self, alert):
        with self.lock:
            alert = _add_timestamp(alert)

            event = alert.get("event_type", "unknown")
            host = _extract_host(alert)
            ip = _extract_ip(alert)
            now = time.time()

            key = make_correlation_key(alert)
            bucket = self.buckets[key]

            bucket.alerts = [e for e in bucket.alerts if now - e["time"] < WINDOW]
            bucket.alerts.append({"time": now, "alert": alert})
            bucket.event_sequence.append(event)

            log.info(
                "EVENT | key=%-60s | event=%-25s | host=%-30s | count=%d",
                key, event, host, len(bucket.alerts)
            )

            # MEDIUM : 3 login_success depuis la meme IP vers le meme host
            if event == "login_success":
                login_key = make_attack_key(ip, host)

                self.login_tracker[login_key] = [
                    item for item in self.login_tracker[login_key]
                    if now - item["time"] < LOGIN_TRACKER_WINDOW
                ]

                self.login_tracker[login_key].append({
                    "time": now,
                    "alert": alert
                })

                log.info(
                    "LOGIN TRACKER | key=%s | count=%d",
                    login_key,
                    len(self.login_tracker[login_key])
                )

                if len(self.login_tracker[login_key]) >= LOGIN_MEDIUM_THRESHOLD:
                    medium_bucket = CorrelationBucket()
                    medium_bucket.alerts = list(self.login_tracker[login_key])

                    self._cancel_low_timer(bucket)

                    self._emit_incident(
                        key=login_key,
                        bucket=medium_bucket,
                        rule="MULTIPLE_SUCCESSFUL_LOGINS",
                        severity="MEDIUM"
                    )

                    self.login_tracker[login_key].clear()
                    bucket.alerts.clear()
                    bucket.event_sequence.clear()
                    return

            # KILL CHAIN : on suit par host cible uniquement.
            # Raison : sudo/su n'a pas toujours l'IP source.
            kc_key = host
            kc = self.kill_chain_tracker[kc_key]

            if now - kc["last_time"] > WINDOW and len(kc["events"]) > 0:
                kc["events"].clear()
                kc["alerts"].clear()
                kc["attacker_ip"] = None

            kc["events"].add(event)
            kc["alerts"].append(alert)
            kc["last_time"] = now

            if ip not in ("internal", "unknown"):
                kc["attacker_ip"] = ip

            log.info(
                "KC STATE | host=%-30s | attacker=%s | etapes=%s",
                host, kc["attacker_ip"], list(kc["events"])
            )

            if now - bucket.last_incident_time < COOLDOWN:
                return

            self._detect(key, bucket, kc_key, kc, host, now)

    def _schedule_low_login(self, key, bucket):
        if bucket.low_timer is not None:
            return

        def delayed_emit():
            with self.lock:
                raw_alerts = _unwrap_alerts(bucket.alerts)

                if len(raw_alerts) == 1:
                    last_event = raw_alerts[-1].get("event_type", "")

                    if last_event == "login_success":
                        self._emit_incident(
                            key,
                            bucket,
                            "SUCCESSFUL_LOGIN",
                            "LOW"
                        )

                bucket.low_timer = None

        timer = threading.Timer(LOW_LOGIN_DELAY, delayed_emit)
        bucket.low_timer = timer
        timer.start()

    def _cancel_low_timer(self, bucket):
        if bucket.low_timer is not None:
            try:
                bucket.low_timer.cancel()
            except Exception:
                pass
            bucket.low_timer = None

    def _detect(self, key, bucket, kc_key, kc, host, now):
        raw_alerts = _unwrap_alerts(bucket.alerts)

        if not raw_alerts:
            return

        last_event = raw_alerts[-1].get("event_type", "")
        events_seen = kc["events"]

        has_bruteforce = any(
            e in ("ssh_bruteforce", "ssh_bruteforce_detected")
            for e in events_seen
        )
        has_login = "login_success" in events_seen
        has_privesc = "privilege_escalation" in events_seen

        if has_bruteforce and has_login and has_privesc:
            kc_cooldown_key = f"KILL_CHAIN::{kc_key}"
            kc_bucket = self.buckets[kc_cooldown_key]

            if now - kc_bucket.last_incident_time >= COOLDOWN:
                self._emit_kill_chain(host, kc, now)
                kc_bucket.last_incident_time = now
                kc["events"].clear()
                kc["alerts"].clear()
                kc["attacker_ip"] = None

            return

        if last_event == "ssh_bruteforce" and len(raw_alerts) >= THRESHOLD:
            self._emit_incident(key, bucket, "SSH_BRUTE_FORCE", "HIGH")
            return

        if last_event == "sensitive_file_access" and len(raw_alerts) >= 2:
            self._emit_incident(key, bucket, "DATA_EXFILTRATION_ATTEMPT", "HIGH")
            return

        if last_event == "port_scan" and len(raw_alerts) >= 3:
            self._emit_incident(key, bucket, "NETWORK_RECONNAISSANCE", "MEDIUM")
            return

        if last_event == "login_success" and len(raw_alerts) == 1:
            self._schedule_low_login(key, bucket)
            return

    def _emit_kill_chain(self, host, kc, now):
        all_alerts = kc["alerts"]
        attacker_ip = kc["attacker_ip"] or "unknown"

        if not all_alerts:
            return

        incident = {
            "incident_id": str(uuid.uuid4())[:8],
            "rule_triggered": "FULL_KILL_CHAIN",
            "severity": "CRITICAL",
            "attacker_ip": attacker_ip,
            "target_agent": host,
            "time_start": all_alerts[0].get("timestamp", ""),
            "time_end": all_alerts[-1].get("timestamp", ""),
            "alert_count": len(all_alerts),
            "event_types": list(kc["events"]),
            "correlation_key": f"{attacker_ip}::FULL_KILL_CHAIN::{host}",
            "alerts": all_alerts,
        }

        log.warning(
            "KILL CHAIN DETECTE | ip=%s | host=%s | alerts=%d",
            attacker_ip, host, len(all_alerts)
        )

        self.producer.send(INCIDENT_TOPIC, incident)
        self.producer.flush()

    def _emit_incident(self, key, bucket, rule, severity):
        raw_alerts = _unwrap_alerts(bucket.alerts)

        if not raw_alerts:
            return

        self._cancel_low_timer(bucket)

        ip = _extract_ip(raw_alerts[0])
        host = _extract_host(raw_alerts[0])
        event_set = list(set(a.get("event_type", "unknown") for a in raw_alerts))

        incident = {
            "incident_id": str(uuid.uuid4())[:8],
            "rule_triggered": rule,
            "severity": severity,
            "attacker_ip": ip,
            "target_agent": host,
            "time_start": raw_alerts[0].get("timestamp", ""),
            "time_end": raw_alerts[-1].get("timestamp", ""),
            "alert_count": len(raw_alerts),
            "event_types": event_set,
            "correlation_key": key,
            "alerts": raw_alerts,
        }

        log.warning(
            "INCIDENT | rule=%s | severity=%s | ip=%s | host=%s | alerts=%d",
            rule, severity, ip, host, len(raw_alerts)
        )

        self.producer.send(INCIDENT_TOPIC, incident)
        self.producer.flush()

        bucket.last_incident_time = time.time()
        bucket.alerts.clear()
        bucket.event_sequence.clear()

    def close(self):
        try:
            self.producer.flush()
            self.producer.close()
        except Exception:
            pass


def run():
    consumer = KafkaConsumer(
        KAFKA_TOPIC,
        bootstrap_servers=KAFKA_BROKER,
        value_deserializer=lambda m: json.loads(m.decode("utf-8")),
        auto_offset_reset="latest",
    )

    engine = SOCEngineV6()
    log.info("SOC ENGINE v6 DEMARRE")

    try:
        for msg in consumer:
            try:
                engine.process(msg.value)
            except Exception as exc:
                log.error("Erreur de traitement : %s", exc)
    finally:
        engine.close()


if __name__ == "__main__":
    run()
