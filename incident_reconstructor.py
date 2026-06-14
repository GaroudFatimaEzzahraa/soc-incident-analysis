import json
from datetime import datetime
from kafka import KafkaConsumer, KafkaProducer

KAFKA_TOPIC  = "security-incidents"
OUTPUT_TOPIC = "reconstructed-incidents"
KAFKA_BROKER = "localhost:9092"

producer = KafkaProducer(
    bootstrap_servers=KAFKA_BROKER,
    value_serializer=lambda v: json.dumps(v).encode("utf-8")
)


def parse_time(value):
    if not value:
        return None

    value = str(value).strip()

    formats = [
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
    ]

    for fmt in formats:
        try:
            return datetime.strptime(value, fmt)
        except Exception:
            pass

    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        return None

def compute_duration(start, end):
    s = parse_time(start)
    e = parse_time(end)

    if not s or not e:
        return "N/A"

    seconds = int((e - s).total_seconds())
    if seconds < 0:
        seconds = 0

    minutes = seconds // 60
    seconds = seconds % 60

    if minutes > 0:
        return f"{minutes} min {seconds} sec"
    return f"{seconds} sec"


def build_timeline(alerts):
    timeline = []

    for i, a in enumerate(alerts, start=1):
        timeline.append({
            "step": i,
            "event": a.get("event_type", "unknown"),
            "time": a.get("timestamp", ""),
            "src_ip": a.get("source_ip", "unknown"),
            "target": a.get("agent_id") or a.get("hostname") or "unknown_host",
            "rule_id": a.get("rule_id", ""),
            "log": a.get("log", "")
        })

    return timeline


def resolve_target_agent(raw, alerts):
    target = raw.get("target_agent", "")

    if target and target not in ("", "unknown", "unknown_host", "None", None):
        return target

    if alerts:
        first = alerts[0]
        for field in ("agent_id", "hostname"):
            value = first.get(field, "")
            if value and value not in ("", "unknown", "unknown_host"):
                return value

    return "unknown_host"


def reconstruct(raw):
    alerts = raw.get("alerts", [])
    target_agent = resolve_target_agent(raw, alerts)

    time_start = raw.get("time_start")
    time_end = raw.get("time_end")

    reconstructed = {
        "incident_id": raw.get("incident_id"),
        "severity": raw.get("severity"),
        "attack_type": raw.get("rule_triggered"),
        "attacker_ip": raw.get("attacker_ip"),
        "target_agent": target_agent,
        "time_start": time_start,
        "time_end": time_end,
        "duration": compute_duration(time_start, time_end),
        "alert_count": len(alerts),
        "event_types": raw.get("event_types", []),
        "correlation_key": raw.get("correlation_key", ""),
        "timeline": build_timeline(alerts),
    }

    return reconstructed


def run():
    consumer = KafkaConsumer(
        KAFKA_TOPIC,
        bootstrap_servers=KAFKA_BROKER,
        value_deserializer=lambda m: json.loads(m.decode("utf-8")),
        auto_offset_reset="latest",
    )

    print("RECONSTRUCTOR STARTED")

    for msg in consumer:
        try:
            reconstructed = reconstruct(msg.value)

            producer.send(OUTPUT_TOPIC, reconstructed)
            producer.flush()

            print(
                "RECONSTRUCTED | id=" + str(reconstructed.get("incident_id")) +
                " | type=" + str(reconstructed.get("attack_type")) +
                " | target=" + str(reconstructed.get("target_agent")) +
                " | duration=" + str(reconstructed.get("duration"))
            )

        except Exception as e:
            print("ERREUR : " + str(e))


if __name__ == "__main__":
    run()
