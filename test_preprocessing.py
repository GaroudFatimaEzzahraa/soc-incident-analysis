import json
from kafka import KafkaConsumer
from preprocessing import preprocess_alert, format_pretty, is_relevant_alert

TOPIC = "security-alerts"
BOOTSTRAP_SERVERS = "localhost:9092"

consumer = KafkaConsumer(
    TOPIC,
    bootstrap_servers=BOOTSTRAP_SERVERS,
    auto_offset_reset="latest",
    enable_auto_commit=True,
    value_deserializer=lambda m: json.loads(m.decode("utf-8")),
)

print("Waiting for alerts from Kafka...")

for message in consumer:
    raw_alert = message.value
    processed = preprocess_alert(raw_alert)

    print("\n=== RAW ALERT RECEIVED ===")
    print(raw_alert.get("rule", {}).get("description", "No description"))

    print("\n=== PREPROCESSED ALERT ===")
    print(format_pretty(processed))

    if is_relevant_alert(processed):
        print(
            f"\n[RELEVANT ALERT] host={processed['agent_name']} | "
            f"event={processed['event_type']} | "
            f"rule_id={processed['rule_id']} | "
            f"level={processed['rule_level']}"
        )
    else:
        print("\n[IGNORED ALERT] This alert is not currently prioritized for correlation.")
