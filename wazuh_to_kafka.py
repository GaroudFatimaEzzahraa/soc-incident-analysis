import json
import time
from kafka import KafkaProducer

ALERT_FILE = "/var/ossec/logs/alerts/alerts.json"
TOPIC = "security-alerts"
BOOTSTRAP_SERVERS = "localhost:9092"

producer = KafkaProducer(
    bootstrap_servers=BOOTSTRAP_SERVERS,
    value_serializer=lambda v: json.dumps(v).encode("utf-8")
)

def follow(file):
    file.seek(0, 2)
    while True:
        line = file.readline()
        if not line:
            time.sleep(1)
            continue
        yield line

with open(ALERT_FILE, "r") as f:
    loglines = follow(f)
    for line in loglines:
        try:
            alert = json.loads(line)
            producer.send(TOPIC, alert)
            producer.flush()
            print("Sent alert to Kafka")
        except Exception as e:
            print(f"Error: {e}")
