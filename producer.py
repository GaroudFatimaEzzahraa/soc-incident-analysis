from kafka import KafkaProducer
import json
import time
import os

producer = KafkaProducer(
    bootstrap_servers="localhost:9092",
    value_serializer=lambda v: json.dumps(v).encode("utf-8")
)

FILE_PATH = "final_report.json"
last_size = 0

print("👁️ Monitoring incidents file...")

while True:
    try:
        if os.path.exists(FILE_PATH):

            size = os.path.getsize(FILE_PATH)

            # seulement si nouveau contenu
            if size != last_size:
                with open(FILE_PATH) as f:
                    data = json.load(f)

                if isinstance(data, list):
                    for incident in data:
                        producer.send("soc-incidents", incident)
                        print("📤 Sent:", incident["id"])

                last_size = size

        time.sleep(2)

    except Exception as e:
        print("Error:", e)
