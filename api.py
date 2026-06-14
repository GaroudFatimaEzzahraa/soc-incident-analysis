from fastapi import FastAPI, WebSocket, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from kafka import KafkaConsumer
import json
import asyncio
import threading

from db import (
    init_db,
    save_incident,
    get_all_incidents,
    get_incident_by_id,
    close_incident,
    reopen_incident,
)

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

init_db()

incidents_data = get_all_incidents()


def refresh_memory():
    global incidents_data
    incidents_data = get_all_incidents()


def kafka_listener():
    consumer = KafkaConsumer(
        "final-incidents",
        bootstrap_servers="localhost:9092",
        value_deserializer=lambda m: json.loads(m.decode("utf-8")),
        auto_offset_reset="latest",
        group_id="api-final-incidents-group"
    )

    print("Kafka listener started on final-incidents...")

    for message in consumer:
        incident = message.value

        save_incident(incident)
        refresh_memory()

        print("New incident saved to SQLite:", incident.get("id"))


threading.Thread(target=kafka_listener, daemon=True).start()


@app.get("/incidents")
def get_incidents():
    refresh_memory()
    return incidents_data


@app.get("/incidents/{incident_id}")
def get_incident(incident_id: str):
    incident = get_incident_by_id(incident_id)

    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    return incident


@app.put("/incidents/{incident_id}/close")
def close_incident_api(incident_id: str):
    incident = close_incident(incident_id)

    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    refresh_memory()
    return incident


@app.put("/incidents/{incident_id}/reopen")
def reopen_incident_api(incident_id: str):
    incident = reopen_incident(incident_id)

    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    refresh_memory()
    return incident


@app.websocket("/ws/incidents")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()

    last_data = None

    while True:
        try:
            refresh_memory()

            current = json.dumps(incidents_data, sort_keys=True)

            if current != last_data:
                await websocket.send_json(incidents_data)
                last_data = current

            await asyncio.sleep(1)

        except Exception as e:
            print("WebSocket error:", e)
            break
