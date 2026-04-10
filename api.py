from fastapi import FastAPI
import json

app = FastAPI()

FILE = "final_report.json"

@app.get("/")
def home():
    return {"message": "SOC API running"}

@app.get("/incidents")
def get_incidents():
    try:
        with open(FILE, "r") as f:
            data = json.load(f)
        return data
    except:
        return {"error": "No data found"}
