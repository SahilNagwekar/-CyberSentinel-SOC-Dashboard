from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .models import Log
from .database import logs_collection, alerts_collection
from .detection import run_detections

app = FastAPI()

# CORS so frontend / Netlify / Live Server can talk to backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          # for dev; later restrict to your domains
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def home():
    return {"message": "Mini SOC API Running 😎"}


@app.get("/stats")
def stats():
    total_logs = logs_collection.count_documents({})
    total_alerts = alerts_collection.count_documents({})
    high_alerts = alerts_collection.count_documents({"severity": "high"})

    return {
        "logs": total_logs,
        "alerts": total_alerts,
        "high_alerts": high_alerts,
    }


@app.post("/logs")
def ingest_log(log: Log):
    log_data = log.dict()

    # store log
    logs_collection.insert_one(log_data)

    # run all detection rules on this log
    run_detections(log_data)

    return {"status": "log stored"}


@app.get("/logs")
def get_logs():
    logs = list(logs_collection.find({}, {"_id": 0}))
    return logs


@app.get("/alerts")
def get_alerts():
    alerts = list(alerts_collection.find({}, {"_id": 0}))
    return alerts
@app.get("/geo-events")
def geo_events(limit: int = 200):
    """
    Return recent log events that have geolocation info,
    used by the world attack map.
    """
    cursor = (
        logs_collection.find(
            {"raw.location.lat": {"$exists": True}},
            {"_id": 0}
        )
        .sort("timestamp", -1)
        .limit(limit)
    )
    return list(cursor)
