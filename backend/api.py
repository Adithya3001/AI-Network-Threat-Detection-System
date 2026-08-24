import asyncio
import threading
import time

from fastapi import FastAPI, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from alerts import enrich_prediction, get_attack_description, get_severity
from database import fetch_events, fetch_history, get_connection, initialize_database
from demo_generator import start_demo, stop_demo
from explainer import explain
from monitor import (capture_status, get_live_state,
                     log_event, manager, traffic_series)
from packet_capture import start_capture, stop_capture, ensure_flow_predictor_running

app = FastAPI(title="AI Network Threat Detection API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173", "http://127.0.0.1:5173",
        "http://localhost:5174", "http://127.0.0.1:5174",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

initialize_database()


# ---------------- Background traffic flusher ----------------

def _traffic_worker():
    while True:
        time.sleep(1)
        try:
            from monitor import flush_traffic
            flush_traffic()
        except Exception:
            pass


threading.Thread(target=_traffic_worker, daemon=True).start()


# ---------------- WebSocket broadcaster ----------------

async def _ws_broadcaster():
    while True:
        await asyncio.sleep(1.5)
        try:
            from monitor import build_snapshot
            if manager.count > 0:
                await manager.broadcast(build_snapshot())
        except Exception:
            pass


@app.on_event("startup")
async def on_startup():
    log_event("System", "API server started", "backend online")
    ensure_flow_predictor_running()
    asyncio.create_task(_ws_broadcaster())


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        # send an immediate snapshot on connect
        from monitor import build_snapshot
        await websocket.send_json(build_snapshot())
        while True:
            await websocket.receive_text()  # keep alive / ignore client messages
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception:
        manager.disconnect(websocket)


# ---------------- Home ----------------

@app.get("/")
def home():
    return {
        "message": "AI Network Threat Detection System API Running",
        "status": capture_status,
        "docs": "/docs",
    }


# ---------------- History ----------------

@app.get("/history")
def get_history(limit: int = Query(200, le=1000)):
    rows = fetch_history(limit)
    return [enrich_prediction(r) for r in rows]


# ---------------- Live ----------------

@app.get("/live")
def get_live():
    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM threats ORDER BY id DESC LIMIT 1"
    ).fetchone()
    conn.close()

    if row:
        return enrich_prediction(dict(row))
    return {}


# ---------------- Latest Threat ----------------

@app.get("/latest-threat")
def latest_threat():
    conn = get_connection()
    row = conn.execute("""
        SELECT * FROM threats
        WHERE attack_type != 'BENIGN'
        ORDER BY id DESC LIMIT 1
    """).fetchone()
    conn.close()

    if row:
        return enrich_prediction(dict(row))
    return {}


# ---------------- Statistics ----------------

@app.get("/stats")
def get_stats():
    conn = get_connection()

    total = conn.execute("SELECT COUNT(*) FROM threats").fetchone()[0]
    benign = conn.execute(
        "SELECT COUNT(*) FROM threats WHERE attack_type='BENIGN'"
    ).fetchone()[0]
    attacks = total - benign

    recent_attacks = conn.execute("""
        SELECT COUNT(*) FROM (
            SELECT attack_type FROM threats
            ORDER BY id DESC LIMIT 100
        ) WHERE attack_type != 'BENIGN'
    """).fetchone()[0]

    # Attack type breakdown
    type_counts = conn.execute("""
        SELECT attack_type, COUNT(*) as count
        FROM threats
        WHERE attack_type != 'BENIGN'
        GROUP BY attack_type
        ORDER BY count DESC
    """).fetchall()

    # Per-severity breakdown
    severity_counts = conn.execute("""
        SELECT severity, COUNT(*) as count
        FROM threats
        WHERE severity != 'None'
        GROUP BY severity
    """).fetchall()

    conn.close()

    if recent_attacks == 0:
        threat_level, severity = "SAFE", 20
    elif recent_attacks <= 5:
        threat_level, severity = "WARNING", 60
    else:
        threat_level, severity = "CRITICAL", 100

    return {
        "total_predictions": total,
        "benign": benign,
        "attacks": attacks,
        "recent_attacks": recent_attacks,
        "threat_level": threat_level,
        "severity": severity,
        "attack_types": [dict(r) for r in type_counts],
        "severity_counts": [dict(r) for r in severity_counts],
        "capture": capture_status,
    }


# ---------------- Top Talkers ----------------

@app.get("/top-talkers")
def top_talkers(limit: int = 5):
    conn = get_connection()
    rows = conn.execute("""
        SELECT source_ip, COUNT(*) AS packets, SUM(bytes) AS total_bytes
        FROM threats
        GROUP BY source_ip
        ORDER BY packets DESC
        LIMIT ?
    """, (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ---------------- Alerts (attacks with severity) ----------------

@app.get("/alerts")
def get_alerts(limit: int = Query(50, le=500)):
    conn = get_connection()
    rows = conn.execute("""
        SELECT * FROM threats
        WHERE attack_type != 'BENIGN'
        ORDER BY id DESC LIMIT ?
    """, (limit,)).fetchall()
    conn.close()
    return [enrich_prediction(dict(r)) for r in rows]


# ---------------- Live event log ----------------

@app.get("/events")
def get_events(limit: int = Query(100, le=300)):
    return get_live_state()["events"][:limit]


# ---------------- Live traffic graph ----------------

@app.get("/traffic")
def get_traffic():
    state = get_live_state()
    return state["traffic"]


# ---------------- Attack trend ----------------

@app.get("/attack-trend")
def attack_trend(minutes: int = Query(30, le=720)):
    conn = get_connection()
    rows = conn.execute("""
        SELECT timestamp, attack_type
        FROM threats
        WHERE attack_type != 'BENIGN'
        ORDER BY id DESC LIMIT 2000
    """).fetchall()
    conn.close()

    buckets = {}
    for r in rows:
        key = r["timestamp"][:16]  # minute granularity
        buckets[key] = buckets.get(key, 0) + 1

    series = sorted(buckets.items())[-minutes:]
    return [
        {"ts": k, "attacks": v} for k, v in series
    ]


# ---------------- Protocol distribution ----------------

@app.get("/protocols")
def protocols():
    conn = get_connection()
    rows = conn.execute("""
        SELECT protocol, COUNT(*) as count
        FROM threats
        GROUP BY protocol
    """).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ---------------- Active connections ----------------

@app.get("/active-connections")
def active_connections():
    return get_live_state()["connections"]


# ---------------- Top attacks (chart data) ----------------

@app.get("/top-attacks")
def top_attacks(limit: int = 8):
    conn = get_connection()
    rows = conn.execute("""
        SELECT attack_type, COUNT(*) as count
        FROM threats
        WHERE attack_type != 'BENIGN'
        GROUP BY attack_type
        ORDER BY count DESC LIMIT ?
    """, (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ---------------- AI Decision Panel ----------------

@app.get("/ai-decision")
def ai_decision():
    from monitor import get_ai_decision
    decision = get_ai_decision()
    if not decision["prediction"]:
        return {"prediction": None}

    features = decision["features"]
    result = explain(
        decision["prediction"],
        decision["confidence"],
        features,
    )
    result["timestamp"] = decision["timestamp"]
    result["prediction"] = result["attack"]
    return result


# ---------------- System Health ----------------

@app.get("/health")
def health():
    db_ok = True
    try:
        conn = get_connection()
        conn.execute("SELECT COUNT(*) FROM threats")
        conn.close()
    except Exception:
        db_ok = False

    model_loaded = True
    model_name = "XGBoost"
    try:
        import predictor
        model_loaded = predictor.model is not None
    except Exception:
        model_loaded = False

    return {
        "api": "online",
        "database": "ok" if db_ok else "error",
        "model": {
            "name": model_name,
            "loaded": model_loaded,
        },
        "capture": capture_status,
        "uptime": time.strftime("%H:%M:%S"),
    }


# ---------------- Capture control ----------------

@app.post("/capture/start")
def capture_start():
    from packet_capture import start_capture
    return start_capture()


@app.post("/capture/stop")
def capture_stop():
    from packet_capture import stop_capture
    return stop_capture()


# ---------------- Demo control ----------------

@app.post("/demo/start")
def demo_start(attack_label: str = None):
    return start_demo(attack_label)


@app.post("/demo/stop")
def demo_stop():
    return stop_demo()


# ---------------- Reset ----------------

@app.post("/reset")
def reset():
    from database import reset_threats
    from monitor import reset_state
    reset_threats()
    reset_state()
    log_event("System", "Threat detections reset", "database cleared")
    return {"status": "ok", "message": "Threat detections reset"}


# ---------------- Virtual network ----------------

@app.get("/vnet/hosts")
def vnet_hosts():
    from virtual_network import get_virtual_hosts
    return get_virtual_hosts()


@app.post("/vnet/start")
def vnet_start():
    from virtual_network import start_vnet
    return start_vnet()


@app.post("/vnet/stop")
def vnet_stop():
    from virtual_network import stop_vnet
    return stop_vnet()


# ---------------- Model training & comparison ----------------

@app.get("/model-comparison")
def model_comparison():
    from training import get_comparison
    return get_comparison()


@app.get("/model-info")
def model_info():
    from training import get_model_info
    return get_model_info()


@app.get("/training/status")
def training_status():
    from training import get_training_status
    return get_training_status()


@app.post("/retrain")
def retrain(train_models: bool = True):
    from training import start_retrain
    return start_retrain(train_models)


# ---------------- Severity helper ----------------

@app.get("/severity/{attack_type}")
def severity_lookup(attack_type: str):
    return {
        "attack_type": attack_type,
        "severity": get_severity(attack_type),
        "description": get_attack_description(attack_type),
    }
