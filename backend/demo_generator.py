"""
Demo Mode - replays real CICIDS2017 flow records through the live XGBoost
pipeline so the dashboard shows authentic attack predictions.

The model was trained on CICIDS2017, so feeding it real flow vectors gives
realistic predictions and confidence scores. Each replayed flow is stored in
the database and tracked in the live monitor state exactly like live capture.
"""
import os
import random
import threading
import time
from datetime import datetime

import pandas as pd

from alerts import get_severity
from database import insert_prediction
from explainer import explain
from monitor import (
    capture_status,
    log_event,
    record_packet,
    set_ai_decision,
    update_capture_status,
)
from predictor import model, label_encoder

BASE_DIR = os.path.dirname(__file__)
DATA_PATH = os.path.join(BASE_DIR, "..", "dataset", "cleaned_dataset.csv")

MODEL_FEATURES = list(model.feature_names_in_)
KNOWN_LABELS = set(label_encoder.classes_)
LABEL_LOOKUP = {c.lower(): c for c in KNOWN_LABELS}


def _canonical_label(raw):
    cleaned = raw.replace("\ufffd", "-").strip().lower()
    return LABEL_LOOKUP.get(cleaned)

_flow_bank = {}          # label -> list of feature dicts
_flow_bank_ready = False
_demo_thread = None
_stop_flag = threading.Event()
_fixed_label = None      # optional: replay only this attack label

ATK_IPS = [
    "185.220.101.45", "103.86.99.55", "91.121.65.170",
    "45.155.205.233", "198.98.50.120", "176.123.7.66",
]
LAN = "192.168.1.10"


def load_flow_bank(rows=200000, per_label=25, force=False):
    """Load a stratified sample of real flows into memory (once)."""
    global _flow_bank, _flow_bank_ready

    if _flow_bank_ready and not force:
        return _flow_bank

    if not os.path.exists(DATA_PATH):
        log_event("Demo", "cleaned_dataset.csv not found - demo unavailable", "error")
        return {}

    cols = MODEL_FEATURES + ["Label"]
    bank = {}

    for chunk in pd.read_csv(DATA_PATH, usecols=cols, chunksize=50000):
        chunk["Label"] = chunk["Label"].map(_canonical_label)
        chunk = chunk.dropna(subset=["Label"])
        for label, group in chunk.groupby("Label"):
            need = per_label - len(bank.get(label, []))
            if need <= 0:
                continue
            for _, row in group.head(need).iterrows():
                bank.setdefault(label, []).append(row.to_dict())

        total = sum(len(v) for v in bank.values())
        if total >= rows:
            break

    # Keep only vectors the model actually classifies as their own label.
    # This keeps the demo authentic while guaranteeing a useful showcase.
    from predictor import predict

    for label in list(bank.keys()):
        kept = []
        for vec in bank[label]:
            feats = {k: vec[k] for k in MODEL_FEATURES if k in vec}
            try:
                pred, _ = predict(feats)
            except Exception:
                continue
            if pred == label:
                kept.append(vec)
        if len(kept) < 3 and bank[label]:
            # top up with any prediction (still real model output)
            extra = [v for v in bank[label] if v not in kept][: (3 - len(kept))]
            kept += extra
        bank[label] = kept[:per_label]

    bank = {str(k): v for k, v in bank.items() if v}
    _flow_bank = bank
    _flow_bank_ready = True

    labels = list(bank.keys())
    log_event(
        "Demo",
        f"Loaded {sum(len(v) for v in bank.values())} real flows "
        f"({len(labels)} classes)",
        "demo",
    )
    return bank


def _pick_flow(attack_label):
    """Pick a random real flow vector for the given attack label."""
    bank = load_flow_bank()

    if attack_label in bank and bank[attack_label]:
        vec = random.choice(bank[attack_label])
    else:
        # Fall back to any non-BENIGN vector
        non_benign = [v for k, v in bank.items() if k != "BENIGN" for v in v]
        vec = random.choice(non_benign) if non_benign else {}

    features = {k: vec[k] for k in MODEL_FEATURES if k in vec}
    return features


def _replay_one(attack_label):
    """Inject one real flow through the predictor and record everything."""
    from predictor import predict

    features = _pick_flow(attack_label)
    if not features:
        return

    try:
        prediction, confidence = predict(features)
    except Exception as e:
        log_event("AI Prediction", f"Prediction failed: {e}", "error")
        return

    atk_ip = random.choice(ATK_IPS)
    src_port = random.randint(1024, 65535)
    dst_port = int(features.get("Destination Port", 80))
    protocol = "TCP" if dst_port in (21, 22, 80, 443, 8080, 6667, 6668) else "UDP"

    # Real CICIDS flow stats for a realistic live table
    total_pkts = int(features.get("Total Fwd Packets", 0) + features.get("Total Backward Packets", 0))
    if total_pkts < 1:
        total_pkts = 5
    fwd_bytes = int(features.get("Total Length of Fwd Packets", 0))
    bwd_bytes = int(features.get("Total Length of Bwd Packets", 0))

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    threat_id = insert_prediction(
        timestamp,
        atk_ip,
        LAN,
        src_port,
        dst_port,
        protocol,
        prediction,
        float(confidence),
        packet_size=40,
        tcp_flags="S",
        severity=get_severity(prediction),
        bytes_total=fwd_bytes + bwd_bytes,
    )
    try:
        from database import insert_flow_features
        insert_flow_features(threat_id, prediction, features)
    except Exception:
        pass

    # Live monitor state (connection + traffic counter)
    record_packet(
        protocol, prediction, 40, {}, atk_ip, LAN,
        src_port, dst_port, "S",
    )

    if prediction == "BENIGN":
        log_event(
            "AI Prediction",
            f"{prediction} · {protocol} {atk_ip}:{src_port} → {LAN}:{dst_port}",
            f"{confidence * 100:.2f}%",
        )
    else:
        log_event(
            "AI Prediction",
            f"{prediction} · {atk_ip}:{src_port} → {LAN}:{dst_port}",
            f"{confidence * 100:.2f}% · severity {get_severity(prediction)}",
        )

    result = explain(prediction, confidence, features)
    result["timestamp"] = time.strftime("%H:%M:%S")
    result["prediction"] = prediction
    result["flow"] = {
        "total_packets": total_pkts,
        "fwd_bytes": fwd_bytes,
        "bwd_bytes": bwd_bytes,
        "destination_port": dst_port,
    }
    set_ai_decision(**result)


def _run_demo(attack_label=None):
    global _fixed_label
    _fixed_label = attack_label

    # Capture this generation's stop event so a later start_demo()
    # that replaces the module-level flag never affects this loop.
    stop_flag = _stop_flag

    # Mark the demo as running immediately so the dashboard shows
    # "Demo Mode Running" while the flow bank loads in the background.
    update_capture_status(
        running=True,
        mode="demo",
        started_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        error=None,
    )

    log_event("System", "Demo mode starting - loading CICIDS2017 flow bank", "demo")

    load_flow_bank()

    if not _flow_bank_ready or not _flow_bank:
        update_capture_status(
            running=False,
            mode="idle",
            error="Demo data unavailable (cleaned_dataset.csv missing)",
        )
        return

    update_capture_status(error=None)

    log_event("System", "Demo mode started - replaying real CICIDS2017 flows", "demo")

    while not stop_flag.is_set():
        if _fixed_label and _fixed_label in _flow_bank:
            label = _fixed_label
        else:
            label = random.choice(list(_flow_bank.keys()))
        burst = random.randint(1, 6)
        for _ in range(burst):
            if stop_flag.is_set():
                break
            _replay_one(label)
            capture_status["packets_seen"] += 1
            time.sleep(random.uniform(0.15, 0.6))

        time.sleep(random.uniform(0.3, 1.2))

    if capture_status["mode"] == "demo":

        update_capture_status(
            running=False,
            mode="idle",
        )

        log_event(
            "System",
            "Demo mode stopped",
            "idle"
        )


def start_demo(attack_label=None):
    global _demo_thread, _stop_flag
    if capture_status["running"] and capture_status["mode"] == "demo":
        return {"status": "already_running"}

    if _demo_thread is not None and _demo_thread.is_alive():
        return {"status": "already_running"}

    _stop_flag = threading.Event()

    # Only one source mode (live / demo) may run at a time.
    # Stop a running live capture before starting the demo.
    try:

        from packet_capture import stop_capture

        if (
            capture_status["running"]
            and capture_status["mode"] == "live"
        ):

            stop_capture()

    except ImportError:

        pass

    _demo_thread = threading.Thread(target=_run_demo, args=(attack_label,), daemon=True, name="demo")
    _demo_thread.start()
    return {"status": "started", "mode": "demo"}


def stop_demo():
    if capture_status["running"]:
        _stop_flag.set()
    return {"status": "stopping", "running": capture_status["running"]}
