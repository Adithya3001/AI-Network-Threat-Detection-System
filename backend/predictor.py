import os
import threading

import joblib
import pandas as pd

BASE_DIR = os.path.dirname(__file__)
MODEL_PATH = os.path.join(BASE_DIR, "..", "models", "best_model.pkl")
LABEL_PATH = os.path.join(BASE_DIR, "..", "models", "label_encoder.pkl")

_lock = threading.Lock()

# Lazy-loaded global model (replaced by reload_model() after retraining)
model = None
label_encoder = None


def _ensure_loaded():
    global model, label_encoder
    if model is None or label_encoder is None:
        model = joblib.load(MODEL_PATH)
        label_encoder = joblib.load(LABEL_PATH)
    return model, label_encoder


# Load the model eagerly at import so modules that read
# model.feature_names_in_ / model.classes_ can use them safely.
try:
    _ensure_loaded()
except Exception:
    pass


def reload_model():
    """Reload the model from disk (called after a retrain completes)."""
    global model, label_encoder
    with _lock:
        model = joblib.load(MODEL_PATH)
        label_encoder = joblib.load(LABEL_PATH)
    return model


def predict(features):
    m, le = _ensure_loaded()

    # Convert dictionary to DataFrame
    df = pd.DataFrame([features])

    # Ensure correct column order
    df = df[m.feature_names_in_]

    prediction = m.predict(df)[0]

    confidence = float(max(m.predict_proba(df)[0]))

    attack = le.inverse_transform([prediction])[0]

    return attack, confidence
