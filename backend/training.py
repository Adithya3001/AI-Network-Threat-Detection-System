"""
Model training pipeline:
  * evaluates XGBoost vs Random Forest vs Decision Tree vs Logistic Regression
  * supports live retraining on captured traffic (dataset sample + stored flow features)
  * swaps the active model used by the predictor
"""
import csv
import os
import threading
import time
from datetime import datetime

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.tree import DecisionTreeClassifier
from xgboost import XGBClassifier

BASE_DIR = os.path.dirname(__file__)
MODELS_DIR = os.path.join(BASE_DIR, "..", "models")
DATA_PATH = os.path.join(BASE_DIR, "..", "dataset", "cleaned_dataset.csv")
COMPARISON_PATH = os.path.join(MODELS_DIR, "model_comparison.csv")
BEST_PATH = os.path.join(MODELS_DIR, "best_model.pkl")
LABEL_PATH = os.path.join(MODELS_DIR, "label_encoder.pkl")

# ------------------------------------------------------------------
# Status
# ------------------------------------------------------------------

_training_status = {
    "running": False,
    "stage": "idle",
    "progress": 0.0,
    "message": "No training in progress",
    "started_at": None,
    "finished_at": None,
    "result": None,
    "error": None,
}

_status_lock = threading.Lock()


def get_training_status():
    with _status_lock:
        return dict(_training_status)


def _set_status(**kwargs):
    with _status_lock:
        _training_status.update(kwargs)


def get_comparison():
    """Return the saved model comparison CSV as JSON."""
    if not os.path.exists(COMPARISON_PATH):
        return []
    with open(COMPARISON_PATH, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    for r in rows:
        for k, v in r.items():
            if k != "Model":
                try:
                    r[k] = round(float(v), 4)
                except ValueError:
                    pass
    return rows


def get_model_info():
    """Metadata about the active model."""
    info = {
        "name": "XGBoost",
        "path": BEST_PATH,
        "trained_at": None,
        "classes": [],
        "n_features": 0,
    }
    try:
        from predictor import model, label_encoder
        info["n_features"] = len(model.feature_names_in_)
        info["classes"] = [str(c) for c in label_encoder.classes_]
        mtime = os.path.getmtime(BEST_PATH)
        info["trained_at"] = datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        pass
    return info


# ------------------------------------------------------------------
# Data loading
# ------------------------------------------------------------------

def _load_sample(dataset_rows=40000, per_class=4000, captured_limit=3000):
    """Stratified dataset sample merged with captured live features."""
    cols = None
    try:
        from predictor import model, label_encoder
        cols = list(model.feature_names_in_) + ["Label"]
    except Exception:
        return None, None, None

    frames = []

    # 1) Dataset sample
    if os.path.exists(DATA_PATH):
        chunks = pd.read_csv(DATA_PATH, usecols=cols, chunksize=100000)
        known = {c.lower(): c for c in label_encoder.classes_}
        collected = {}

        for chunk in chunks:
            chunk.columns = [c.strip() for c in chunk.columns]
            chunk["Label"] = (
                chunk["Label"].astype(str)
                .str.replace("\ufffd", "-")
                .str.strip()
            )
            chunk["Label"] = chunk["Label"].map(lambda x: known.get(x.lower(), None))
            chunk = chunk.dropna(subset=["Label"])
            for label, group in chunk.groupby("Label"):
                need = per_class - collected.get(label, 0)
                if need <= 0:
                    continue
                picked = group.head(need)
                frames.append(picked)
                collected[label] = collected.get(label, 0) + len(picked)
            if sum(collected.values()) >= dataset_rows:
                break

    # 2) Captured live features (from our own detection history)
    try:
        from database import fetch_flow_features
        captured = fetch_flow_features(captured_limit)
        if captured:
            cap_df = pd.DataFrame([c["features"] for c in captured])
            cap_df["Label"] = [c["attack_type"] for c in captured]
            # only include features the model knows
            cap_df = cap_df[[c for c in cap_df.columns if c in cols]]
            frames.append(cap_df)
    except Exception:
        pass

    if not frames:
        return None, None, None

    df = pd.concat(frames, ignore_index=True)
    df = df.dropna()

    X = df.drop("Label", axis=1)
    y = df["Label"]

    # Balance-ish sample cap
    if len(X) > 60000:
        keep = df.sample(n=60000, random_state=42)
        X = keep.drop("Label", axis=1)
        y = keep["Label"]

    return X, y, None


# ------------------------------------------------------------------
# Training
# ------------------------------------------------------------------

def _evaluate(model, X_test, y_test, le):
    y_pred = model.predict(X_test)
    return {
        "Accuracy": round(accuracy_score(y_test, y_pred), 4),
        "Precision": round(precision_score(y_test, y_pred, average="weighted", zero_division=0), 4),
        "Recall": round(recall_score(y_test, y_pred, average="weighted", zero_division=0), 4),
        "F1 Score": round(f1_score(y_test, y_pred, average="weighted", zero_division=0), 4),
        "classes": list(le.classes_),
    }


def _save_comparison(rows):
    os.makedirs(MODELS_DIR, exist_ok=True)
    with open(COMPARISON_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["Model", "Accuracy", "Precision", "Recall", "F1 Score"])
        writer.writeheader()
        for r in rows:
            writer.writerow({k: r[k] for k in writer.fieldnames})


def _train_worker(train_models=True):
    try:
        _set_status(
            running=True, stage="data",
            progress=0.05, message="Loading training data…",
            started_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            result=None, error=None,
        )

        X, y, _ = _load_sample()
        if X is None or len(X) < 2000:
            _set_status(running=False, stage="error", progress=0,
                        message="Not enough training data (need dataset or captured flows).",
                        error="insufficient data")
            return

        _set_status(stage="split", progress=0.2,
                    message=f"Prepared {len(X):,} flows across {len(set(y))} classes")

        le = LabelEncoder()
        y_enc = le.fit_transform(y)

        X_train, X_test, y_train, y_test = train_test_split(
            X, y_enc, test_size=0.2, random_state=42, stratify=y_enc,
        )

        results = []

        # ---- XGBoost (primary) ----
        _set_status(stage="train", progress=0.35, message="Training XGBoost…")
        xgb = XGBClassifier(
            n_estimators=200, max_depth=8, learning_rate=0.1,
            subsample=0.9, colsample_bytree=0.9,
            eval_metric="mlogloss", n_jobs=-1, random_state=42,
        )
        xgb.fit(X_train, y_train, verbose=False)
        results.append({
            "Model": "XGBoost",
            "model": xgb,
            **{k: v for k, v in _evaluate(xgb, X_test, y_test, le).items() if k != "classes"},
        })
        _set_status(stage="train", progress=0.55, message=f"XGBoost done · acc {results[-1]['Accuracy']:.4f}")

        if train_models:
            # ---- Random Forest ----
            _set_status(stage="train", progress=0.65, message="Training Random Forest…")
            rf = RandomForestClassifier(n_estimators=80, random_state=42, n_jobs=-1)
            rf.fit(X_train, y_train)
            results.append({
                "Model": "Random Forest",
                "model": rf,
                **{k: v for k, v in _evaluate(rf, X_test, y_test, le).items() if k != "classes"},
            })

            # ---- Decision Tree ----
            _set_status(stage="train", progress=0.75, message="Training Decision Tree…")
            dt = DecisionTreeClassifier(max_depth=18, random_state=42)
            dt.fit(X_train, y_train)
            results.append({
                "Model": "Decision Tree",
                "model": dt,
                **{k: v for k, v in _evaluate(dt, X_test, y_test, le).items() if k != "classes"},
            })

            # ---- Logistic Regression ----
            _set_status(stage="train", progress=0.85, message="Training Logistic Regression…")
            lr = LogisticRegression(max_iter=200, n_jobs=-1)
            lr.fit(X_train, y_train)
            results.append({
                "Model": "Logistic Regression",
                "model": lr,
                **{k: v for k, v in _evaluate(lr, X_test, y_test, le).items() if k != "classes"},
            })

        # Save comparison CSV
        _save_comparison(results)

        # Save best model (XGBoost) + encoder
        _set_status(stage="save", progress=0.92, message="Saving model…")
        joblib.dump(results[0]["model"], BEST_PATH)
        joblib.dump(le, LABEL_PATH)

        # Swap the live model
        from predictor import reload_model
        reload_model()

        _set_status(
            running=False, stage="complete", progress=1.0,
            message="Retraining complete — model is now live",
            finished_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            result={
                "accuracy": results[0]["Accuracy"],
                "f1": results[0]["F1 Score"],
                "trained_flows": int(len(X)),
                "classes": len(le.classes_),
            },
        )
    except Exception as e:
        _set_status(
            running=False, stage="error", progress=0,
            message=f"Training failed: {e}",
            error=str(e),
        )


def start_retrain(train_models=True):
    with _status_lock:
        if _training_status["running"]:
            return {"status": "already_running"}
        _training_status["running"] = True

    t = threading.Thread(target=_train_worker, args=(train_models,), daemon=True)
    t.start()
    return {"status": "started"}
