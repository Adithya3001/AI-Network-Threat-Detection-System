# AI-Based Network Threat Detection System

A real-time cybersecurity application that captures live network traffic, builds network flows, extracts 78 CICIDS2017 machine-learning features, classifies each flow with an **XGBoost** model, stores predictions in **SQLite**, and visualises everything in a modern **SOC-style React dashboard**.

```
Live Network → Scapy Packet Capture → Flow Builder → Feature Generator
    → XGBoost Model → Prediction → SQLite → FastAPI REST API → React Dashboard
```

## Tech Stack

| Layer      | Technology                                        |
|------------|---------------------------------------------------|
| Frontend   | React (Vite) · React Router · Axios · Recharts · React Icons |
| Backend    | Python · FastAPI · Scapy · SQLite                 |
| AI / ML    | XGBoost Classifier · CICIDS2017 Dataset           |

---

## Getting Started

### 1. Backend

```bash
cd backend

# create a virtual environment (recommended)
python -m venv venv
venv\Scripts\activate          # Windows

# install dependencies
pip install -r ../requirements.txt

# start the FastAPI server
python -m uvicorn api:app --host 127.0.0.1 --port 8000 --reload
```

The API is available at `http://127.0.0.1:8000` (interactive docs at `/docs`).

> Note: on first start the XGBoost model is loaded, which can take a few seconds.

### 2. Start capture (real traffic) or Demo Mode

**Option A — Live capture** (requires the Wi-Fi adapter and admin/root privileges):

```bash
curl -X POST http://127.0.0.1:8000/capture/start
curl -X POST http://127.0.0.1:8000/capture/stop
```

**Option B — Demo mode** (replays real CICIDS2017 flows through the live model for an instant, realistic showcase):

```bash
curl -X POST http://127.0.0.1:8000/demo/start
curl -X POST http://127.0.0.1:8000/demo/stop
```

You can also start capture or demo mode from the **System Health** panel in the dashboard.

### 3. Frontend

```bash
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173`.

---

## Architecture

```
Internet
    │
    ▼
Network Adapter (Wi-Fi) ── Scapy packet sniffing
    │
    ▼
Flow Builder ──────────── 5-tuple flow grouping (fwd / bwd)
    │
    ▼
Feature Generator ─────── 78 CICIDS2017 features
    │
    ▼
AI Prediction ─────────── XGBoost multiclass classification + confidence
    │
    ▼
SQLite Database ───────── threats table + events pipeline log
    │
    ▼
FastAPI REST API ──────── /history /live /stats /alerts /events /traffic /health ...
    │
    ▼
React Dashboard ───────── SOC-style multi-page dashboard
```

---

## Backend Structure

```
backend/
├── api.py               # FastAPI app — all REST endpoints
├── packet_capture.py    # live Scapy capture, pipeline processing
├── flow_builder.py      # groups packets into forward/backward flows
├── feature_generator.py # 78-feature CICIDS2017 extraction
├── predictor.py         # XGBoost model loading + prediction
├── explainer.py         # heuristic AI decision explanation
├── alerts.py            # severity classification + descriptions
├── database.py          # SQLite schema, migrations, inserts
├── monitor.py           # in-memory live state (traffic, connections, events)
├── demo_generator.py    # demo mode — replays real CICIDS2017 flows
└── threats.db           # SQLite database
```

## Frontend Structure

```
frontend/src/
├── App.jsx              # React Router routes
├── constants.js         # severity / attack colours
├── hooks/usePolling.js  # polling data-fetch hook
├── components/          # 20+ UI components (cards, charts, panels, modals)
├── pages/               # Dashboard · Monitoring · Analytics · Alerts · Network · About
└── styles.css           # SOC dark theme
```

---

## API Endpoints

| Method | Endpoint                  | Description |
|--------|---------------------------|-------------|
| GET    | `/`                       | API info + capture status |
| GET    | `/history`                | Latest predictions |
| GET    | `/live`                   | Most recent prediction |
| GET    | `/latest-threat`          | Most recent attack |
| GET    | `/stats`                  | Totals, threat level, attack breakdown |
| GET    | `/alerts`                 | Attack alerts with severity |
| GET    | `/events`                 | Live pipeline event log |
| GET    | `/traffic`                | Packets/sec time series |
| GET    | `/attack-trend`           | Attack frequency over time |
| GET    | `/protocols`              | TCP / UDP / OTHER distribution |
| GET    | `/active-connections`     | Current source→destination connections |
| GET    | `/top-attacks`            | Attack type distribution |
| GET    | `/top-talkers`            | Busiest source IPs |
| GET    | `/ai-decision`            | Last prediction + explanation |
| GET    | `/health`                 | API / DB / model / capture status |
| POST   | `/capture/start` `/capture/stop` | Control live capture |
| POST   | `/demo/start` `/demo/stop`      | Control demo mode |

---

## Dashboard Features

- **Dashboard** — threat-level gauge, latest threat, live traffic graph, AI decision panel, recent alerts, system health, pipeline explainer.
- **Monitoring** — packet inspector (click any row), search/filter, CSV export, live event log.
- **Analytics** — traffic distribution, attack distribution, attack trend, top attack vectors, top talkers, protocol donut.
- **Alerts** — full alert history, severity breakdown (Critical / High / Medium), alert detail popups, CSV export.
- **Network Map** — live SVG network topology, local devices vs external hosts, active connections.
- **About** — project, stack, model, dataset and feature documentation.

---

## Model

- **Algorithm**: XGBoost (multiclass) — ~99.8% accuracy on the CICIDS2017 evaluation split.
- **Classes**: BENIGN, PortScan, FTP-Patator, SSH-Patator, Bot, DDoS, DoS Hulk, DoS GoldenEye, DoS Slowloris, DoS Slowhttptest, Web Attack (Brute Force / XSS).
- **Features**: 78 network-flow features from the CICIDS2017 feature set.
- **Location**: `models/best_model.pkl`, `models/label_encoder.pkl`.
