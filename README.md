<!-- 
  PLACEHOLDER: Replace badge URLs below with real ones once CI/CD, releases, and license
  are finalized. See https://shields.io for badge generation.
-->
<div align="center">

# 🛡️ AI Network Threat Detection System

**An AI-powered Network Intrusion Detection System (NIDS) with real-time packet capture, machine-learning classification, and a live SOC dashboard.**

</div>

---

## Description

The **AI Network Threat Detection System** is an integrated network security monitoring platform that combines real-time packet capture, network-flow analysis, and machine-learning classification into a single tool. Built around a trained **XGBoost** model, it inspects live network traffic (or replays labeled traffic from the **CICIDS2017** dataset in Demo Mode) to detect malicious activity such as port scans, DoS/DDoS attacks, brute-force attempts, and web attacks — surfacing the results through a modern, real-time **SOC-style dashboard**. It's designed for students, security researchers, and blue-team practitioners who want a hands-on, self-contained environment for learning network intrusion detection, experimenting with ML-based threat classification, or running controlled security demonstrations in a lab setting.

---

## Table of Contents

- [Description](#description)
- [Features](#features)
- [Architecture](#architecture)
- [Technology Stack](#technology-stack)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
  - [1. Clone the Repository](#1-clone-the-repository)
  - [2. Backend Setup](#2-backend-setup)
  - [3. Frontend Setup](#3-frontend-setup)
- [Usage](#usage)
  - [Running the System](#running-the-system)
  - [Demo Mode](#demo-mode)
  - [Live Capture Mode](#live-capture-mode)
  - [Live Capture Demo with Kali Linux](#live-capture-demo-with-kali-linux)
- [Dataset](#dataset)
- [Project Structure](#project-structure)
- [API Reference](#api-reference)
- [Troubleshooting / Getting Help](#troubleshooting--getting-help)
- [Contributing](#contributing)
- [Future Improvements](#future-improvements)
- [Security and Responsible Use](#security-and-responsible-use)
- [License](#license)
- [Acknowledgments](#acknowledgments)
- [Contact / Support](#contact--support)

---

## Features

- **AI-based threat detection** using a trained XGBoost model, classifying traffic into categories such as `BENIGN`, `PortScan`, `DoS GoldenEye`, `DDoS`, `SSH-Patator`, `FTP-Patator`, `Web Attacks`, `Bot`, and `Infiltration`
- **Real-time packet capture** via Scapy and Npcap, with automatic network interface detection (no manual interface index configuration required)
- **Dedicated PortScan detection logic** that analyzes SYN packets, destination-port frequency, and flow behavior
- **Demo Mode** that replays CICIDS2017 flow data — no live capture, Kali Linux, or admin privileges required
- **Live SOC dashboard** built with React/Vite showing:
  - Total predictions, benign traffic, and detected attacks
  - Recent alerts, threat level, and severity
  - Live traffic graphs, protocol statistics, and network topology
  - An **AI Decision Engine** panel with confidence scores, observed signals, and flow-level explanations
- **Persistent storage** of predictions, alerts, and flow data in SQLite, with in-memory caching for live monitoring performance
- **FastAPI backend** exposing REST endpoints and interactive Swagger documentation

---

## Architecture

<!-- Alt text provided for accessibility since this is a text-based diagram -->
<details>
<summary><strong>High-level data flow</strong> (click to expand)</summary>

```text
NETWORK TRAFFIC
      │
      ▼
Scapy / Npcap → Packet Capture → Flow Builder → Feature Extraction → XGBoost Model
                                                                          │
                                                          ┌───────────────┴───────────────┐
                                                          ▼                               ▼
                                                       BENIGN                          ATTACK
                                                                                           │
                                                                                           ▼
                                                                                Alert / Severity Engine
                                                                                           │
                                                                                           ▼
                                                                                       SQLite
                                                                                           │
                                                                                           ▼
                                                                                       FastAPI
                                                                                           │
                                                                                           ▼
                                                                              React/Vite SOC Dashboard
```

*Diagram description: Raw network traffic is captured via Scapy/Npcap, assembled into flows, converted into ML features, and classified by an XGBoost model as either benign or an attack. Attack predictions pass through an alert/severity engine, are persisted to SQLite, served via FastAPI, and visualized in the React SOC dashboard.*

</details>

<details>
<summary><strong>WSL / Kali automatic interface resolution</strong> (click to expand)</summary>

```text
Kali Linux (172.29.2.45)
      │
      ▼
WSL / Hyper-V Network
      │
      ▼
Windows Host (172.29.0.1)
      │
      ▼
Npcap → Scapy
```

*Diagram description: In a WSL/Kali lab setup, traffic originating on the Kali virtual adapter passes through the Hyper-V virtual network to the Windows host, where Npcap and Scapy capture it — without requiring the user to manually specify an interface index.*

</details>

---

## Technology Stack

| Layer | Technology |
|---|---|
| Frontend | React |
| Build Tool | Vite |
| Backend | FastAPI |
| Programming Language | Python |
| Packet Capture | Scapy |
| Windows Packet Capture | Npcap |
| Machine Learning | XGBoost |
| Data Processing | Pandas / NumPy |
| Database | SQLite |
| Dataset | CICIDS2017 |
| Testing Environment | Kali Linux / WSL |
| Version Control | Git / GitHub |

---

## Prerequisites

- Windows 10/11
- Python 3.11
- Node.js and npm
- Git
- [Npcap](https://npcap.com/) (required for live packet capture)
- Kali Linux / WSL (only required for the live Kali demonstration)

> **Note:** A pre-trained model is included in the repository, so the CICIDS2017 dataset itself is **not required** to run the application — only to retrain or re-evaluate models.

---

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/Adithya3001/AI-Network-Threat-Detection-System.git
cd AI-Network-Threat-Detection-System
```

### 2. Backend Setup

```powershell
cd backend
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r ..\requirements.txt
```

If PowerShell blocks script execution (execution policy restrictions), install dependencies directly through the venv's Python executable instead:

```powershell
.\venv\Scripts\python.exe -m pip install -r ..\requirements.txt
```

<!-- PLACEHOLDER: Add macOS/Linux backend setup commands if the project is intended to support non-Windows hosts -->

### 3. Frontend Setup

```bash
cd frontend
npm install
```

---

## Usage

### Running the System

The backend and frontend run as two separate processes.

**Terminal 1 — Backend**

```bash
cd "AI-Network-Threat-Detection-System/backend"
python -m uvicorn api:app --host 0.0.0.0 --port 8000
```

> ⚠️ Run only **one** backend instance on port 8000 at a time.

| Endpoint | URL |
|---|---|
| Backend root | http://127.0.0.1:8000 |
| API docs (Swagger) | http://127.0.0.1:8000/docs |
| Health check | http://127.0.0.1:8000/health |

**Terminal 2 — Frontend**

```bash
cd "AI-Network-Threat-Detection-System/frontend"
npm run dev
```

Open the URL Vite prints (typically `http://localhost:5173`; Vite will pick another port automatically if 5173 is in use).

### Demo Mode

Demo Mode replays labeled CICIDS2017 flow data through the same detection pipeline used for live traffic — useful when packet capture isn't available or a repeatable demo is needed.

```text
CICIDS2017 Flow → Feature Processing → XGBoost Model → Prediction → Alert/Severity → Dashboard
```

No live capture, Kali Linux, or administrator privileges are required.

### Live Capture Mode

Live Capture processes real packets from a network interface:

```text
Real Network Traffic → Npcap → Scapy → Packet Processing → Flow Construction
                     → Feature Generation → XGBoost Prediction → Threat Detection
                     → FastAPI → React Dashboard
```

> On Windows, live packet capture may require **Administrator** privileges.

### Live Capture Demo with Kali Linux

This walkthrough is intended for a **controlled lab environment** only.

Example network layout:

| Host | IP Address |
|---|---|
| Kali Linux | `172.29.2.45` |
| Windows / WSL | `172.29.0.1` |

**Step 1 — Start the backend** (as Administrator if live capture requires it)

```powershell
cd "AI-Network-Threat-Detection-System\backend"
python -m uvicorn api:app --host 0.0.0.0 --port 8000
```

**Step 2 — Start the frontend**

```bash
cd "AI-Network-Threat-Detection-System/frontend"
npm run dev
```

**Step 3 — Start live capture from the dashboard**

Navigate to **System Health → Start Live Capture**. The application automatically resolves the correct network interface.

<details>
<summary><strong>Optional: run a local HTTP test server for traffic generation</strong></summary>

```bash
cd "AI-Network-Threat-Detection-System"
python -m http.server 8080 --bind 0.0.0.0
```

The test service is then available at `http://172.29.0.1:8080`.

</details>

<details>
<summary><strong>Generate normal traffic from Kali</strong></summary>

```bash
wsl -d kali-linux
```

Continuous HTTP traffic:

```bash
while true; do curl -s http://172.29.0.1:8080 > /dev/null; sleep 1; done
```

Or continuous ICMP traffic:

```bash
ping 172.29.0.1
```

</details>

<details>
<summary><strong>Controlled PortScan demonstration</strong></summary>

> ⚠️ Only scan systems you own or are explicitly authorized to test.

```bash
nmap -sS -p 1-1000 172.29.0.1
```

Expected flow:

```text
Normal Traffic → BENIGN → Nmap SYN Scan → PortScan Detection → PORTSCAN Alert → Dashboard
```

The dashboard should display an alert similar to:

| Field | Example Value |
|---|---|
| Attack Type | `PORTSCAN` |
| Confidence | `~99%` |
| Severity | `Medium` |
| Source | `172.29.2.45` |
| Destination | `172.29.0.1` |
| Ports Scanned | `<count>` |

To return to a normal traffic baseline:

```bash
ping -c 5 172.29.0.1
```

</details>

**Demo Mode vs. Live Capture**

| Feature | Live Capture | Demo Mode |
|---|---|---|
| Real packets | Yes | No |
| Kali required | For Kali demo | No |
| Npcap required | Yes | No |
| Administrator privileges | May be required | No |
| CICIDS2017 flows | No | Yes |
| Real-time dashboard | Yes | Yes |
| Repeatable demo | Environment dependent | Yes |
| Network interface required | Yes | No |

---

## Dataset

This project uses the **CICIDS2017 (CIC-IDS2017)** dataset, provided by the Canadian Institute for Cybersecurity at the University of New Brunswick, for model training and evaluation. The dataset includes labeled benign traffic alongside multiple attack categories (DoS, DDoS, PortScan, Brute Force, Web Attacks, Infiltration, Bot).

- **Official download:** https://www.unb.ca/cic/datasets/ids-2017.html
- Place extracted CSV files under `dataset/CICIDS2017/` (excluded from version control due to file size, ~1.8 GB)
- **The dataset is not required to run the application** — a pre-trained model ships with the repo. It's only needed to retrain the model, modify preprocessing, perform feature selection, or evaluate new configurations.

---

## Project Structure

```text
AI-Network-Threat-Detection-System/
│
├── backend/
│   ├── alerts.py
│   ├── api.py
│   ├── database.py
│   ├── demo_generator.py
│   ├── explainer.py
│   ├── feature_extractor.py
│   ├── feature_generator.py
│   ├── flow_builder.py
│   ├── monitor.py
│   ├── packet_capture.py
│   ├── predictor.py
│   ├── test_wsl_capture.py
│   ├── train_models.py
│   ├── training.py
│   └── virtual_network.py
│
├── frontend/
│   ├── public/
│   ├── src/
│   │   ├── components/
│   │   ├── hooks/
│   │   ├── pages/
│   │   ├── services/
│   │   ├── App.jsx
│   │   ├── constants.js
│   │   ├── main.jsx
│   │   └── styles.css
│   ├── index.html
│   ├── package.json
│   └── vite.config.js
│
├── models/
│   ├── best_model.pkl
│   ├── label_encoder.pkl
│   └── model_comparison.csv
│
├── notebooks/
│   ├── clean_dataset.py
│   ├── preprocess.py
│   ├── train_model.py
│   ├── 04_train_model.py
│   └── 05_feature_selection.py
│
├── requirements.txt
├── README.md
└── .gitignore
```

---

## API Reference

The backend is built with **FastAPI**, which auto-generates interactive documentation.

| Resource | URL |
|---|---|
| Swagger UI | http://127.0.0.1:8000/docs |
| Health check | http://127.0.0.1:8000/health |

```text
React Frontend ⇄ FastAPI ⇄ AI Model
                         ⇄ Database
                              │
                              ▼
                       Packet Capture
```

<!-- PLACEHOLDER: List key REST endpoints (method, path, description, example request/response) here once finalized -->

---

## Troubleshooting / Getting Help

<details>
<summary><strong>Port 8000 is already in use</strong></summary>

```powershell
netstat -ano | findstr :8000
tasklist /FI "PID eq <PID>"
taskkill /F /PID <PID>
```

Then restart the backend. Only one backend instance should run on port 8000 at a time.

</details>

<details>
<summary><strong>Live capture does not start</strong></summary>

Check that:
- Npcap is installed
- The backend is running
- PowerShell has Administrator privileges (if required)
- Only one backend instance is running
- A valid network interface is active
- WSL/Hyper-V networking is active (for the Kali demonstration)

Verify the API is reachable:

```bash
curl.exe http://127.0.0.1:8000/health
```

</details>

<details>
<summary><strong>Packets are not appearing on the dashboard</strong></summary>

1. Test connectivity from Kali: `ping 172.29.0.1`
2. Check the dashboard's packet counter
3. For the Kali/WSL demo, confirm the WSL/Hyper-V network is active — the app attempts to auto-resolve the correct interface

</details>

<details>
<summary><strong>Frontend cannot connect to the backend</strong></summary>

1. Confirm the backend is reachable at http://127.0.0.1:8000 and http://127.0.0.1:8000/docs
2. If the backend responds but the frontend doesn't, check `frontend/src/services/api.js` and confirm it points to the correct backend host/port

</details>

<!-- PLACEHOLDER: Add an FAQ entry here for any other common issues reported via GitHub Issues -->

If your issue isn't listed above, please open a [GitHub Issue](https://github.com/Adithya3001/AI-Network-Threat-Detection-System/issues) with logs, your OS/Python/Node versions, and steps to reproduce.

---

## Contributing

Contributions are welcome! To propose a change:

1. Fork the repository and create a feature branch (`git checkout -b feature/my-feature`)
2. Make your changes, following the existing code style
3. Add or update tests where applicable
4. Commit with a clear message and push to your fork
5. Open a Pull Request against `main`, describing the change and its motivation

<!-- PLACEHOLDER: Add CONTRIBUTING.md and CODE_OF_CONDUCT.md, then link them here, e.g.:
Please read [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines and our
[Code of Conduct](CODE_OF_CONDUCT.md) before submitting a pull request. -->

---

## Future Improvements

- Deep-learning-based intrusion detection
- Improved anomaly detection and zero-day attack detection
- Automated threat response
- Threat-intelligence integration
- Distributed packet-capture sensors
- Cloud-based monitoring
- Role-based authentication
- Advanced explainable AI
- Automated model retraining
- Additional network protocol support
- Network-wide sensor deployment

---

## Security and Responsible Use

This project is intended for **educational use, research, network security learning, authorized security testing, and controlled laboratory demonstrations only**.

Live packet capture and network scanning must only be performed on systems and networks you **own** or are **explicitly authorized** to test. The Kali Linux examples in this README are designed for a controlled, local WSL/Hyper-V lab environment.

If you discover a security vulnerability in this project itself, please report it privately rather than opening a public issue.
<!-- PLACEHOLDER: Add a SECURITY.md and/or a dedicated security-contact email address -->

---

## License

This project is intended primarily for educational, research, and authorized security-testing purposes. Users are responsible for ensuring their use of network monitoring and security-testing functionality complies with applicable laws, regulations, and organizational policies.

<!-- PLACEHOLDER: No license was specified in the original draft. Add a LICENSE file (e.g., MIT, Apache 2.0)
and replace this section with the standard notice and a link, e.g.:
This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details. -->

---

## Acknowledgments

- **Dataset:** [CICIDS2017](https://www.unb.ca/cic/datasets/ids-2017.html), provided by the Canadian Institute for Cybersecurity, University of New Brunswick
- Built with [Scapy](https://scapy.net/), [Npcap](https://npcap.com/), [XGBoost](https://xgboost.readthedocs.io/), [FastAPI](https://fastapi.tiangolo.com/), and [React](https://react.dev/) + [Vite](https://vitejs.dev/)

<!-- PLACEHOLDER: Credit any tutorials, papers, or collaborators that informed the project -->

---

## Contact / Support

**Author:** Adithya
**Repository:** https://github.com/Adithya3001/AI-Network-Threat-Detection-System

For bugs or feature requests, please [open an issue](https://github.com/Adithya3001/AI-Network-Threat-Detection-System/issues).

<!-- PLACEHOLDER: Add an email address, Discord/Slack invite, or other preferred support channel -->
