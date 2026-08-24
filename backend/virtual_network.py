"""
Virtual Network Simulator.

Emulates a real LAN of virtual hosts (servers, workstations, a gateway)
plus external internet hosts and attackers. Each host is a distinct
"virtual computer" that runs traffic-generating applications. Normal
applications emit real Scapy packets through the actual detection
pipeline; attacker applications replay real CICIDS2017 attack flows so
the XGBoost model produces authentic attack predictions.

The topology of these hosts is surfaced in the dashboard so you can see
distinct virtual machines communicating over your "network".
"""
import random
import threading
import time
from datetime import datetime

from scapy.all import IP, TCP, UDP, Raw

from database import insert_prediction
from monitor import capture_status, log_event, record_packet, set_ai_decision, update_capture_status
from packet_capture import analyze_and_store, extract_packet_info, ensure_flow_predictor_running
from predictor import model

BASE_DIR = __import__("os").path.dirname(__file__)
DATA_PATH = __import__("os").path.join(BASE_DIR, "..", "dataset", "cleaned_dataset.csv")
MODEL_FEATURES = list(model.feature_names_in_)

# ------------------------------------------------------------------
# Virtual hosts
# ------------------------------------------------------------------

class VirtualHost:
    def __init__(self, name, ip, mac, role, os_name):
        self.name = name
        self.ip = ip
        self.mac = mac
        self.role = role
        self.os = os_name

    def to_dict(self):
        return {
            "name": self.name,
            "ip": self.ip,
            "mac": self.mac,
            "role": self.role,
            "os": self.os,
        }


LAN_HOSTS = [
    VirtualHost("Web Server", "192.168.1.5", "00:0c:29:aa:00:01", "server", "Linux / Nginx"),
    VirtualHost("File Server", "192.168.1.6", "00:0c:29:aa:00:02", "server", "Windows / SMB"),
    VirtualHost("Mail Server", "192.168.1.7", "00:0c:29:aa:00:03", "server", "Linux / Postfix"),
    VirtualHost("Database", "192.168.1.8", "00:0c:29:aa:00:04", "server", "Linux / MySQL"),
    VirtualHost("Workstation-1", "192.168.1.20", "00:0c:29:bb:00:01", "client", "Windows 11"),
    VirtualHost("Workstation-2", "192.168.1.21", "00:0c:29:bb:00:02", "client", "Windows 11"),
    VirtualHost("Workstation-3", "192.168.1.22", "00:0c:29:bb:00:03", "client", "Ubuntu 24"),
]

EXTERNAL_HOSTS = {
    "public-dns": "8.8.8.8",
    "public-web": "203.0.113.7",
    "public-cdn": "93.184.216.34",
}

ATTACKERS = [
    VirtualHost("Attacker-Botnet-1", "185.220.101.45", "00:16:3e:00:00:11", "attacker", "Unknown"),
    VirtualHost("Attacker-Botnet-2", "103.86.99.55", "00:16:3e:00:00:22", "attacker", "Unknown"),
    VirtualHost("Attacker-Botnet-3", "91.121.65.170", "00:16:3e:00:00:33", "attacker", "Unknown"),
]

GATEWAY = VirtualHost("Gateway/Router", "192.168.1.1", "00:0c:29:cc:00:01", "gateway", "RouterOS")

_vnet_thread = None
_stop_flag = threading.Event()
_hosts_registered = False

# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _rand_payload(size):
    return bytes(random.getrandbits(8) for _ in range(size))


def _build_pkt(src, dst, sport, dport, proto, flags, size=64):
    if proto == "UDP":
        pkt = IP(src=src, dst=dst) / UDP(sport=sport, dport=dport)
    else:
        pkt = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags)
    return pkt / Raw(_rand_payload(max(1, size - 40)))


def _run_session(src, dst, sport, dport, proto, size, packets):
    """Emit a realistic packet burst (handshake + data + teardown) through the pipeline."""
    src_p, dst_p = sport, dport
    if proto == "UDP":
        for _ in range(packets):
            pkt = _build_pkt(src, dst, src_p, dst_p, "UDP", "", size)
            _process(pkt)
            time.sleep(random.uniform(0.01, 0.05))
        return

    for _ in range(packets):
        step = random.random()
        if step < 0.12:
            flags, d, s = "S", size // 2, src_p
        elif step < 0.2:
            flags, d, s = "SA", size // 2, dst_p
        elif step < 0.3:
            flags, d, s = "A", size // 3, src_p
        elif step < 0.85:
            flags, d, s = "PA", size, src_p if random.random() < 0.7 else dst_p
        else:
            flags, d, s = "FA", size // 3, src_p if random.random() < 0.6 else dst_p

        if s == src_p:
            pkt = _build_pkt(src, dst, src_p, dst_p, "TCP", flags, d)
        else:
            pkt = _build_pkt(dst, src, dst_p, src_p, "TCP", flags, d)
        _process(pkt)
        time.sleep(random.uniform(0.008, 0.03))


def _process(pkt):
    if _stop_flag.is_set():
        return
    info = extract_packet_info(pkt)
    if not info:
        return
    from flow_builder import get_flow
    flow = get_flow(
        pkt, info["src_ip"], info["dst_ip"],
        info["src_port"], info["dst_port"], info["proto_num"],
    )
    analyze_and_store(info, pkt, flow)
    capture_status["packets_seen"] += 1


def _replay_attack(attacker, victim_ip, attack_label):
    """Replay a real CICIDS2017 flow as this attacker's traffic."""
    if not __import__("os").path.exists(DATA_PATH):
        return

    import pandas as pd
    from alerts import get_severity
    from predictor import predict

    from predictor import label_encoder
    known = {c.lower(): c for c in label_encoder.classes_}
    lookup = {c.lower(): c for c in known}

    cols = MODEL_FEATURES + ["Label"]
    for chunk in pd.read_csv(DATA_PATH, usecols=cols, chunksize=100000):
        chunk["Label"] = chunk["Label"].astype(str).str.replace("\ufffd", "-").str.strip().str.lower()
        chunk = chunk[chunk["Label"] == attack_label.lower()]
        if len(chunk):
            vec = chunk.sample(1).iloc[0].to_dict()
            break
    else:
        return

    features = {k: vec[k] for k in MODEL_FEATURES}
    try:
        prediction, confidence = predict(features)
    except Exception as e:
        log_event("VNet", f"Attack replay failed: {e}", "error")
        return

    sport = random.randint(1024, 65535)
    dst_port = int(features.get("Destination Port", 80))
    proto = "TCP" if dst_port in (21, 22, 80, 443, 8080, 6667, 6668) else "UDP"

    threat_id = insert_prediction(
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        attacker.ip, victim_ip,
        sport, dst_port, proto,
        prediction, float(confidence),
        packet_size=40, tcp_flags="S",
        severity=get_severity(prediction),
        bytes_total=int(features.get("Total Length of Fwd Packets", 0) + features.get("Total Length of Bwd Packets", 0)),
    )
    from database import insert_flow_features
    insert_flow_features(threat_id, prediction, features)

    record_packet(proto, prediction, 40, {}, attacker.ip, victim_ip, sport, dst_port, "S")

    if prediction == "BENIGN":
        log_event("VNet", f"{attacker.name} → {victim_ip}: benign flow", f"{confidence * 100:.1f}%")
    else:
        log_event(
            "VNet",
            f"{attacker.name} {prediction} → {victim_ip}",
            f"{confidence * 100:.1f}% · {get_severity(prediction)}",
        )

    from monitor import set_ai_decision
    from explainer import explain
    res = explain(prediction, confidence, features)
    res["timestamp"] = time.strftime("%H:%M:%S")
    res["prediction"] = prediction
    set_ai_decision(**res)

    # A burst of real packets so the inspector + flows feel real too
    for _ in range(random.randint(8, 20)):
        _process(_build_pkt(attacker.ip, victim_ip, sport, dst_port, proto, "S", random.randint(40, 120)))


# ------------------------------------------------------------------
# Session director
# ------------------------------------------------------------------

BENIGN_SESSIONS = [
    ("Workstation-1", "public-web", "web browse", 443, 80, "TCP"),
    ("Workstation-1", "public-dns", "dns query", 53, 53, "UDP"),
    ("Workstation-2", "Web Server", "web browse", 443, 80, "TCP"),
    ("Workstation-2", "File Server", "smb transfer", 445, 445, "TCP"),
    ("Workstation-3", "Database", "sql query", 3306, 3306, "TCP"),
    ("Workstation-3", "Mail Server", "smtp", 587, 587, "TCP"),
    ("Workstation-1", "File Server", "backup sync", 445, 445, "TCP"),
    ("Workstation-2", "public-cdn", "streaming", 443, 443, "TCP"),
]

ATTACK_SESSIONS = [
    ("Attacker-Botnet-1", "Workstation-1", "PortScan"),
    ("Attacker-Botnet-1", "Workstation-2", "PortScan"),
    ("Attacker-Botnet-2", "File Server", "FTP-Patator"),
    ("Attacker-Botnet-2", "Web Server", "SSH-Patator"),
    ("Attacker-Botnet-3", "Web Server", "DoS Hulk"),
    ("Attacker-Botnet-3", "Database", "DoS Slowhttptest"),
    ("Attacker-Botnet-1", "Workstation-3", "Bot"),
]

_attack_bank = None


def _load_attack_labels():
    global _attack_bank
    if _attack_bank:
        return _attack_bank
    import pandas as pd
    if not __import__("os").path.exists(DATA_PATH):
        return []
    from predictor import label_encoder
    known = {c.lower(): c for c in label_encoder.classes_}
    labels = set()
    for chunk in pd.read_csv(DATA_PATH, usecols=["Label"], chunksize=200000):
        for label in chunk["Label"].astype(str).str.replace("\ufffd", "-").str.strip().str.lower().unique():
            if label in known and label != "benign":
                labels.add(known[label])
        if len(labels) >= 12:
            break
    _attack_bank = sorted(labels)
    return _attack_bank


def _host(name):
    for h in LAN_HOSTS + ATTACKERS + [GATEWAY]:
        if h.name == name:
            return h
    return None


def _run_vnet():
    global _hosts_registered
    update_capture_status(
        running=True,
        mode="vnet",
        started_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        error=None,
    )
    _hosts_registered = True

    log_event("VNet", "Virtual network online - 7 LAN hosts + 3 attackers", "emulated")
    log_event("VNet", f"Hosts: {', '.join(h.name for h in LAN_HOSTS)}", "topology")

    attack_labels = _load_attack_labels()

    benign_weights = [0.65] * len(BENIGN_SESSIONS)
    attack_weights = [0.55] * len(ATTACK_SESSIONS)

    last_attack_time = 0

    while not _stop_flag.is_set():
        tick = time.time()

        # Run a normal session most of the time
        if random.random() < 0.62 or (tick - last_attack_time < 2):
            s = random.choices(BENIGN_SESSIONS, weights=benign_weights, k=1)[0]
            src, dst, name, sport, dport, proto = s
            src_h, dst_h = _host(src), _host(dst)
            if not src_h or not dst_h:
                time.sleep(0.2)
                continue
            log_event(
                "VNet",
                f"{src_h.name} ({src_h.ip}) → {dst_h.name} ({dst_h.ip}) · {name}",
                f"port {dport}/{proto}",
            )
            _run_session(
                src_h.ip, dst_h.ip,
                random.randint(1024, 65535), dport, proto,
                random.choice([64, 128, 256, 512, 1024]),
                random.randint(6, 24),
            )
            time.sleep(random.uniform(0.2, 0.6))
        else:
            # Attack session
            s = random.choices(ATTACK_SESSIONS, weights=attack_weights, k=1)[0]
            attacker_name, victim_name, attack_label = s
            attacker = _host(attacker_name)
            victim = _host(victim_name)
            if not attacker or not victim:
                time.sleep(0.2)
                continue

            if attack_labels and attack_label in attack_labels:
                _replay_attack(attacker, victim.ip, attack_label)
                last_attack_time = time.time()
            else:
                # fall back to generated packets through the model
                log_event("VNet", f"{attacker.name} probing {victim.name}", "attack simulation")
                _run_session(
                    attacker.ip, victim.ip,
                    random.randint(1024, 65535),
                    random.choice([21, 22, 80, 443, 23, 3389]),
                    "TCP", 60, random.randint(30, 90),
                )
                last_attack_time = time.time()
            time.sleep(random.uniform(0.5, 1.2))

    update_capture_status(
        running=False,
        mode="idle",
    )
    log_event("VNet", "Virtual network stopped", "idle")


def get_virtual_hosts():
    return [h.to_dict() for h in LAN_HOSTS + [GATEWAY] + ATTACKERS]


def start_vnet():
    global _vnet_thread, _stop_flag
    if capture_status["running"] and capture_status["mode"] == "vnet":
        return {"status": "already_running", "mode": "vnet"}

    if _vnet_thread is not None and _vnet_thread.is_alive():
        return {"status": "already_running", "mode": "vnet"}

    _stop_flag = threading.Event()
    _vnet_thread = threading.Thread(target=_run_vnet, daemon=True, name="vnet")
    _vnet_thread.start()
    ensure_flow_predictor_running()
    return {"status": "started", "mode": "vnet"}


def stop_vnet():
    if capture_status["running"]:
        _stop_flag.set()
    return {"status": "stopping", "running": capture_status["running"]}
