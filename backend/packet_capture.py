import threading
import time
from datetime import datetime
from collections import defaultdict, deque

from scapy.all import IP, IPv6, TCP, UDP, ICMP, sniff, conf, get_if_list

from alerts import get_severity
from database import (
    initialize_database,
    insert_predictions_batch,
    insert_flow_features_batch,
)
from feature_generator import generate_features
from flow_builder import get_flow, prune_stale_flows
from monitor import (
    capture_status,
    log_event,
    record_packet,
    set_ai_decision,
    update_capture_status,
)
from predictor import predict


# ===============================================================
# SETTINGS
# ===============================================================

# Packet-level debug output is OFF by default - do not print every
# packet to the console during normal operation.
DEBUG = False

# The WSL/Hyper-V gateway address. The Kali demo box routes to the
# Windows host through this IP, so the adapter that owns it is the
# one that can actually see Kali's traffic.
WSL_GATEWAY_IP = "172.29.0.1"

# Private 172.16/12 prefixes that indicate a NAT/virtual (WSL/Hyper-V)
# adapter rather than a physical LAN/Wi-Fi adapter.
WSL_NET_PREFIXES = (
    "172.16.",
    "172.17.",
    "172.18.",
    "172.19.",
    "172.20.",
    "172.21.",
    "172.22.",
    "172.23.",
    "172.24.",
    "172.25.",
    "172.26.",
    "172.27.",
    "172.28.",
    "172.29.",
    "172.30.",
    "172.31.",
)

# Live PortScan detection
PORTSCAN_WINDOW = 10
PORTSCAN_THRESHOLD = 20
PORTSCAN_ACTIVE_TIME = 5
PORTSCAN_ALERT_COOLDOWN = 10

# Flow-based prediction batching
FLOW_PREDICT_INTERVAL = 2.0
FLOW_STALE_AFTER = 120.0


# ===============================================================
# GLOBAL STATE
# ===============================================================

last_predictions = {}

_capture_thread = None
_stop_flag = threading.Event()

# PortScan tracking
portscan_tracker = defaultdict(deque)
portscan_last_alert = {}
portscan_last_seen = {}
portscan_features = {}

# Flows queued for batched AI prediction
_pending_flows = set()
_pending_lock = threading.Lock()

_flow_predictor_thread = None
_flow_predictor_stop = threading.Event()
_flow_predictor_guard = threading.Lock()


# ===============================================================
# PACKET INFORMATION
# ===============================================================

def extract_packet_info(packet):

    src_ip = None
    dst_ip = None

    src_port = 0
    dst_port = 0

    proto_num = 0
    proto_name = "OTHER"

    tcp_flags = ""

    # -----------------------------------------------------------
    # IPv4
    # -----------------------------------------------------------

    if IP in packet:

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        proto_num = packet[IP].proto

    # -----------------------------------------------------------
    # IPv6
    # -----------------------------------------------------------

    elif IPv6 in packet:

        src_ip = packet[IPv6].src
        dst_ip = packet[IPv6].dst

        proto_num = packet[IPv6].nh

    else:

        return None

    # -----------------------------------------------------------
    # TCP
    # -----------------------------------------------------------

    if TCP in packet:

        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

        proto_name = "TCP"

        tcp_flags = str(
            packet[TCP].flags
        )

    # -----------------------------------------------------------
    # UDP
    # -----------------------------------------------------------

    elif UDP in packet:

        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

        proto_name = "UDP"

    # -----------------------------------------------------------
    # ICMP
    # -----------------------------------------------------------

    elif ICMP in packet:

        proto_name = "ICMP"

    return {

        "src_ip":
            src_ip,

        "dst_ip":
            dst_ip,

        "src_port":
            src_port,

        "dst_port":
            dst_port,

        "proto_num":
            proto_num,

        "proto_name":
            proto_name,

        "tcp_flags":
            tcp_flags,
    }


# ===============================================================
# LIVE PORTSCAN DETECTION
# ===============================================================

def detect_live_portscan(info):

    # Only TCP
    if info["proto_name"] != "TCP":

        return False, 0

    # Only SYN packets
    if info["tcp_flags"] != "S":

        return False, 0

    source_ip = info["src_ip"]

    destination_ip = info["dst_ip"]

    destination_port = info["dst_port"]

    now = time.time()

    key = (
        source_ip,
        destination_ip
    )

    # -----------------------------------------------------------
    # Store SYN + destination port
    # -----------------------------------------------------------

    portscan_tracker[key].append(
        (
            now,
            destination_port
        )
    )

    # -----------------------------------------------------------
    # Remove old entries
    # -----------------------------------------------------------

    while portscan_tracker[key]:

        timestamp, port = (
            portscan_tracker[key][0]
        )

        if (
            now - timestamp
            <= PORTSCAN_WINDOW
        ):

            break

        portscan_tracker[key].popleft()

    # -----------------------------------------------------------
    # Count unique destination ports
    # -----------------------------------------------------------

    unique_ports = {

        port

        for timestamp, port
        in portscan_tracker[key]

    }

    port_count = len(
        unique_ports
    )

    # -----------------------------------------------------------
    # PortScan threshold
    # -----------------------------------------------------------

    if port_count >= PORTSCAN_THRESHOLD:

        # Mark PortScan as currently active
        portscan_last_seen[key] = now

        return True, port_count

    return False, port_count


def scanned_port_count(src_ip, dst_ip):
    """Return the number of unique destination ports tracked for a
    source/destination pair, or 0 if no scan has been observed."""
    key = (src_ip, dst_ip)
    seen = portscan_tracker.get(key)
    if not seen:
        return 0
    return len({port for _ts, port in seen})


# ===============================================================
# CHECK WHETHER PORTSCAN IS STILL ACTIVE
# ===============================================================

def is_portscan_active(
    src_ip,
    dst_ip
):

    key = (
        src_ip,
        dst_ip
    )

    last_seen = portscan_last_seen.get(
        key,
        0
    )

    return (
        time.time() - last_seen
        <= PORTSCAN_ACTIVE_TIME
    )


# ===============================================================
# UPDATE AI DECISION PANEL
# ===============================================================

def update_ai_decision(
    attack,
    confidence,
    features,
    flow
):
    """
    Always show the latest prediction (BENIGN, PortScan, or any
    XGBoost class). Thread-safe via monitor.set_ai_decision().
    """

    set_ai_decision(
        prediction=attack,
        confidence=float(confidence),
        features=features,
        flow={
            key: value
            for key, value
            in flow.items()
            if not isinstance(value, list)
        },
        timestamp=time.strftime(
            "%H:%M:%S"
        ),
    )


# ===============================================================
# DATABASE ALERT (single row - used for immediate PortScan alerts)
# ===============================================================

def store_prediction_row(
    flow_key,
    attack,
    confidence,
    features,
    flow,
    packet_size=0,
    tcp_flags="",
    scanned_ports=0
):

    src_ip, dst_ip, src_port, dst_port, protocol = flow_key

    severity = get_severity(
        attack
    )

    prediction_changed = (

        flow_key not in last_predictions

        or

        last_predictions[
            flow_key
        ] != attack
    )

    # -----------------------------------------------------------
    # Prevent repeated PortScan DB entries
    # -----------------------------------------------------------

    if attack == "PortScan":

        portscan_key = (
            src_ip,
            dst_ip
        )

        now = time.time()

        previous = portscan_last_alert.get(
            portscan_key,
            0
        )

        if (
            now - previous
            < PORTSCAN_ALERT_COOLDOWN
        ):

            prediction_changed = False

        else:

            prediction_changed = True

            portscan_last_alert[
                portscan_key
            ] = now

    if not prediction_changed:

        return None

    # -----------------------------------------------------------
    # Insert prediction + features
    # -----------------------------------------------------------

    threat_id = insert_prediction_single(
        datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        ),
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol,
        attack,
        float(confidence),
        packet_size=packet_size,
        tcp_flags=tcp_flags,
        severity=severity,
        bytes_total=int(
            flow.get("fwd_bytes", 0)
            + flow.get("bwd_bytes", 0)
        ),
        features=features,
        scanned_ports=scanned_ports,
    )

    last_predictions[
        flow_key
    ] = attack

    return threat_id


def insert_prediction_single(
    timestamp,
    src_ip,
    dst_ip,
    src_port,
    dst_port,
    protocol,
    attack,
    confidence,
    packet_size=0,
    tcp_flags="",
    severity="None",
    bytes_total=0,
    features=None,
    scanned_ports=0
):

    from database import (
        insert_prediction,
        insert_flow_features,
    )

    threat_id = insert_prediction(
        timestamp,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol,
        attack,
        confidence,
        packet_size=packet_size,
        tcp_flags=tcp_flags,
        severity=severity,
        bytes_total=bytes_total,
        scanned_ports=scanned_ports,
    )

    if features:
        try:
            insert_flow_features(
                threat_id,
                attack,
                features
            )
        except Exception as e:
            if DEBUG:
                print(
                    "Feature store error:",
                    e
                )

    return threat_id


def log_prediction(
    attack,
    protocol,
    src_ip,
    src_port,
    dst_ip,
    dst_port,
    confidence,
    severity,
    scanned_ports=0
):

    if attack == "BENIGN":

        log_event(

            "AI Prediction",

            (
                f"BENIGN · "
                f"{protocol} "
                f"{src_ip}:"
                f"{src_port} → "
                f"{dst_ip}:"
                f"{dst_port}"
            ),

            f"{confidence * 100:.2f}%"
        )

        return

    # -----------------------------------------------------------
    # Attack event
    # -----------------------------------------------------------

    log_event(

        "AI Prediction",

        (
            f"{attack} · "
            f"{src_ip}:"
            f"{src_port} → "
            f"{dst_ip}:"
            f"{dst_port}"
        ),

        (
            f"{confidence * 100:.2f}% · "
            f"severity {severity}"
        )
    )

    _safe_print()

    _safe_print(
        "========================================"
    )

    _safe_print(
        "          THREAT DETECTED"
    )

    _safe_print(
        "========================================"
    )

    _safe_print(
        f"Attack      : {attack}"
    )

    _safe_print(
        f"Confidence  : "
        f"{confidence * 100:.2f}%"
    )

    _safe_print(
        f"Severity    : {severity}"
    )

    _safe_print(
        f"Source      : "
        f"{src_ip}:{src_port}"
    )

    _safe_print(
        f"Destination : "
        f"{dst_ip}:{dst_port}"
    )

    _safe_print(
        f"Protocol    : {protocol}"
    )

    if attack == "PortScan" and scanned_ports:

        _safe_print(
            f"Ports Scanned: {scanned_ports}"
        )

    _safe_print(
        "========================================"
    )

    _safe_print()


def _safe_print(*args, **kwargs):
    """Print without crashing when the console cannot encode the text
    (e.g. Windows cp1252 terminal vs. emoji/special characters)."""
    try:
        print(*args, **kwargs)
    except Exception:
        try:
            text = " ".join(str(a) for a in args)
            print(text.encode("ascii", "replace").decode("ascii"))
        except Exception:
            pass


# ===============================================================
# ANALYZE PACKET (lightweight hot path)
# ===============================================================

def analyze_and_store(
    info,
    packet,
    flow
):
    """
    Lightweight per-packet path.

    - PortScan detection stays per-packet (cheap) and raises an
      alert immediately.
    - Every other packet is only counted in the live dashboard and
      queued for batched AI prediction on the background flow
      predictor thread. The expensive XGBoost prediction + feature
      generation no longer run on the packet-capture thread.
    """

    flow_key = flow.get(
        "flow_key"
    ) or (
        info["src_ip"],
        info["dst_ip"],
        info["src_port"],
        info["dst_port"],
        info["proto_name"],
    )

    is_portscan, scanned_ports = (
        detect_live_portscan(
            info
        )
    )

    # -----------------------------------------------------------
    # Provisional classification for the live counters
    # (refined by the flow predictor a moment later)
    # -----------------------------------------------------------

    if is_portscan or is_portscan_active(
        info["src_ip"],
        info["dst_ip"]
    ):

        attack = "PortScan"

    else:

        attack = last_predictions.get(
            flow_key,
            "BENIGN"
        )

    # -----------------------------------------------------------
    # Live monitoring (traffic counters + active connections)
    # -----------------------------------------------------------

    record_packet(

        info["proto_name"],

        attack,

        len(packet),

        flow,

        info["src_ip"],

        info["dst_ip"],

        info["src_port"],

        info["dst_port"],

        info["tcp_flags"],
    )

    # ===========================================================
    # PORTSCAN - immediate handling
    # ===========================================================

    if is_portscan:

        portscan_key = (
            info["src_ip"],
            info["dst_ip"]
        )

        now = time.time()

        # Reuse cached features for repeated SYN packets during an
        # active scan so we do not rebuild the 78-feature vector
        # for every single packet.
        features = portscan_features.get(
            portscan_key,
            {}
        )

        fresh_alert = (
            now - portscan_last_alert.get(
                portscan_key,
                0
            )
            >= PORTSCAN_ALERT_COOLDOWN
        )

        if fresh_alert or not features:

            features = generate_features(
                flow
            )

            portscan_features[
                portscan_key
            ] = features

        if fresh_alert:

            store_prediction_row(
                flow_key,
                "PortScan",
                0.99,
                features,
                flow,
                packet_size=len(packet),
                tcp_flags=info["tcp_flags"],
                scanned_ports=scanned_ports,
            )

            log_prediction(
                "PortScan",
                info["proto_name"],
                info["src_ip"],
                info["src_port"],
                info["dst_ip"],
                info["dst_port"],
                0.99,
                get_severity("PortScan"),
                scanned_ports,
            )

        update_ai_decision(
            "PortScan",
            0.99,
            features,
            flow
        )

        return

    # ===========================================================
    # NORMAL TRAFFIC - queue for batched prediction
    # ===========================================================

    mark_flow_pending(
        flow_key
    )


# ===============================================================
# PROCESS PACKET
# ===============================================================

def process_packet(packet):

    info = extract_packet_info(
        packet
    )

    if not info:

        return

    # ===========================================================
    # ICMP
    # ===========================================================

    if info["proto_name"] == "ICMP":

        size = len(packet)

        flow = {

            "fwd_bytes":
                size,

            "bwd_bytes":
                0,
        }

        record_packet(

            "ICMP",

            "BENIGN",

            size,

            flow,

            info["src_ip"],

            info["dst_ip"],

            0,

            0,

            ""
        )

        # ICMP is normal live traffic, so update AI panel to BENIGN
        set_ai_decision(
            prediction="BENIGN",
            confidence=1.0,
            features={},
            flow=flow,
            timestamp=time.strftime(
                "%H:%M:%S"
            ),
        )

        return

    # ===========================================================
    # TCP / UDP
    # ===========================================================

    if info["proto_name"] not in (
        "TCP",
        "UDP"
    ):

        return

    # -----------------------------------------------------------
    # Build flow
    # -----------------------------------------------------------

    flow = get_flow(

        packet,

        info["src_ip"],

        info["dst_ip"],

        info["src_port"],

        info["dst_port"],

        info["proto_num"],
    )

    # -----------------------------------------------------------
    # Analyze (lightweight)
    # -----------------------------------------------------------

    analyze_and_store(

        info,

        packet,

        flow
    )


# ===============================================================
# FLOW PREDICTOR (background batched AI analysis)
# ===============================================================

_PROTO_NAMES = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    47: "GRE",
    50: "ESP",
    51: "AH",
}

def mark_flow_pending(flow_key):

    with _pending_lock:

        _pending_flows.add(flow_key)


def ensure_flow_predictor_running():

    global _flow_predictor_thread

    with _flow_predictor_guard:

        if (
            _flow_predictor_thread is None
            or not _flow_predictor_thread.is_alive()
        ):

            _flow_predictor_stop.clear()

            _flow_predictor_thread = threading.Thread(
                target=_flow_predictor_loop,
                daemon=True,
                name="flow-predictor",
            )

            _flow_predictor_thread.start()


def _flow_predictor_loop():

    # Event.wait(timeout) returns True only when the stop event fires.
    while not _flow_predictor_stop.wait(
        FLOW_PREDICT_INTERVAL
    ):

        try:

            _process_pending_flows()

        except Exception as e:

            if DEBUG:

                print(
                    "Flow predictor error:",
                    e
                )


def _avg_packet_size(flow):

    lengths = flow.get(
        "all_lengths"
    ) or []

    if not lengths:

        return 0

    try:

        return int(
            sum(lengths) / len(lengths)
        )

    except Exception:

        return 0


def _process_pending_flows():

    # Re-queue flows whose PortScan state just expired so their
    # verdict can return to the model's prediction (BENIGN).
    _requeue_expired_portscans()

    with _pending_lock:

        pending = list(
            _pending_flows
        )

        _pending_flows.clear()

    prune_stale_flows(
        FLOW_STALE_AFTER
    )

    if not pending:

        _prune_aging_state()

        return

    from flow_builder import flows, flow_lock

    # -----------------------------------------------------------
    # Snapshot the flows we need to predict
    # -----------------------------------------------------------

    with flow_lock:

        snapshot = {}

        for key in pending:

            flow = flows.get(key)

            if flow is not None:

                snapshot[key] = flow

    results = []
    records = []

    for key, flow in snapshot.items():

        src_ip, dst_ip, src_port, dst_port, protocol = key

        protocol = _PROTO_NAMES.get(
            protocol,
            str(protocol),
        )

        # -------------------------------------------------------
        # Generate features
        # -------------------------------------------------------

        try:

            features = generate_features(
                flow
            )

        except Exception:

            continue

        # -------------------------------------------------------
        # Predict (force PortScan while a scan is active)
        # -------------------------------------------------------

        try:

            if is_portscan_active(
                src_ip,
                dst_ip
            ):

                attack, confidence = "PortScan", 0.99

            else:

                attack, confidence = predict(
                    features
                )

        except Exception as e:

            log_event(

                "AI Prediction",

                f"Prediction failed: {e}",

                "error"
            )

            if DEBUG:

                print(
                    "Prediction error:",
                    e
                )

            continue

        # -------------------------------------------------------
        # Only write to the database when the prediction changes
        # -------------------------------------------------------

        if last_predictions.get(
            key
        ) != attack:

            last_predictions[
                key
            ] = attack

            records.append({
                "timestamp":
                    datetime.now().strftime(
                        "%Y-%m-%d %H:%M:%S"
                    ),
                "src_ip":
                    src_ip,
                "dst_ip":
                    dst_ip,
                "src_port":
                    src_port,
                "dst_port":
                    dst_port,
                "protocol":
                    protocol,
                "attack":
                    attack,
                "confidence":
                    float(confidence),
                "packet_size":
                    _avg_packet_size(flow),
                "tcp_flags":
                    flow.get(
                        "tcp_flags",
                        ""
                    ),
                "severity":
                    get_severity(attack),
                "bytes_total":
                    int(
                        flow.get("fwd_bytes", 0)
                        + flow.get("bwd_bytes", 0)
                    ),
                "scanned_ports":
                    scanned_port_count(src_ip, dst_ip)
                    if attack == "PortScan"
                    else 0,
                "features":
                    features,
            })

        results.append(
            (key, attack, confidence, features, flow)
        )

    # -----------------------------------------------------------
    # Batch database write (one transaction for the whole cycle)
    # -----------------------------------------------------------

    if records:

        try:

            ids = insert_predictions_batch(
                records
            )

            insert_flow_features_batch([

                (
                    tid,
                    rec["attack"],
                    rec["features"],
                )

                for tid, rec
                in zip(ids, records)

            ])

        except Exception as e:

            if DEBUG:

                print(
                    "Batch store error:",
                    e
                )

        for rec in records:

            log_prediction(

                rec["attack"],

                rec["protocol"],

                rec["src_ip"],

                rec["src_port"],

                rec["dst_ip"],

                rec["dst_port"],

                rec["confidence"],

                rec["severity"],
            )

    # -----------------------------------------------------------
    # Refresh the AI Decision Engine
    # -----------------------------------------------------------

    _finalize_ai_decision(
        results
    )

    _prune_aging_state()


def _finalize_ai_decision(results):
    """
    Show the most meaningful prediction from this cycle:
    - PortScan if any processed flow is still under an active scan
    - otherwise the most recently-seen attack, or the most
      recently-seen flow prediction if everything is benign.
    """

    if not results:

        return

    for key, attack, confidence, features, flow in results:

        if is_portscan_active(
            key[0],
            key[1]
        ):

            update_ai_decision(
                "PortScan",
                0.99,
                features,
                flow
            )

            return

    attacks = [
        r for r in results
        if r[1] != "BENIGN"
    ]

    pool = attacks if attacks else results

    best = max(
        pool,
        key=lambda r: r[4].get(
            "last_seen",
            0
        ),
    )

    update_ai_decision(
        best[1],
        best[2],
        best[3],
        best[4],
    )


def _requeue_expired_portscans(limit=100):
    """Flows labelled PortScan whose scan is no longer active are
    re-queued so the next prediction cycle returns them to BENIGN.
    This implements the 'PortScan stops -> BENIGN' transition while
    keeping the PortScan entries in the alert history."""

    from flow_builder import flows

    count = 0

    for key, pred in list(
        last_predictions.items()
    ):

        if count >= limit:

            break

        if (
            pred == "PortScan"
            and key in flows
            and not is_portscan_active(
                key[0],
                key[1]
            )
        ):

            mark_flow_pending(
                key
            )

            count += 1


def _prune_aging_state():

    now = time.time()

    # Drop old PortScan tracking state
    for key in list(
        portscan_last_seen
    ):

        if now - portscan_last_seen[
            key
        ] > 300:

            portscan_last_seen.pop(
                key,
                None
            )

            portscan_tracker.pop(
                key,
                None
            )

            portscan_last_alert.pop(
                key,
                None
            )

            portscan_features.pop(
                key,
                None
            )

    # Drop predictions for flows that no longer exist
    from flow_builder import flows

    for key in list(
        last_predictions
    ):

        if key not in flows:

            last_predictions.pop(
                key,
                None
            )


# ===============================================================
# INTERFACE RESOLUTION
# ===============================================================

def _iface_ipv4_addresses(iface):
    """Return the IPv4 addresses bound to a Scapy interface object."""
    try:
        ips = getattr(iface, "ips", None)
        if not ips:
            return []
        return [str(a) for a in (ips.get(4) or []) if a]
    except Exception:
        return []


def _iface_primary_ip(iface):
    """Return the primary IPv4 address, if one exists."""
    addrs = _iface_ipv4_addresses(iface)
    if addrs:
        return addrs[0]
    ip = getattr(iface, "ip", None)
    return str(ip) if ip else None


def _iface_flags_str(iface):
    return str(getattr(iface, "flags", "") or "")


def _iface_is_up(iface):
    flags = _iface_flags_str(iface)
    return "UP" in flags and "RUNNING" in flags


def _iface_is_loopback(iface):
    text = f"{(getattr(iface, 'name', '') or '')} {(getattr(iface, 'description', '') or '')}".lower()
    return "loopback" in text


def _iface_is_wsl_hyperv(iface):
    """True for the WSL/Hyper-V virtual switch adapter."""
    name = (getattr(iface, "name", "") or "").lower()
    desc = (getattr(iface, "description", "") or "").lower()
    return (
        "hyper-v" in name
        or "hyper-v" in desc
        or "vEthernet".lower() in name
        or "virtual ethernet" in desc
        or "wsl" in name
        or "wsl" in desc
    )


def _iface_owns_wsl_subnet(iface):
    """True if the interface holds an IPv4 on the 172.16/12 private
    range (the subnet WSL/Hyper-V uses for its NAT)."""
    addrs = _iface_ipv4_addresses(iface)
    return any(a.startswith(WSL_NET_PREFIXES) for a in addrs)


def _is_physical_desc(desc, name):
    """True if the description/name looks like a physical (non-virtual)
    adapter rather than a miniport/virtual/direct pseudo device."""
    text = f"{desc or ''} {name or ''}".lower()
    ban = (
        "loopback", "miniport", "virtual", "wi-fi direct",
        "kernel debug", "lightweight filter", "packet driver",
        "qos", "wfp", "vmswitch", "bluetooth",
        "npcap", "ndis", "pppoe",
    )
    return not any(b in text for b in ban)


def _all_scapy_ifaces():
    """Return every NetworkInterface object Scapy currently knows."""
    return list(conf.ifaces.values())


def _resolve_capture_interface():
    """
    Resolve the capture interface dynamically from Scapy's live
    interface table (conf.ifaces / get_if_list). Never depends on a
    hard-coded interface index or a stale NPF GUID.

    Priority order:
      1. WSL/Hyper-V adapter owning the gateway IP (172.29.0.1)
      2. Any WSL/Hyper-V adapter with a 172.16/12 address
      3. Any WSL/Hyper-V adapter that is UP/RUNNING
      4. Physical Ethernet adapter
      5. Physical Wi-Fi adapter
      6. Any other UP/RUNNING, non-loopback Npcap interface

    Returns a NetworkInterface object, or None if nothing valid exists.
    """
    ifaces = _all_scapy_ifaces()

    def usable(iface):
        return (
            getattr(iface, "name", None)
            and not _iface_is_loopback(iface)
            and _iface_is_up(iface)
        )

    # 1) The adapter that owns the exact WSL gateway 172.29.0.1.
    for iface in ifaces:
        if usable(iface) and WSL_GATEWAY_IP in _iface_ipv4_addresses(iface):
            return iface

    # 2) A WSL/Hyper-V adapter carrying a 172.16/12 private address.
    for iface in ifaces:
        if usable(iface) and _iface_is_wsl_hyperv(iface) and _iface_owns_wsl_subnet(iface):
            return iface

    # 3) Any UP/RUNNING WSL/Hyper-V adapter, even without a v4 address.
    for iface in ifaces:
        if usable(iface) and _iface_is_wsl_hyperv(iface):
            return iface

    # 4) Physical Ethernet.
    for iface in ifaces:
        desc = (getattr(iface, "description", "") or "").lower()
        if not usable(iface):
            continue
        if ("ethernet" in desc or "gbe" in desc or "gigabit" in desc) and _is_physical_desc(
            getattr(iface, "description", ""), getattr(iface, "name", "")
        ):
            return iface

    # 5) Physical Wi-Fi (only physical, never "Wi-Fi Direct" virtual).
    for iface in ifaces:
        desc = (getattr(iface, "description", "") or "").lower()
        if not usable(iface):
            continue
        if ("wi-fi" in desc or "wireless" in desc or "802.11" in desc) \
                and "direct" not in desc:
            return iface

    # 6) Any other UP/RUNNING, non-loopback, non-virtual Npcap interface.
    for iface in ifaces:
        if not usable(iface):
            continue
        if _is_physical_desc(
            getattr(iface, "description", ""), getattr(iface, "name", "")
        ):
            return iface

    return None


def _validate_interface(candidate):
    """
    Confirm a resolved interface still exists in Scapy's interface
    table and return a concrete NetworkInterface object usable by
    sniff(). Returns None if the interface cannot be validated.
    """
    if candidate is None:
        return None

    name = getattr(candidate, "name", None)
    if name:
        try:
            return conf.ifaces.dev_from_name(name)
        except Exception:
            pass
    return candidate if candidate in _all_scapy_ifaces() else None


def _describe_interface(iface):
    """Build the human-readable capture banner lines for an interface."""
    name = getattr(iface, "name", None) or str(iface)
    ip = _iface_primary_ip(iface)
    desc = getattr(iface, "description", "") or ""
    return name, (ip or "none"), desc


# ===============================================================
# BACKGROUND CAPTURE
# ===============================================================

def _run_capture(iface):

    # Capture this generation's stop event so replacing the
    # module-level one on a later start never affects this loop.
    stop_flag = _stop_flag

    # -----------------------------------------------------------
    # Resolve the interface inside the thread so the
    # /capture/start request returns immediately. Never blocks the
    # API thread on interface discovery or Scapy startup.
    # -----------------------------------------------------------

    # If the caller supplied an explicit interface name string, resolve
    # it to a concrete Scapy interface; otherwise auto-detect one.
    if isinstance(iface, str) and iface:
        try:
            iface = conf.ifaces.dev_from_name(iface)
        except Exception:
            iface = None

    if iface is None:

        iface = _resolve_capture_interface()

    iface = _validate_interface(iface)

    if iface is None:

        error_msg = (
            "No valid capture interface found. "
            "Could not locate the WSL/Hyper-V adapter (172.29.0.1) "
            "or any other Npcap interface."
        )

        update_capture_status(
            running=False,
            mode="idle",
            error=error_msg,
        )

        log_event(

            "System",

            error_msg,

            "error"
        )

        print()
        print("CAPTURE ERROR:")
        print(error_msg)
        print()

        return

    # -----------------------------------------------------------
    # Friendly details for the dashboard + console banner
    # -----------------------------------------------------------

    iface_name, iface_ip, iface_desc = _describe_interface(iface)

    update_capture_status(
        running=True,
        mode="live",
        iface=iface_name,
        iface_ip=iface_ip,
        started_at=datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        ),
        error=None,
    )

    log_event(

        "System",

        f"Packet capture started on {iface_name} ({iface_ip})",

        "live mode"
    )

    print()

    print(
        "========================================"
    )

    print(
        "       LIVE PACKET CAPTURE"
    )

    print(
        "========================================"
    )

    print(
        f"Selected interface : {iface_name}"
    )

    print(
        f"IP                 : {iface_ip}"
    )

    print(
        f"Capture mode       : live"
    )

    print(
        f"Description        : {iface_desc}"
    )

    print(
        "Status             : RUNNING"
    )

    print(
        "========================================"
    )

    print()

    # -----------------------------------------------------------
    # Packet callback
    # -----------------------------------------------------------

    def _prn(pkt):

        capture_status[
            "packets_seen"
        ] += 1

        capture_status[
            "last_heartbeat"
        ] = time.time()

        if DEBUG:

            print(
                "[PACKET RECEIVED] "
                f"{pkt.summary()} | "
                f"{len(pkt)} bytes"
            )

        try:

            process_packet(
                pkt
            )

        except Exception as e:

            if DEBUG:

                print(
                    "[PROCESS ERROR]",
                    e
                )

            log_event(

                "Packet Processing",

                str(e),

                "error"
            )

    # -----------------------------------------------------------
    # Stop condition.
    #
    # This is the ONLY thing allowed to end the sniff loop: the stop
    # flag set by stop_capture(). Receiving a packet never touches it,
    # so the stop condition can never become true as a side effect of
    # processing the first (or any) packet.
    # -----------------------------------------------------------

    def _should_stop(pkt):
        return stop_flag.is_set()

    log_event(

        "System",

        f"sniff started on {iface_name} ({iface_ip})",

        "live mode"
    )

    print()
    print("SNIFF STARTED")
    print()

    # -----------------------------------------------------------
    # Capture loop.
    #
    # sniff() is synchronous: it returns only when Scapy's internal
    # socket loop exits. That can happen for three reasons:
    #   1. the stop condition above becomes True (Stop was pressed),
    #   2. the per-iteration timeout elapses (no packet for a while),
    #   3. the underlying capture socket dropped (Windows Npcap on the
    #      WSL/Hyper-V virtual adapter can report EOF after a single
    #      frame).
    #
    # We loop and keep re-entering sniff() until the user explicitly
    # requests a stop, so a dropped socket can never silently end the
    # capture right after the first packet. A short timeout also means
    # stop_capture() is noticed promptly even when traffic is idle.
    # -----------------------------------------------------------

    try:

        while not stop_flag.is_set():

            sniff(

                iface=iface,

                prn=_prn,

                store=False,

                timeout=1,

                stop_filter=_should_stop,
            )

            if stop_flag.is_set():

                log_event(

                    "System",

                    "sniff exited (stop requested)",

                    "live mode"
                )

                print("SNIFF EXITED (stop requested)")

                break

    except Exception as e:

        update_capture_status(
            error=str(e),
        )

        log_event(

            "System",

            f"Capture error: {e}",

            "error"
        )

        print()

        print(
            "CAPTURE ERROR:"
        )

        print(e)

        print()

    finally:

        # Only reset status when this mode is still the active one,
        # so a stopping capture cannot clobber a newly started demo.
        if capture_status["mode"] == "live":

            update_capture_status(
                running=False,
                mode="idle",
            )

            log_event(

                "System",

                "Packet capture stopped",

                "idle"
            )

            print("CAPTURE STOPPED")


# ===============================================================
# START CAPTURE
# ===============================================================

def start_capture(iface=None):
    """
    Start live capture and return immediately.

    The interface lookup and the Scapy sniff loop run on a
    background thread, so the request never waits for them.
    """

    global _capture_thread
    global _stop_flag

    # -----------------------------------------------------------
    # Already running
    # -----------------------------------------------------------

    if (
        _capture_thread is not None
        and _capture_thread.is_alive()
    ):

        return {

            "status":
                "already_running",

            "mode":
                "live",
        }

    if (
        capture_status["running"]
        and capture_status["mode"] == "live"
    ):

        return {

            "status":
                "already_running",

            "mode":
                "live",
        }

    # -----------------------------------------------------------
    # Reset stop flag + start background thread
    # -----------------------------------------------------------

    # Only one source mode (live / demo) may run at a time.
    # Stop a running demo before starting live capture.
    try:

        from demo_generator import stop_demo

        if (
            capture_status["running"]
            and capture_status["mode"] == "demo"
        ):

            stop_demo()

    except ImportError:

        pass

    _stop_flag = threading.Event()

    _capture_thread = threading.Thread(
        target=_run_capture,
        args=(iface,),
        daemon=True,
        name="capture",
    )

    _capture_thread.start()

    ensure_flow_predictor_running()

    return {

        "status":
            "started",

        "mode":
            "live",
    }


# ===============================================================
# STOP CAPTURE
# ===============================================================

def stop_capture():

    # Only stop_capture() sets the stop flag. Setting it whenever a
    # capture thread is alive (rather than only when the in-memory
    # "running" flag happens to be True) avoids a race where a stop
    # request is dropped and the sniff loop keeps running.

    thread_alive = (
        _capture_thread is not None
        and _capture_thread.is_alive()
    )

    if capture_status["running"] or thread_alive:

        _stop_flag.set()

    return {

        "status":
            "stopping",

        "running":
            capture_status[
                "running"
            ],
    }


# ===============================================================
# START THE FLOW PREDICTOR FOR CLI / IMPORT USAGE
# ===============================================================

ensure_flow_predictor_running()


# ===============================================================
# CLI ENTRYPOINT
# ===============================================================

if __name__ == "__main__":

    initialize_database()

    print(
        "Database Ready"
    )

    print()

    print(
        "Starting WSL live packet capture..."
    )

    print()

    result = start_capture()

    print(
        "Capture result:",
        result
    )

    try:

        while capture_status[
            "running"
        ]:

            time.sleep(1)

    except KeyboardInterrupt:

        print()

        print(
            "Stopping packet capture..."
        )

        stop_capture()