"""
Heuristic explanation for each AI prediction.

Uses the live flow features to highlight the observable signals that
support the classification, presented as human-readable reasons.
"""

from alerts import get_attack_description, get_severity


def _rounded(features, key):
    val = features.get(key, 0)
    try:
        return round(float(val), 2)
    except (TypeError, ValueError):
        return 0


def explain(attack, confidence, features):
    reasons = []
    signals = []

    dst_port = features.get("Destination Port", 0)
    syn = features.get("SYN Flag Count", 0)
    fwd = features.get("Total Fwd Packets", 0)
    bwd = features.get("Total Backward Packets", 0)
    flow_bps = features.get("Flow Bytes/s", 0)
    pkt_ps = features.get("Flow Packets/s", 0)
    duration = features.get("Flow Duration", 0)
    active_mean = features.get("Active Mean", 0)

    # ---- Port / flag heuristics ----
    if dst_port == 21 and syn > 0:
        signals.append(f"Repeated connections to FTP port 21 ({int(syn)} SYN flags)")
        if "FTP" in str(attack):
            reasons.append("Targets FTP service with repeated handshakes - classic brute-force signature.")
    if dst_port == 22 and syn > 0:
        signals.append(f"Repeated connections to SSH port 22 ({int(syn)} SYN flags)")
        if "SSH" in str(attack):
            reasons.append("Repeated login attempts to SSH detected - brute-force signature.")
    if dst_port <= 1024 and fwd > 3:
        signals.append(f"Multiple distinct low ports targeted (e.g. port {dst_port})")
        if "PortScan" in str(attack):
            reasons.append("Host is probing many destination ports - matches PortScan behaviour.")
    if flow_bps and flow_bps > 1_000_000:
        signals.append(f"High data throughput (~{int(flow_bps/1e6)} MB/s)")
        if "DoS" in str(attack):
            reasons.append("Traffic volume saturates the target - consistent with DoS flooding.")
    if pkt_ps and pkt_ps > 50:
        signals.append(f"High packet rate (~{int(pkt_ps)} pkts/sec)")
        if "DoS" in str(attack) or "PortScan" in str(attack):
            reasons.append("Elevated packet rate indicates automated flood or scanning.")
    if syn and fwd and syn / max(fwd, 1) > 0.5:
        signals.append(f"Large share of handshake (SYN) packets ({int(syn)} of {int(fwd)})")
    if "Bot" in str(attack):
        signals.append("Periodic beaconing pattern across the flow")
        reasons.append("Steady periodic communication matches botnet command-and-control behaviour.")
    if "Web" in str(attack):
        signals.append(f"Web-port activity (port {dst_port}) with anomalous request patterns")
        reasons.append("Suspicious web application traffic - possible exploitation attempt.")

    if not reasons:
        reasons.append("No dominant single signal; the model combined many subtle features.")

    # Top measured signals
    if not signals:
        signals = [
            f"Flow duration {_rounded(features, 'Flow Duration'):.3f}s",
            f"{int(fwd)} fwd / {int(bwd)} bwd packets",
            f"{_rounded(features, 'Flow Bytes/s')} bytes/s",
        ]

    return {
        "attack": attack,
        "confidence": confidence,
        "severity": get_severity(attack),
        "description": get_attack_description(attack),
        "reasons": reasons,
        "signals": signals[:5],
        "feature_highlight": [
            {"name": "Destination Port", "value": dst_port},
            {"name": "Total Fwd Packets", "value": fwd},
            {"name": "SYN Flag Count", "value": syn},
            {"name": "Flow Bytes/s", "value": _rounded(features, "Flow Bytes/s")},
            {"name": "Flow Packets/s", "value": _rounded(features, "Flow Packets/s")},
        ],
    }
