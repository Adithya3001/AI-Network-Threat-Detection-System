# ---------------------------------------------------------------
# Severity classification for detected attack types.
# ---------------------------------------------------------------

SEVERITY_MAP = {
    "BENIGN": "None",
    "PortScan": "Medium",
    "FTP-Patator": "High",
    "SSH-Patator": "High",
    "Bot": "Critical",
    "Botnet": "Critical",
    "DoS Hulk": "Critical",
    "DoS GoldenEye": "Critical",
    "DoS Slowloris": "Critical",
    "DoS Slowhttptest": "Critical",
    "Web Attack": "High",
    "Web Attack - Brute Force": "High",
    "Web Attack - XSS": "High",
    "Infiltration": "High",
    "Brute Force": "High",
    "DDoS": "Critical",
}

SEVERITY_ORDER = {
    "None": 0,
    "Low": 1,
    "Medium": 2,
    "High": 3,
    "Critical": 4,
}

ATTACK_DESCRIPTIONS = {
    "BENIGN": "Normal network traffic with no detected malicious activity.",
    "PortScan": "An actor is systematically probing ports to discover open services and plan an attack.",
    "FTP-Patator": "Automated brute-force attempt against the FTP (port 21) login service.",
    "SSH-Patator": "Automated brute-force attempt against the SSH (port 22) login service.",
    "Bot": "A device is part of a botnet and may be used for coordinated attacks (C2, DDoS).",
    "Botnet": "A device is part of a botnet and may be used for coordinated attacks (C2, DDoS).",
    "DoS Hulk": "HTTP flood (Hulk tool) saturating the target with high-volume requests.",
    "DoS GoldenEye": "HTTP Keep-Alive flood designed to exhaust the target server's connections.",
    "DoS Slowloris": "Slowloris holds many connections open slowly to exhaust server resources.",
    "DoS Slowhttptest": "Slow-HTTP DoS attack keeping connections alive to drain resources.",
    "Web Attack": "Exploitation attempt against a web application (SQLi, XSS, or brute force).",
    "Web Attack - Brute Force": "Automated brute-force attempt against the web application login.",
    "Web Attack - XSS": "Cross-site scripting (XSS) payload injected into web traffic.",
    "Infiltration": "Malicious file exfiltration or internal network compromise detected.",
    "DDoS": "Distributed denial-of-service flooding a target from multiple sources.",
}


def get_severity(attack_type):
    return SEVERITY_MAP.get(attack_type, "Medium")


def get_attack_description(attack_type):
    return ATTACK_DESCRIPTIONS.get(attack_type, "Unknown traffic pattern.")


def severity_score(severity):
    return SEVERITY_ORDER.get(severity, 0)


def enrich_prediction(record):
    """Add severity + description to a DB row dictionary."""
    record = dict(record)
    record["severity"] = get_severity(record.get("attack_type", "BENIGN"))
    record["description"] = get_attack_description(record.get("attack_type", "BENIGN"))
    return record
