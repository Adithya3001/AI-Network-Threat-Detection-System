export const SEVERITY_COLORS = {
    None: "#16A34A",
    Low: "#0D9488",
    Medium: "#D97706",
    High: "#EA580C",
    Critical: "#DC2626",
};

export const SEVERITY_ORDER = ["None", "Low", "Medium", "High", "Critical"];

export const ATTACK_COLORS = {
    BENIGN: "#16A34A",
    PortScan: "#0D9488",
    "FTP-Patator": "#D97706",
    "SSH-Patator": "#EA580C",
    Bot: "#7C3AED",
    Botnet: "#7C3AED",
    DDoS: "#DC2626",
    "DoS Hulk": "#DC2626",
    "DoS GoldenEye": "#BE123C",
    "DoS Slowloris": "#B91C1C",
    "DoS Slowhttptest": "#991B1B",
    "Web Attack": "#EA580C",
    "Web Attack - Brute Force": "#E11D48",
    "Web Attack - XSS": "#C026D3",
    Infiltration: "#9333EA",
    "Brute Force": "#D97706",
};

export function attackColor(attack) {
    return ATTACK_COLORS[attack] || "#94A3B8";
}

export function severityColor(sev) {
    return SEVERITY_COLORS[sev] || "#94A3B8";
}

export function formatConfidence(c) {
    if (c === null || c === undefined) return "—";
    return `${(c * 100).toFixed(2)}%`;
}