import { FaShieldAlt, FaExclamationTriangle, FaExclamationCircle } from "react-icons/fa";
import API from "../services/api";
import usePolling from "../hooks/usePolling";

const LEVELS = {
    SAFE: { color: "#16A34A", glow: "rgba(22,163,74,.35)", icon: FaShieldAlt, msg: "No recent attacks detected" },
    WARNING: { color: "#D97706", glow: "rgba(217,119,6,.35)", icon: FaExclamationTriangle, msg: "Some attack activity detected" },
    CRITICAL: { color: "#DC2626", glow: "rgba(220,38,38,.4)", icon: FaExclamationCircle, msg: "High attack activity detected" },
};

function ThreatLevel() {
    const { data } = usePolling(async () => {
        const res = await API.get("/stats");
        return res.data;
    }, 2000);

    const level = LEVELS[data?.threat_level] || LEVELS.SAFE;
    const severity = data?.severity || 0;
    const Icon = level.icon;

    return (
        <div className="threat-card">
            <div className="threat-level-top">
                <h2>Network Threat Level</h2>
                <span className="threat-recent">{data?.recent_attacks ?? 0} attacks / last 100</span>
            </div>

            <div className="threat-gauge" style={{ "--glow": level.glow }}>
                <div className="gauge-ring" style={{ background: `conic-gradient(${level.color} ${severity}%, #D9E4E1 ${severity}%)` }}>
                    <div className="gauge-center">
                        <Icon style={{ color: level.color, fontSize: 30 }} />
                        <strong style={{ color: level.color }}>{data?.threat_level || "SAFE"}</strong>
                    </div>
                </div>
            </div>

            <div className="threat-msg" style={{ color: level.color }}>{level.msg}</div>

            <div className="threat-stats">
                <div><span>Total</span><strong>{data?.total_predictions ?? 0}</strong></div>
                <div><span>Benign</span><strong>{data?.benign ?? 0}</strong></div>
                <div><span>Attacks</span><strong>{data?.attacks ?? 0}</strong></div>
            </div>
        </div>
    );
}

export default ThreatLevel;
