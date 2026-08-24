import { FaBrain, FaShieldAlt, FaExclamationTriangle } from "react-icons/fa";
import API from "../services/api";
import usePolling from "../hooks/usePolling";
import SeverityBadge from "./SeverityBadge";
import { attackColor, formatConfidence } from "../constants";

function AIDecisionPanel() {
    const { data, loading } = usePolling(async () => {
        const res = await API.get("/ai-decision");
        return res.data;
    }, 3000);

    if (loading && !data) {
        return (
            <div className="panel">
                <div className="panel-head"><h2>AI Decision Engine</h2></div>
                <div className="empty-state">Waiting for analysis…</div>
            </div>
        );
    }

    const d = data || {};
    const isAttack = d.attack && d.attack !== "BENIGN";
    const color = attackColor(d.attack || "BENIGN");

    return (
        <div className="panel">
            <div className="panel-head">
                <h2><FaBrain className="inline-icon" /> AI Decision Engine</h2>
                <span className="panel-badge">{d.timestamp || "—"}</span>
            </div>

            {!d.attack ? (
                <div className="empty-state">No prediction yet — start capture or demo mode.</div>
            ) : (
                <>
                    <div className="ai-hero" style={{ borderColor: color }}>
                        <div
                            className={`ai-verdict ${isAttack ? "verdict-attack" : "verdict-benign"}`}
                            style={{ color }}
                        >
                            {isAttack ? <FaExclamationTriangle /> : <FaShieldAlt />}
                            <span>{d.attack}</span>
                        </div>
                        <div className="ai-meta">
                            <SeverityBadge severity={d.severity} />
                            <span className="ai-confidence">
                                {formatConfidence(d.confidence)}
                            </span>
                            <span className="ai-conf-label">confidence</span>
                        </div>
                    </div>

                    <p className="ai-description">{d.description}</p>

                    {d.reasons && d.reasons.length > 0 && (
                        <div className="ai-section">
                            <h4>Why the model decided this</h4>
                            {d.reasons.map((r, i) => (
                                <div className="ai-reason" key={i}>
                                    <span className="ai-bullet" style={{ background: color }} />
                                    {r}
                                </div>
                            ))}
                        </div>
                    )}

                    {d.signals && d.signals.length > 0 && (
                        <div className="ai-section">
                            <h4>Signals observed</h4>
                            <div className="signal-chips">
                                {d.signals.map((s, i) => (
                                    <span className="signal-chip" key={i}>{s}</span>
                                ))}
                            </div>
                        </div>
                    )}

                    {d.feature_highlight && (
                        <div className="ai-section">
                            <h4>Key features</h4>
                            <div className="feature-grid">
                                {d.feature_highlight.map((f, i) => (
                                    <div className="feature-cell" key={i}>
                                        <span>{f.name}</span>
                                        <strong>{f.value}</strong>
                                    </div>
                                ))}
                            </div>
                        </div>
                    )}
                </>
            )}
        </div>
    );
}

export default AIDecisionPanel;
