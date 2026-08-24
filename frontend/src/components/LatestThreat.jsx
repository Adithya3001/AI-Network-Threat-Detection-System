import { FaShieldAlt, FaExclamationTriangle } from "react-icons/fa";
import API from "../services/api";
import usePolling from "../hooks/usePolling";
import SeverityBadge from "./SeverityBadge";
import { formatConfidence } from "../constants";

function LatestThreat() {
    const { data } = usePolling(async () => {
        const res = await API.get("/latest-threat");
        return res.data;
    }, 2500);

    const threat = data && data.id ? data : null;

    return (
        <div className={`latest-threat ${threat ? "has-threat" : ""}`}>
            {!threat ? (
                <div className="lt-safe">
                    <div className="lt-safe-icon"><FaShieldAlt /></div>
                    <div>
                        <h2>No Active Threats</h2>
                        <p>Your network currently looks safe.</p>
                    </div>
                </div>
            ) : (
                <>
                    <div className="lt-head">
                        <div className="lt-icon"><FaExclamationTriangle /></div>
                        <div>
                            <h2>{threat.attack_type}</h2>
                            <p>Latest detected attack</p>
                        </div>
                    </div>
                    <div className="lt-grid">
                        <div><span>Source</span><strong>{threat.source_ip}</strong></div>
                        <div><span>Destination</span><strong>{threat.destination_ip}</strong></div>
                        <div><span>Protocol</span><strong>{threat.protocol}</strong></div>
                        <div><span>Confidence</span><strong>{formatConfidence(threat.confidence)}</strong></div>
                    </div>
                    <div className="lt-meta">
                        <SeverityBadge severity={threat.severity} />
                        <span className="lt-time">{threat.timestamp}</span>
                    </div>
                </>
            )}
        </div>
    );
}

export default LatestThreat;
