import { FaArrowRight } from "react-icons/fa";
import API from "../services/api";
import usePolling from "../hooks/usePolling";
import SeverityBadge from "./SeverityBadge";
import { formatConfidence } from "../constants";

function RecentAlertsPanel({ onOpen }) {
    const { data } = usePolling(async () => {
        const res = await API.get("/alerts", { params: { limit: 6 } });
        return res.data;
    }, 2500);

    const alerts = data || [];

    return (
        <div className="panel">
            <div className="panel-head">
                <h2>Recent Alerts</h2>
                <span className="panel-badge">{alerts.length} latest</span>
            </div>
            {alerts.length === 0 ? (
                <div className="empty-state">No active alerts — network is clean.</div>
            ) : (
                <div className="recent-alerts">
                    {alerts.map((a) => (
                        <button
                            className="recent-alert"
                            key={a.id}
                            onClick={() => onOpen && onOpen(a)}
                        >
                            <span className={`alert-sev-bar sev-${a.severity?.toLowerCase()}`} />
                            <div className="recent-alert-info">
                                <span className="recent-alert-type">{a.attack_type}</span>
                                <span className="recent-alert-conn">
                                    {a.source_ip} <FaArrowRight className="mini-arrow" /> {a.destination_ip}
                                </span>
                            </div>
                            <SeverityBadge severity={a.severity} />
                            {a.attack_type === "PortScan" && a.scanned_ports > 0 && (
                                <span className="recent-alert-ports">{a.scanned_ports} ports</span>
                            )}
                            <span className="recent-alert-conf">{formatConfidence(a.confidence)}</span>
                        </button>
                    ))}
                </div>
            )}
        </div>
    );
}

export default RecentAlertsPanel;
