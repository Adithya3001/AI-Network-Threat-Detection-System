import { useMemo } from "react";
import API from "../services/api";
import usePolling from "../hooks/usePolling";
import SeverityBadge from "./SeverityBadge";
import { formatConfidence, attackColor } from "../constants";

function LiveTable({ onOpen }) {
    const { data } = usePolling(async () => {
        const res = await API.get("/live");
        return res.data;
    }, 2000);

    const rows = useMemo(() => {
        if (!data || Object.keys(data).length === 0) return [];
        return [data];
    }, [data]);

    if (rows.length === 0) {
        return (
            <div className="panel">
                <div className="panel-head"><h2>Latest Packet</h2></div>
                <div className="empty-state">No packets captured yet.</div>
            </div>
        );
    }

    const r = rows[0];
    const isAttack = r.attack_type !== "BENIGN";

    return (
        <div className="panel">
            <div className="panel-head">
                <h2>Latest Packet</h2>
                <span className="panel-badge">real-time</span>
            </div>
            <div className="live-mini-row" onClick={() => onOpen && onOpen(r)}>
                <div className="live-mini-conn">
                    <strong>{r.source_ip}:{r.source_port}</strong>
                    <span className="mini-arrow">→</span>
                    <strong>{r.destination_ip}:{r.destination_port}</strong>
                </div>
                <div className="live-mini-meta">
                    <span className={`proto-chip ${r.protocol?.toLowerCase()}`}>{r.protocol}</span>
                    <span
                        className={`classify-chip ${isAttack ? "attack" : "benign"}`}
                        style={isAttack ? { background: `${attackColor(r.attack_type)}1a`, color: attackColor(r.attack_type), borderColor: `${attackColor(r.attack_type)}44` } : {}}
                    >
                        {r.attack_type}
                    </span>
                    <SeverityBadge severity={r.severity} />
                    <span className="cell-conf">{formatConfidence(r.confidence)}</span>
                </div>
            </div>
        </div>
    );
}

export default LiveTable;
