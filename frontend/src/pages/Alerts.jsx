import { useMemo, useState } from "react";
import { FaSearch, FaDownload, FaBell, FaExclamationTriangle, FaTimes } from "react-icons/fa";
import API from "../services/api";
import usePolling from "../hooks/usePolling";
import SeverityBadge from "./../components/SeverityBadge";
import AlertDetailsModal from "./../components/AlertDetailsModal";
import StatCard from "./../components/StatCard";
import { formatConfidence, severityColor } from "../constants";

function Alerts() {
    const [search, setSearch] = useState("");
    const [sevFilter, setSevFilter] = useState("ALL");
    const [detail, setDetail] = useState(null);

    const { data } = usePolling(async () => {
        const res = await API.get("/alerts", { params: { limit: 300 } });
        return res.data;
    }, 2500);

    const alerts = data || [];

    const totalAttacks = alerts.length;
    const critical = alerts.filter((a) => a.severity === "Critical").length;
    const high = alerts.filter((a) => a.severity === "High").length;
    const medium = alerts.filter((a) => a.severity === "Medium").length;

    const severityDistribution = useMemo(() => {
        const alerts = data || [];
        const map = {};
        alerts.forEach((a) => {
            map[a.severity] = (map[a.severity] || 0) + 1;
        });
        return Object.entries(map).sort(
            (a, b) => severityColor(a[0]) > severityColor(b[0]) ? -1 : 1
        );
    }, [data]);

    const attackTypes = useMemo(() => {
        const alerts = data || [];
        const map = {};
        alerts.forEach((a) => {
            map[a.attack_type] = (map[a.attack_type] || 0) + 1;
        });
        return Object.entries(map).sort((a, b) => b[1] - a[1]);
    }, [data]);

    const filtered = useMemo(() => {
        const alerts = data || [];
        const q = search.toLowerCase();
        return alerts.filter((a) => {
            const mSearch =
                a.source_ip.toLowerCase().includes(q) ||
                a.destination_ip.toLowerCase().includes(q) ||
                a.attack_type.toLowerCase().includes(q);
            const mSev = sevFilter === "ALL" || a.severity === sevFilter;
            return mSearch && mSev;
        });
    }, [data, search, sevFilter]);

    function exportCSV() {
        const headers = ["Time", "Source IP", "Destination IP", "Source Port", "Destination Port", "Protocol", "Attack", "Confidence", "Severity"];
        const rows = filtered.map((a) => [
            a.timestamp, a.source_ip, a.destination_ip, a.source_port,
            a.destination_port, a.protocol, a.attack_type,
            formatConfidence(a.confidence), a.severity,
        ]);
        const csv = [headers, ...rows].map((e) => e.join(",")).join("\n");
        const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
        const url = URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.href = url;
        link.download = "security_alerts.csv";
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(url);
    }

    return (
        <div className="page">
            <div className="page-title">
                <div>
                    <h1>Security Alerts</h1>
                    <p>Complete history of detected attacks with severity classification.</p>
                </div>
            </div>

            <div className="cards cards-4">
                <StatCard icon={FaBell} label="Total Alerts" value={totalAttacks.toLocaleString()} tone="red" />
                <StatCard icon={FaExclamationTriangle} label="Critical" value={critical.toLocaleString()} tone="red" sub="immediate action" />
                <StatCard icon={FaExclamationTriangle} label="High" value={high.toLocaleString()} tone="amber" />
                <StatCard icon={FaExclamationTriangle} label="Medium" value={medium.toLocaleString()} tone="teal" />
            </div>

            <div className="grid-2">
                <div className="panel">
                    <div className="panel-head">
                        <h2>Severity Breakdown</h2>
                        <span className="panel-badge">alerts</span>
                    </div>
                    {severityDistribution.length === 0 ? (
                        <div className="empty-state">No alerts to display</div>
                    ) : (
                        <div className="sev-bars">
                            {severityDistribution.map(([sev, count]) => {
                                const pct = (count / Math.max(totalAttacks, 1)) * 100;
                                return (
                                    <div className="sev-bar-row" key={sev}>
                                        <span className="sev-name">{sev}</span>
                                        <div className="sev-track">
                                            <div
                                                className="sev-fill"
                                                style={{ width: `${pct}%`, background: severityColor(sev) }}
                                            />
                                        </div>
                                        <span className="sev-count">{count}</span>
                                    </div>
                                );
                            })}
                        </div>
                    )}
                </div>

                <div className="panel">
                    <div className="panel-head">
                        <h2>Attack Types</h2>
                        <span className="panel-badge">distribution</span>
                    </div>
                    <div className="type-tags">
                        {attackTypes.map(([type, count]) => (
                            <div className="type-tag" key={type}>
                                <span>{type}</span>
                                <strong>{count}</strong>
                            </div>
                        ))}
                        {alerts.length === 0 && <div className="empty-state">No attacks yet</div>}
                    </div>
                </div>
            </div>

            <div className="panel table-panel">
                <div className="panel-head">
                    <h2>Alert History</h2>
                    <span className="panel-badge">{filtered.length} shown</span>
                </div>

                <div className="table-controls">
                    <div className="search-box">
                        <FaSearch />
                        <input
                            type="text"
                            placeholder="Search alerts…"
                            value={search}
                            onChange={(e) => setSearch(e.target.value)}
                        />
                        {search && (
                            <button className="search-clear" onClick={() => setSearch("")}><FaTimes /></button>
                        )}
                    </div>
                    <select value={sevFilter} onChange={(e) => setSevFilter(e.target.value)}>
                        <option value="ALL">All severities</option>
                        <option value="Critical">Critical</option>
                        <option value="High">High</option>
                        <option value="Medium">Medium</option>
                    </select>
                    <button className="export-btn" onClick={exportCSV}>
                        <FaDownload /> Export CSV
                    </button>
                </div>

                <div className="table-scroll">
                    <table className="traffic-table">
                        <thead>
                            <tr>
                                <th>Time</th>
                                <th>Source</th>
                                <th>Destination</th>
                                <th>Protocol</th>
                                <th>Attack Type</th>
                                <th>Confidence</th>
                                <th>Severity</th>
                            </tr>
                        </thead>
                        <tbody>
                            {filtered.slice(0, 200).map((a) => (
                                <tr key={a.id} className="clickable-row" onClick={() => setDetail(a)}>
                                    <td className="cell-time">{a.timestamp}</td>
                                    <td className="cell-ip">{a.source_ip}<span className="cell-port">:{a.source_port}</span></td>
                                    <td className="cell-ip">{a.destination_ip}<span className="cell-port">:{a.destination_port}</span></td>
                                    <td><span className={`proto-chip ${a.protocol?.toLowerCase()}`}>{a.protocol}</span></td>
                                    <td>
                                        <span className="classify-chip attack">{a.attack_type}</span>
                                    </td>
                                    <td className="cell-conf">{formatConfidence(a.confidence)}</td>
                                    <td><SeverityBadge severity={a.severity} /></td>
                                </tr>
                            ))}
                            {filtered.length === 0 && (
                                <tr><td colSpan="7" className="empty-cell">No alerts match your filters.</td></tr>
                            )}
                        </tbody>
                    </table>
                </div>
            </div>

            <AlertDetailsModal alert={detail} onClose={() => setDetail(null)} />
        </div>
    );
}

export default Alerts;
