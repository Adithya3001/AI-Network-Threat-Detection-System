import { useMemo, useState } from "react";
import { FaSearch, FaDownload, FaTimes } from "react-icons/fa";
import API from "../services/api";
import SeverityBadge from "./SeverityBadge";
import PacketInspector from "./PacketInspector";
import usePolling from "../hooks/usePolling";
import { formatConfidence, attackColor } from "../constants";

function TrafficTable() {
    const { data } = usePolling(async () => {
        const res = await API.get("/history");
        return res.data;
    }, 2000);

    const [search, setSearch] = useState("");
    const [filter, setFilter] = useState("ALL");
    const [inspector, setInspector] = useState(null);

    const history = useMemo(() => data || [], [data]);

    const attackTypes = useMemo(
        () => [...new Set(history.map((r) => r.attack_type))].sort(),
        [history]
    );

    const filteredHistory = useMemo(() => {
        const q = search.toLowerCase();
        return history.filter((row) => {
            const matchesSearch =
                row.source_ip.toLowerCase().includes(q) ||
                row.destination_ip.toLowerCase().includes(q) ||
                row.attack_type.toLowerCase().includes(q) ||
                String(row.destination_port).includes(q);
            const matchesFilter = filter === "ALL" || row.attack_type === filter;
            return matchesSearch && matchesFilter;
        });
    }, [history, search, filter]);

    function exportCSV() {
        const headers = ["Time", "Source IP", "Destination IP", "Source Port", "Destination Port", "Protocol", "Attack", "Confidence", "Severity"];
        const rows = filteredHistory.map((row) => [
            row.timestamp, row.source_ip, row.destination_ip,
            row.source_port, row.destination_port, row.protocol,
            row.attack_type, formatConfidence(row.confidence), row.severity,
        ]);
        const csv = [headers, ...rows].map((e) => e.join(",")).join("\n");
        const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
        const url = URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.href = url;
        link.download = "network_traffic.csv";
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(url);
    }

    return (
        <div className="panel table-panel">
            <div className="panel-head">
                <h2>Live Traffic</h2>
                <span className="panel-badge">{filteredHistory.length} records</span>
            </div>

            <div className="table-controls">
                <div className="search-box">
                    <FaSearch />
                    <input
                        type="text"
                        placeholder="Search IP, port or attack…"
                        value={search}
                        onChange={(e) => setSearch(e.target.value)}
                    />
                    {search && (
                        <button className="search-clear" onClick={() => setSearch("")}><FaTimes /></button>
                    )}
                </div>
                <select value={filter} onChange={(e) => setFilter(e.target.value)}>
                    <option value="ALL">All types</option>
                    {attackTypes.map((t) => (
                        <option key={t} value={t}>{t}</option>
                    ))}
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
                            <th>Direction</th>
                            <th>Destination</th>
                            <th>Protocol</th>
                            <th>Classification</th>
                            <th>Confidence</th>
                            <th>Severity</th>
                        </tr>
                    </thead>
                    <tbody>
                        {filteredHistory.slice(0, 100).map((row) => {
                            const isAttack = row.attack_type !== "BENIGN";
                            return (
                                <tr key={row.id} onClick={() => setInspector(row)} className="clickable-row">
                                    <td className="cell-time">{row.timestamp}</td>
                                    <td className="cell-ip">{row.source_ip}<span className="cell-port">:{row.source_port}</span></td>
                                    <td className="cell-dir">
                                        <span className="dir-arrow">→</span>
                                    </td>
                                    <td className="cell-ip">{row.destination_ip}<span className="cell-port">:{row.destination_port}</span></td>
                                    <td>
                                        <span className={`proto-chip ${row.protocol?.toLowerCase()}`}>{row.protocol}</span>
                                    </td>
                                    <td>
                                        <span
                                            className={`classify-chip ${isAttack ? "attack" : "benign"}`}
                                            style={isAttack ? { background: `${attackColor(row.attack_type)}1a`, color: attackColor(row.attack_type), borderColor: `${attackColor(row.attack_type)}44` } : {}}
                                        >
                                            {row.attack_type}
                                        </span>
                                    </td>
                                    <td className="cell-conf">{formatConfidence(row.confidence)}</td>
                                    <td><SeverityBadge severity={row.severity} /></td>
                                </tr>
                            );
                        })}
                        {filteredHistory.length === 0 && (
                            <tr><td colSpan="8" className="empty-cell">No records match your filters.</td></tr>
                        )}
                    </tbody>
                </table>
            </div>

            <p className="table-hint">Click any row to open the packet inspector.</p>

            <PacketInspector record={inspector} onClose={() => setInspector(null)} />
        </div>
    );
}

export default TrafficTable;
