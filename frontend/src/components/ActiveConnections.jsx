import { FaArrowRight } from "react-icons/fa";
import API from "../services/api";
import usePolling from "../hooks/usePolling";
import Loading from "./Loading";

function ActiveConnections({ limit = 8 }) {
    const { data, loading } = usePolling(async () => {
        const res = await API.get("/active-connections");
        return res.data;
    }, 2500);

    const conns = (data || [])
        .filter((c) => c.packets > 0)
        .sort((a, b) => b.packets - a.packets)
        .slice(0, limit);

    return (
        <div className="panel">
            <div className="panel-head">
                <h2>Active Connections</h2>
                <span className="panel-badge">source → destination</span>
            </div>
            {loading && !data ? (
                <Loading height={180} />
            ) : conns.length === 0 ? (
                <div className="empty-state">No active connections</div>
            ) : (
                <div className="conn-list">
                    {conns.map((c, i) => {
                        const isAttack = c.attack_type && c.attack_type !== "BENIGN";
                        return (
                            <div className="conn-row" key={`${c.source_ip}${c.destination_ip}${c.source_port}${i}`}>
                                <span className={`conn-ip ${isAttack ? "attack" : ""}`}>
                                    {c.source_ip}:{c.source_port}
                                </span>
                                <FaArrowRight className="mini-arrow" />
                                <span className="conn-ip">{c.destination_ip}:{c.destination_port}</span>
                                <span className={`proto-chip ${c.protocol?.toLowerCase()}`}>{c.protocol}</span>
                                <span className="conn-pkts">{c.packets} pkts</span>
                                {isAttack && <span className="conn-alert">⚠ {c.attack_type}</span>}
                            </div>
                        );
                    })}
                </div>
            )}
        </div>
    );
}

export default ActiveConnections;
