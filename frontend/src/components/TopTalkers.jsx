import API from "../services/api";
import usePolling from "../hooks/usePolling";
import Loading from "./Loading";

function TopTalkers() {
    const { data, loading } = usePolling(async () => {
        const res = await API.get("/top-talkers", { params: { limit: 5 } });
        return res.data;
    }, 3000);

    const talkers = data || [];
    const max = Math.max(...talkers.map((t) => t.packets), 1);

    return (
        <div className="panel">
            <div className="panel-head">
                <h2>Top Talkers</h2>
                <span className="panel-badge">by volume</span>
            </div>
            {loading && !data ? (
                <Loading height={180} />
            ) : talkers.length === 0 ? (
                <div className="empty-state">No traffic data yet</div>
            ) : (
                <div className="talker-list">
                    {talkers.map((row, index) => (
                        <div className="talker-row" key={row.source_ip}>
                            <span className={`talker-rank rank-${index + 1}`}>{index + 1}</span>
                            <div className="talker-main">
                                <span className="talker-ip">{row.source_ip}</span>
                                <div className="talker-bar">
                                    <div
                                        className="talker-fill"
                                        style={{ width: `${(row.packets / max) * 100}%` }}
                                    />
                                </div>
                            </div>
                            <span className="talker-count">{row.packets.toLocaleString()} pkts</span>
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
}

export default TopTalkers;
