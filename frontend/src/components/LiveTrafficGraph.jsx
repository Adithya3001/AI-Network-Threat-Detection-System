import {
    AreaChart, Area, XAxis, YAxis, Tooltip,
    ResponsiveContainer, CartesianGrid,
} from "recharts";
import API from "../services/api";
import usePolling from "../hooks/usePolling";
import Loading from "./Loading";

function LiveTrafficGraph() {
    const { data, loading } = usePolling(async () => {
        const res = await API.get("/traffic");
        return res.data;
    }, 2000);

    const history = (data || []).slice(-60);

    return (
        <div className="panel">
            <div className="panel-head">
                <h2>Live Traffic</h2>
                <span className="panel-badge">packets / sec</span>
            </div>
            <div className="legend-row">
                <span className="legend-item"><i style={{ background: "#16A34A" }} />Benign</span>
                <span className="legend-item"><i style={{ background: "#DC2626" }} />Attacks</span>
            </div>
            {loading && history.length === 0 ? (
                <Loading />
            ) : (
                <ResponsiveContainer width="100%" height={220}>
                    <AreaChart data={history} margin={{ top: 5, right: 5, left: -20, bottom: 0 }}>
                        <defs>
                            <linearGradient id="gBenign" x1="0" y1="0" x2="0" y2="1">
                                <stop offset="0%" stopColor="#16A34A" stopOpacity={0.5} />
                                <stop offset="100%" stopColor="#16A34A" stopOpacity={0} />
                            </linearGradient>
                            <linearGradient id="gAttack" x1="0" y1="0" x2="0" y2="1">
                                <stop offset="0%" stopColor="#DC2626" stopOpacity={0.5} />
                                <stop offset="100%" stopColor="#DC2626" stopOpacity={0} />
                            </linearGradient>
                        </defs>
                        <CartesianGrid strokeDasharray="3 3" stroke="#D9E4E1" />
                        <XAxis dataKey="ts" tick={{ fill: "#64748B", fontSize: 11 }} />
                        <YAxis tick={{ fill: "#64748B", fontSize: 11 }} />
                        <Tooltip
                            contentStyle={{
                                background: "#FAFCFB", border: "1px solid #D9E4E1",
                                borderRadius: 10, fontSize: 12, color: "#24323A",
                            }}
                        />
                        <Area
                            type="monotone" dataKey="benign"
                            stroke="#16A34A" strokeWidth={2} fill="url(#gBenign)"
                            isAnimationActive={false}
                        />
                        <Area
                            type="monotone" dataKey="attacks"
                            stroke="#DC2626" strokeWidth={2} fill="url(#gAttack)"
                            isAnimationActive={false}
                        />
                    </AreaChart>
                </ResponsiveContainer>
            )}
        </div>
    );
}

export default LiveTrafficGraph;
