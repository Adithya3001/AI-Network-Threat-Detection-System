import {
    Line, XAxis, YAxis, Tooltip,
    ResponsiveContainer, CartesianGrid, Area, ComposedChart,
} from "recharts";
import API from "../services/api";
import usePolling from "../hooks/usePolling";
import Loading from "./Loading";

function AttackTrendGraph() {
    const { data, loading } = usePolling(async () => {
        const res = await API.get("/attack-trend");
        return res.data;
    }, 4000);

    return (
        <div className="panel">
            <div className="panel-head">
                <h2>Attack Trend</h2>
                <span className="panel-badge">last 30 min</span>
            </div>
            {loading && !data ? (
                <Loading />
            ) : (
                <ResponsiveContainer width="100%" height={260}>
                    <ComposedChart data={data || []} margin={{ top: 5, right: 5, left: -20, bottom: 0 }}>
                        <defs>
                            <linearGradient id="gTrend" x1="0" y1="0" x2="0" y2="1">
                                <stop offset="0%" stopColor="#D97706" stopOpacity={0.35} />
                                <stop offset="100%" stopColor="#D97706" stopOpacity={0} />
                            </linearGradient>
                        </defs>
                        <CartesianGrid strokeDasharray="3 3" stroke="#D9E4E1" />
                        <XAxis dataKey="ts" tick={{ fill: "#64748B", fontSize: 11 }} />
                        <YAxis tick={{ fill: "#64748B", fontSize: 11 }} allowDecimals={false} />
                        <Tooltip
                            contentStyle={{
                                background: "#FAFCFB", border: "1px solid #D9E4E1",
                                borderRadius: 10, fontSize: 12, color: "#24323A",
                            }}
                        />
                        <Area type="monotone" dataKey="attacks" stroke="#D97706" fill="url(#gTrend)" isAnimationActive={false} />
                        <Line
                            type="monotone" dataKey="attacks" stroke="#F59E0B"
                            strokeWidth={2} dot={false} isAnimationActive={false}
                        />
                    </ComposedChart>
                </ResponsiveContainer>
            )}
        </div>
    );
}

export default AttackTrendGraph;
