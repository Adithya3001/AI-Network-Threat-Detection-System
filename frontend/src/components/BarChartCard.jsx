import {
    BarChart, Bar, XAxis, YAxis, Tooltip,
    ResponsiveContainer, CartesianGrid, Cell,
} from "recharts";
import API from "../services/api";
import usePolling from "../hooks/usePolling";
import Loading from "./Loading";
import { attackColor } from "../constants";

function BarChartCard() {
    const { data, loading } = usePolling(async () => {
        const res = await API.get("/top-attacks");
        return res.data;
    }, 3000);

    const chartData = (data || [])
        .map((d) => ({ name: d.attack_type, value: d.count }))
        .filter((d) => d.value > 0)
        .slice(0, 8);

    return (
        <div className="panel">
            <div className="panel-head">
                <h2>Top Attack Vectors</h2>
                <span className="panel-badge">count</span>
            </div>
            {loading && !data ? (
                <Loading />
            ) : chartData.length === 0 ? (
                <div className="empty-state">No attacks detected yet</div>
            ) : (
                <ResponsiveContainer width="100%" height={300}>
                    <BarChart data={chartData} layout="vertical" margin={{ left: 10, right: 20 }}>
                        <CartesianGrid strokeDasharray="3 3" stroke="#D9E4E1" />
                        <XAxis type="number" tick={{ fill: "#64748B", fontSize: 11 }} allowDecimals={false} />
                        <YAxis
                            type="category" dataKey="name" width={110}
                            tick={{ fill: "#64748B", fontSize: 11 }}
                        />
                        <Tooltip
                            contentStyle={{
                                background: "#FAFCFB", border: "1px solid #D9E4E1",
                                borderRadius: 10, fontSize: 12, color: "#24323A",
                            }}
                            cursor={{ fill: "#D9E4E188" }}
                        />
                        <Bar dataKey="value" radius={[0, 6, 6, 0]}>
                            {chartData.map((entry, i) => (
                                <Cell key={i} fill={attackColor(entry.name)} />
                            ))}
                        </Bar>
                    </BarChart>
                </ResponsiveContainer>
            )}
        </div>
    );
}

export default BarChartCard;
