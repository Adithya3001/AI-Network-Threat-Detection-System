import {
    PieChart, Pie, Cell, Tooltip, ResponsiveContainer,
} from "recharts";
import API from "../services/api";
import usePolling from "../hooks/usePolling";
import Loading from "./Loading";

const COLORS = ["#0D9488", "#7C3AED", "#D97706"];
const LABELS = { TCP: "TCP", UDP: "UDP", OTHER: "Other" };

function ProtocolDonut() {
    const { data, loading } = usePolling(async () => {
        const res = await API.get("/protocols");
        return res.data;
    }, 3000);

    const chartData = (data || [])
        .map((p) => ({ name: LABELS[p.protocol] || p.protocol, value: p.count }))
        .filter((p) => p.value > 0);

    const total = chartData.reduce((s, d) => s + d.value, 0);

    return (
        <div className="panel">
            <div className="panel-head">
                <h2>Protocol Distribution</h2>
                <span className="panel-badge">{total} flows</span>
            </div>
            {loading && !data ? (
                <Loading />
            ) : (
                <div className="donut-wrap">
                    <ResponsiveContainer width="100%" height={220}>
                        <PieChart>
                            <Pie
                                data={chartData} dataKey="value"
                                innerRadius={55} outerRadius={85}
                                paddingAngle={3} strokeWidth={0}
                            >
                                {chartData.map((entry, i) => (
                                    <Cell key={i} fill={COLORS[i % COLORS.length]} />
                                ))}
                            </Pie>
                            <Tooltip
                                contentStyle={{
                                    background: "#FAFCFB", border: "1px solid #D9E4E1",
                                    borderRadius: 10, fontSize: 12, color: "#24323A",
                                }}
                            />
                        </PieChart>
                    </ResponsiveContainer>
                    <div className="donut-center">
                        <strong>{total.toLocaleString()}</strong>
                        <span>flows</span>
                    </div>
                    <div className="protocol-legend">
                        {chartData.map((d, i) => (
                            <div className="proto-row" key={d.name}>
                                <span><i style={{ background: COLORS[i % COLORS.length] }} />{d.name}</span>
                                <strong>{d.value.toLocaleString()}</strong>
                            </div>
                        ))}
                    </div>
                </div>
            )}
        </div>
    );
}

export default ProtocolDonut;
