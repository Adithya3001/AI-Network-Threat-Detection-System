import {
    PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend,
} from "recharts";
import API from "../services/api";
import usePolling from "../hooks/usePolling";
import Loading from "./Loading";
import { attackColor } from "../constants";

function AttackPieChart() {
    const { data, loading } = usePolling(async () => {
        const res = await API.get("/top-attacks");
        return res.data;
    }, 3000);

    const chartData = (data || []).filter((a) => a.count > 0);

    return (
        <div className="panel">
            <div className="panel-head">
                <h2>Attack Distribution</h2>
                <span className="panel-badge">by type</span>
            </div>
            {loading && !data ? (
                <Loading />
            ) : chartData.length === 0 ? (
                <div className="empty-state">No attacks detected yet</div>
            ) : (
                <ResponsiveContainer width="100%" height={300}>
                    <PieChart>
                        <Pie
                            data={chartData} dataKey="count" nameKey="attack_type"
                            outerRadius={110} label
                        >
                            {chartData.map((entry, i) => (
                                <Cell key={i} fill={attackColor(entry.attack_type)} />
                            ))}
                        </Pie>
                        <Tooltip
                            contentStyle={{
                                background: "#FAFCFB", border: "1px solid #D9E4E1",
                                borderRadius: 10, fontSize: 12, color: "#24323A",
                            }}
                        />
                        <Legend wrapperStyle={{ fontSize: 12 }} />
                    </PieChart>
                </ResponsiveContainer>
            )}
        </div>
    );
}

export default AttackPieChart;
