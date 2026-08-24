import {
    PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend,
} from "recharts";
import API from "../services/api";
import usePolling from "../hooks/usePolling";
import Loading from "./Loading";

const COLORS = ["#16A34A", "#DC2626"];

function PieChartCard() {
    const { data, loading } = usePolling(async () => {
        const res = await API.get("/stats");
        return res.data;
    }, 3000);

    const chartData = data
        ? [
            { name: "Benign", value: data.benign },
            { name: "Threats", value: data.attacks },
        ]
        : [];

    return (
        <div className="panel">
            <div className="panel-head">
                <h2>Traffic Distribution</h2>
                <span className="panel-badge">benign vs threat</span>
            </div>
            {loading && !data ? (
                <Loading />
            ) : (
                <ResponsiveContainer width="100%" height={300}>
                    <PieChart>
                        <Pie
                            data={chartData} dataKey="value" nameKey="name"
                            outerRadius={110} label
                        >
                            {chartData.map((entry, index) => (
                                <Cell key={index} fill={COLORS[index % COLORS.length]} />
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

export default PieChartCard;
