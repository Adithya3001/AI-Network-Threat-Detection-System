import { FaChartLine, FaShieldAlt, FaExclamationTriangle, FaBell } from "react-icons/fa";
import API from "../services/api";
import usePolling from "../hooks/usePolling";
import StatCard from "./StatCard";

function StatsCards() {
    const { data } = usePolling(async () => {
        const res = await API.get("/stats");
        return res.data;
    }, 2000);

    const { data: alerts } = usePolling(async () => {
        const res = await API.get("/alerts", { params: { limit: 50 } });
        return res.data;
    }, 3000);

    const stats = data || {};
    const activeAlerts = Array.isArray(alerts) ? alerts.length : 0;

    return (
        <div className="cards cards-4">
            <StatCard
                icon={FaChartLine}
                label="Total Predictions"
                value={(stats.total_predictions ?? 0).toLocaleString()}
                sub="analysed flows"
                tone="teal"
            />
            <StatCard
                icon={FaShieldAlt}
                label="Benign Traffic"
                value={(stats.benign ?? 0).toLocaleString()}
                sub="normal flows"
                tone="green"
            />
            <StatCard
                icon={FaExclamationTriangle}
                label="Threats Detected"
                value={(stats.attacks ?? 0).toLocaleString()}
                sub="malicious flows"
                tone="red"
            />
            <StatCard
                icon={FaBell}
                label="Active Alerts"
                value={activeAlerts.toLocaleString()}
                sub="recent alerts"
                tone="amber"
            />
        </div>
    );
}

export default StatsCards;