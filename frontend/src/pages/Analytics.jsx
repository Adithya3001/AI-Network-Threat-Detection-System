import PieChartCard from "../components/PieChartCard";
import BarChartCard from "../components/BarChartCard";
import AttackPieChart from "../components/AttackPieChart";
import AttackTrendGraph from "../components/AttackTrendGraph";
import TopTalkers from "../components/TopTalkers";
import ProtocolDonut from "../components/ProtocolDonut";

function Analytics() {
    return (
        <div className="page">
            <div className="page-title">
                <div>
                    <h1>Analytics</h1>
                    <p>Statistical insights across all detected traffic and attacks.</p>
                </div>
            </div>

            <div className="grid-2">
                <PieChartCard />
                <AttackPieChart />
            </div>

            <AttackTrendGraph />

            <div className="grid-2">
                <BarChartCard />
                <TopTalkers />
            </div>

            <div className="grid-2">
                <ProtocolDonut />
            </div>
        </div>
    );
}

export default Analytics;
