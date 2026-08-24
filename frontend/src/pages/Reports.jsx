import LiveTrafficGraph from "../components/LiveTrafficGraph";
import AttackTrendGraph from "../components/AttackTrendGraph";
import AttackPieChart from "../components/AttackPieChart";
import BarChartCard from "../components/BarChartCard";
import TopTalkers from "../components/TopTalkers";
import ProtocolDonut from "../components/ProtocolDonut";

function Reports() {
    return (
        <div className="page">
            <div className="page-title">
                <div>
                    <h1>Reports</h1>
                    <p>Security reports and trend analysis across all monitored traffic.</p>
                </div>
            </div>

            <LiveTrafficGraph />

            <div className="grid-2">
                <AttackTrendGraph />
                <AttackPieChart />
            </div>

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

export default Reports;