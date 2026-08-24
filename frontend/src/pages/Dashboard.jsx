import StatsCards from "../components/StatsCards";
import StatusBar from "../components/StatusBar";
import ThreatLevel from "../components/ThreatLevel";
import LatestThreat from "../components/LatestThreat";
import LiveTrafficGraph from "../components/LiveTrafficGraph";
import AIDecisionPanel from "../components/AIDecisionPanel";
import RecentAlertsPanel from "../components/RecentAlertsPanel";
import EventLog from "../components/EventLog";
import SystemHealthPanel from "../components/SystemHealthPanel";
import AlertDetailsModal from "../components/AlertDetailsModal";
import { useState } from "react";

function Dashboard() {
    const [alertDetail, setAlertDetail] = useState(null);

    return (
        <>
            <StatusBar />

            <StatsCards />

            <div className="grid-3">
                <ThreatLevel />
                <LatestThreat />
                <SystemHealthPanel />
            </div>

            <LiveTrafficGraph />

            <div className="grid-2">
                <AIDecisionPanel />
                <RecentAlertsPanel onOpen={setAlertDetail} />
            </div>

            <div className="grid-2">
                <EventLog />
                <div className="panel">
                    <div className="panel-head">
                        <h2>Pipeline</h2>
                        <span className="panel-badge">processing chain</span>
                    </div>
                    <div className="pipeline">
                        {[
                            { n: 1, t: "Packet Capture", d: "Scapy sniffs live traffic on the network interface" },
                            { n: 2, t: "Flow Builder", d: "Packets grouped into 5-tuple flows (fwd / bwd)" },
                            { n: 3, t: "Feature Generator", d: "78 CICIDS2017 features extracted per flow" },
                            { n: 4, t: "XGBoost Classifier", d: "Trained on CICIDS2017 (99.8% accuracy)" },
                            { n: 5, t: "SQLite Storage", d: "Predictions persisted with confidence & severity" },
                            { n: 6, t: "Dashboard Update", d: "React SOC dashboard refreshes every 2s" },
                        ].map((step) => (
                            <div className="pipeline-step" key={step.n}>
                                <span className="pipe-num">{step.n}</span>
                                <div>
                                    <strong>{step.t}</strong>
                                    <p>{step.d}</p>
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            </div>

            <AlertDetailsModal alert={alertDetail} onClose={() => setAlertDetail(null)} />
        </>
    );
}

export default Dashboard;
