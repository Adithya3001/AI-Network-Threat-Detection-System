import LiveTable from "../components/LiveTable";
import LiveTrafficGraph from "../components/LiveTrafficGraph";
import ProtocolDonut from "../components/ProtocolDonut";
import TrafficTable from "../components/TrafficTable";
import EventLog from "../components/EventLog";
import AIDecisionPanel from "../components/AIDecisionPanel";
import PacketInspector from "../components/PacketInspector";
import { useState } from "react";

function Monitoring() {
    const [inspector, setInspector] = useState(null);

    return (
        <div className="page">
            <div className="page-title">
                <div>
                    <h1>Live Monitoring</h1>
                    <p>Real-time packet inspection and classification pipeline.</p>
                </div>
            </div>

            <div className="monitor-grid">
                <LiveTable onOpen={setInspector} />
                <ProtocolDonut />
            </div>

            <LiveTrafficGraph />

            <TrafficTable />

            <div className="grid-2">
                <AIDecisionPanel />
                <EventLog />
            </div>

            <PacketInspector record={inspector} onClose={() => setInspector(null)} />
        </div>
    );
}

export default Monitoring;
