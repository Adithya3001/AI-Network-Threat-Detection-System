import { FaBrain, FaDatabase, FaServer, FaNetworkWired, FaShieldAlt, FaCog, FaExclamationTriangle } from "react-icons/fa";
import API from "../services/api";
import usePolling from "../hooks/usePolling";
import SystemHealthPanel from "../components/SystemHealthPanel";

function SettingsRow({ icon: Icon, label, value }) {
    return (
        <div className="health-row">
            <span className="health-icon"><Icon /></span>
            <span className="health-label">{label}</span>
            <span className="health-detail">{value}</span>
        </div>
    );
}

function Settings() {
    const { data } = usePolling(async () => {
        const res = await API.get("/health");
        return res.data;
    }, 5000);

    const h = data || {};
    const model = h.model || {};
    const capture = h.capture || {};

    return (
        <div className="page">
            <div className="page-title">
                <div>
                    <h1>Settings</h1>
                    <p>System configuration and detection pipeline status.</p>
                </div>
            </div>

            <div className="grid-2">
                <SystemHealthPanel />

                <div className="panel">
                    <div className="panel-head">
                        <h2><FaCog className="inline-icon" /> Detection Configuration</h2>
                        <span className="panel-badge">read-only</span>
                    </div>
                    <div className="health-list">
                        <SettingsRow
                            icon={FaBrain}
                            label="AI Model"
                            value={`${model.name || "XGBoost"} · ${model.classes ? `${model.classes} classes` : ""}`}
                        />
                        <SettingsRow
                            icon={FaDatabase}
                            label="Database"
                            value={h.database === "ok" ? "connected · SQLite" : "offline"}
                        />
                        <SettingsRow
                            icon={FaServer}
                            label="API Server"
                            value={h.api === "online" ? "online · REST" : "offline"}
                        />
                        <SettingsRow
                            icon={FaNetworkWired}
                            label="Capture Mode"
                            value={capture.mode ? `${capture.mode} · ${capture.running ? "running" : "idle"}` : "idle"}
                        />
                        <SettingsRow
                            icon={FaExclamationTriangle}
                            label="Refresh Interval"
                            value="2s dashboard polling"
                        />
                    </div>
                    <div className="health-controls">
                        <span className="panel-badge"><FaShieldAlt /> Dashboard is protected by the XGBoost threat model</span>
                    </div>
                </div>
            </div>
        </div>
    );
}

export default Settings;