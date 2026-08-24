import { FaServer, FaDatabase, FaBrain, FaNetworkWired, FaPlay, FaStop, FaFlask } from "react-icons/fa";
import API from "../services/api";
import usePolling from "../hooks/usePolling";

function HealthRow({ icon: Icon, label, ok, detail }) {
    return (
        <div className="health-row">
            <span className="health-icon"><Icon /></span>
            <span className="health-label">{label}</span>
            <span className="health-detail">{detail}</span>
            <span className={`health-dot ${ok ? "ok" : "bad"}`} />
        </div>
    );
}

function SystemHealthPanel() {
    const { data } = usePolling(async () => {
        const res = await API.get("/health");
        return res.data;
    }, 3000);

    const h = data || {};
    const capture = h.capture || {};
    const running = capture.running;
    const mode = capture.mode;

    async function control(action) {
        try {
            if (action === "demo") await API.post("/demo/start");
            if (action === "demo-stop") await API.post("/demo/stop");
            if (action === "live") await API.post("/capture/start");
            if (action === "live-stop") await API.post("/capture/stop");
        } catch (err) {
            console.error(err);
        }
    }

    return (
        <div className="panel">
            <div className="panel-head">
                <h2>System Health</h2>
                <span className={`live-dot ${running ? "" : "off"}`} />
            </div>

            <div className="health-list">
                <HealthRow icon={FaServer} label="API Server" ok={h.api === "online"} detail={h.api} />
                <HealthRow icon={FaDatabase} label="Database" ok={h.database === "ok"} detail={h.database} />
                <HealthRow
                    icon={FaBrain} label="AI Model"
                    ok={h.model?.loaded} detail={`${h.model?.name || "XGBoost"} · ${h.model?.loaded ? "loaded" : "missing"}`}
                />
                <HealthRow
                    icon={FaNetworkWired}
                    label={mode === "demo" ? "Demo Generator" : "Packet Capture"}
                    ok={running}
                    detail={running ? `${mode} · ${(capture.packets_seen || 0).toLocaleString()} packets` : "idle"}
                />
            </div>

            <div className="health-controls">
                {!running ? (
                    <>
                        <button className="btn btn-primary" onClick={() => control("live")}>
                            <FaPlay /> Start Live Capture
                        </button>
                        <button className="btn btn-demo" onClick={() => control("demo")}>
                            <FaFlask /> Start Demo Mode
                        </button>
                    </>
                ) : (
                    <button className="btn btn-danger" onClick={() => control(mode === "demo" ? "demo-stop" : "live-stop")}>
                        <FaStop /> Stop {mode === "demo" ? "Demo" : "Capture"}
                    </button>
                )}
            </div>

            {capture.error && <div className="health-error">{capture.error}</div>}
        </div>
    );
}

export default SystemHealthPanel;
