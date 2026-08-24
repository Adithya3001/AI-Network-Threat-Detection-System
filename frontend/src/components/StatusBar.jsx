import API from "../services/api";
import usePolling from "../hooks/usePolling";

function StatusBar() {
    const { data } = usePolling(async () => {
        const res = await API.get("/health");
        return res.data;
    }, 3000);

    const capture = data?.capture || {};
    const running = capture.running;
    const mode = capture.mode;

    return (
        <div className="status-bar">
            <div className="live-status">
                <span className={`live-dot ${running ? "" : "off"}`}></span>
                <span>{running ? (mode === "demo" ? "Demo Mode Running" : "Monitoring Active") : "Monitoring Paused"}</span>
                {running && <span className="pkt-count">{(capture.packets_seen || 0).toLocaleString()} packets</span>}
            </div>
            <div className="status-text">
                <span>AI Model: XGBoost</span>
                <span className="status-sep">•</span>
                <span>Auto-refresh every 2s</span>
            </div>
        </div>
    );
}

export default StatusBar;
