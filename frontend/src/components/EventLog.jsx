import { FaNetworkWired, FaBoxOpen, FaCog, FaBrain, FaDatabase, FaInfoCircle } from "react-icons/fa";
import API from "../services/api";
import usePolling from "../hooks/usePolling";

const STAGE_ICONS = {
    "Packet Capture": <FaNetworkWired />,
    "Flow Created": <FaBoxOpen />,
    "Features Generated": <FaCog />,
    "AI Prediction": <FaBrain />,
    "Database Updated": <FaDatabase />,
    System: <FaInfoCircle />,
    Demo: <FaInfoCircle />,
};

const STAGE_COLORS = {
    "Packet Capture": "#0D9488",
    "Flow Created": "#7C3AED",
    "Features Generated": "#D97706",
    "AI Prediction": "#16A34A",
    "Database Updated": "#DB2777",
    System: "#64748B",
    Demo: "#94A3B8",
};

function EventLog() {
    const { data } = usePolling(async () => {
        const res = await API.get("/events");
        return res.data;
    }, 2500);

    const events = data || [];

    return (
        <div className="panel">
            <div className="panel-head">
                <h2>Live Event Log</h2>
                <span className="panel-badge">{events.length} events</span>
            </div>
            <div className="event-log">
                {events.length === 0 && <div className="empty-state">No events yet</div>}
                {events.map((e, i) => {
                    const color = STAGE_COLORS[e.stage] || "#64748b";
                    return (
                        <div className="event-row" key={`${e.id || i}`}>
                            <span className="event-time">{e.timestamp}</span>
                            <span className="event-stage" style={{ color, background: `${color}1a` }}>
                                {STAGE_ICONS[e.stage] || <FaInfoCircle />}
                                {e.stage}
                            </span>
                            <span className="event-msg">{e.message}</span>
                            {e.details && <span className="event-detail">{e.details}</span>}
                        </div>
                    );
                })}
            </div>
        </div>
    );
}

export default EventLog;
