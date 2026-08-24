import { useEffect, useRef, useState } from "react";
import { FaExclamationTriangle, FaTimes } from "react-icons/fa";
import API from "../services/api";
import { formatConfidence, attackColor } from "../constants";

function Notification() {
    const [alert, setAlert] = useState(null);
    const lastAttackId = useRef(null);
    const timeoutRef = useRef(null);

    async function checkThreat() {
        try {
            const response = await API.get("/latest-threat");
            const threat = response.data;

            if (!threat.id) return;

            if (lastAttackId.current === null) {
                lastAttackId.current = threat.id;
                return;
            }

            if (threat.id !== lastAttackId.current) {
                lastAttackId.current = threat.id;
                setAlert(threat);
                timeoutRef.current = setTimeout(() => setAlert(null), 6000);
            }
        } catch (error) {
            console.error(error);
        }
    }

    useEffect(() => {
        const init = setTimeout(checkThreat, 0);
        const timer = setInterval(checkThreat, 2000);
        return () => {
            clearTimeout(init);
            clearInterval(timer);
            clearTimeout(timeoutRef.current);
        };
    }, []);

    if (!alert) return null;

    const color = attackColor(alert.attack_type);

    return (
        <div className="notification" style={{ borderLeft: `4px solid ${color}` }}>
            <button className="notif-close" onClick={() => setAlert(null)}><FaTimes /></button>
            <div className="notif-head">
                <FaExclamationTriangle style={{ color }} />
                <h3>Attack Detected</h3>
            </div>
            <p className="notif-type" style={{ color }}>{alert.attack_type}</p>
            <div className="notif-conn">
                <span>{alert.source_ip}</span>
                <span className="notif-arrow">→</span>
                <span>{alert.destination_ip}</span>
            </div>
            <p className="notif-conf">Confidence: <strong>{formatConfidence(alert.confidence)}</strong> · Severity: <strong>{alert.severity}</strong></p>
        </div>
    );
}

export default Notification;
