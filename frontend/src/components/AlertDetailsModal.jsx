import { FaTimes, FaExclamationTriangle, FaArrowRight } from "react-icons/fa";
import SeverityBadge from "./SeverityBadge";
import { formatConfidence, attackColor } from "../constants";

function AlertDetailsModal({ alert, onClose }) {
    if (!alert) return null;

    return (
        <div className="modal-overlay" onClick={onClose}>
            <div className="modal" onClick={(e) => e.stopPropagation()}>
                <div className="modal-head">
                    <div>
                        <h3><FaExclamationTriangle className="inline-icon" /> Alert Details</h3>
                        <span className="modal-sub">Alert #{alert.id} · {alert.timestamp}</span>
                    </div>
                    <button className="modal-close" onClick={onClose}><FaTimes /></button>
                </div>

                <div className="alert-hero" style={{ borderLeft: `4px solid ${attackColor(alert.attack_type)}` }}>
                    <div>
                        <span className="alert-hero-type">{alert.attack_type}</span>
                        <span className="alert-hero-conn">
                            {alert.source_ip}:{alert.source_port}
                            <FaArrowRight className="mini-arrow" />
                            {alert.destination_ip}:{alert.destination_port}
                        </span>
                    </div>
                    <div className="alert-hero-meta">
                        <SeverityBadge severity={alert.severity} />
                        <span className="alert-hero-conf">{formatConfidence(alert.confidence)}</span>
                    </div>
                </div>

                <div className="pi-grid">
                    <div className="pi-field"><span>Protocol</span><strong>{alert.protocol}</strong></div>
                    <div className="pi-field"><span>Source Port</span><strong>{alert.source_port}</strong></div>
                    <div className="pi-field"><span>Destination Port</span><strong>{alert.destination_port}</strong></div>
                    <div className="pi-field"><span>TCP Flags</span><strong>{alert.tcp_flags || "—"}</strong></div>
                    <div className="pi-field"><span>Packet Size</span><strong>{alert.packet_size || "—"}</strong></div>
                    <div className="pi-field"><span>Total Bytes</span><strong>{alert.bytes ? alert.bytes.toLocaleString() : "—"}</strong></div>
                    {alert.scanned_ports > 0 && (
                        <div className="pi-field"><span>Ports Scanned</span><strong>{alert.scanned_ports}</strong></div>
                    )}
                </div>

                {alert.description && (
                    <div className="pi-description">
                        <strong>What does this mean?</strong>
                        <p>{alert.description}</p>
                    </div>
                )}
            </div>
        </div>
    );
}

export default AlertDetailsModal;
