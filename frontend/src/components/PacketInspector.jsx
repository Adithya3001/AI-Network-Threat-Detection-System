import { FaTimes, FaArrowRight } from "react-icons/fa";
import SeverityBadge from "./SeverityBadge";
import { formatConfidence } from "../constants";

function Field({ label, value }) {
    return (
        <div className="pi-field">
            <span>{label}</span>
            <strong>{value || "—"}</strong>
        </div>
    );
}

function PacketInspector({ record, onClose }) {
    if (!record) return null;

    return (
        <div className="modal-overlay" onClick={onClose}>
            <div className="modal" onClick={(e) => e.stopPropagation()}>
                <div className="modal-head">
                    <div>
                        <h3>Packet Inspector</h3>
                        <span className="modal-sub">Record #{record.id} · {record.timestamp}</span>
                    </div>
                    <button className="modal-close" onClick={onClose}><FaTimes /></button>
                </div>

                <div className="pi-verdict">
                    <span className={`badge-attack ${record.attack_type === "BENIGN" ? "is-benign" : ""}`}>
                        {record.attack_type}
                    </span>
                    <SeverityBadge severity={record.severity} />
                    <span className="pi-conf">{formatConfidence(record.confidence)}</span>
                </div>

                <div className="pi-connection">
                    <div className="pi-endpoint">
                        <span className="pi-label">Source</span>
                        <strong>{record.source_ip}</strong>
                        <span className="pi-port">:{record.source_port}</span>
                    </div>
                    <span className="pi-flow-arrow"><FaArrowRight /></span>
                    <div className="pi-endpoint">
                        <span className="pi-label">Destination</span>
                        <strong>{record.destination_ip}</strong>
                        <span className="pi-port">:{record.destination_port}</span>
                    </div>
                </div>

                <div className="pi-grid">
                    <Field label="Protocol" value={record.protocol} />
                    <Field label="TCP Flags" value={record.tcp_flags || "—"} />
                    <Field label="Packet Size" value={record.packet_size ? `${record.packet_size} B` : "—"} />
                    <Field label="Total Bytes" value={record.bytes ? `${(record.bytes).toLocaleString()} B` : "—"} />
                    <Field label="Confidence" value={formatConfidence(record.confidence)} />
                    <Field label="Attack Type" value={record.attack_type} />
                </div>

                {record.description && (
                    <div className="pi-description">
                        <strong>Analysis</strong>
                        <p>{record.description}</p>
                    </div>
                )}
            </div>
        </div>
    );
}

export default PacketInspector;
