import { severityColor } from "../constants";

function SeverityBadge({ severity = "None" }) {
    const color = severityColor(severity);
    return (
        <span
            className="severity-badge"
            style={{
                background: `${color}1a`,
                color,
                borderColor: `${color}55`,
            }}
        >
            <span className="severity-dot" style={{ background: color }} />
            {severity}
        </span>
    );
}

export default SeverityBadge;
