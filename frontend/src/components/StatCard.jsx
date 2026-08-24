function StatCard({ icon: Icon, label, value, sub, tone = "teal" }) {
    const tones = {
        teal: { accent: "#0D9488", bg: "rgba(13,148,136,.12)" },
        green: { accent: "#16A34A", bg: "rgba(22,163,74,.12)" },
        red: { accent: "#DC2626", bg: "rgba(220,38,38,.12)" },
        amber: { accent: "#D97706", bg: "rgba(217,119,6,.12)" },
        purple: { accent: "#7C3AED", bg: "rgba(124,58,237,.12)" },
    };
    const t = tones[tone] || tones.teal;

    return (
        <div className="stat-card">
            <div className="stat-icon" style={{ background: t.bg, color: t.accent }}>
                <Icon />
            </div>
            <div className="stat-info">
                <h3>{label}</h3>
                <div className="stat-value" style={{ color: t.accent }}>{value}</div>
                {sub && <p className="stat-sub">{sub}</p>}
            </div>
        </div>
    );
}

export default StatCard;
