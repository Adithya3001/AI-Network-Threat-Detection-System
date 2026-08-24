import { FaShieldAlt, FaReact, FaPython, FaDatabase, FaBrain, FaNetworkWired, FaChartBar } from "react-icons/fa";

const STACK = [
    { icon: FaReact, name: "React + Vite", role: "Frontend dashboard" },
    { icon: FaPython, name: "FastAPI", role: "REST API backend" },
    { icon: FaBrain, name: "XGBoost", role: "AI classification model" },
    { icon: FaNetworkWired, name: "Scapy", role: "Live packet capture" },
    { icon: FaDatabase, name: "SQLite", role: "Prediction storage" },
    { icon: FaChartBar, name: "Recharts", role: "Visual analytics" },
];

const FEATURES = [
    "Live packet capture over Wi-Fi",
    "Automatic 5-tuple flow builder",
    "78-feature CICIDS2017 extraction",
    "XGBoost multiclass threat classification",
    "Confidence scoring with severity levels",
    "Real-time SOC-style monitoring dashboard",
    "Live traffic & attack trend graphs",
    "AI decision explainability panel",
    "Event-driven pipeline logging",
    "Demo mode for showcasing attacks",
    "CSV export, search and filtering",
];

const PAGES = [
    { name: "Dashboard", desc: "Overview of threat level, live traffic, AI decisions and system health." },
    { name: "Monitoring", desc: "Real-time packet inspector with search, filter and export." },
    { name: "Analytics", desc: "Traffic distribution, attack vectors and trends." },
    { name: "Alerts", desc: "Full alert history with severity classification and details." },
    { name: "Network Map", desc: "Topology visualization and active connections." },
];

function About() {
    return (
        <div className="page">
            <div className="page-title">
                <div>
                    <h1>About the Project</h1>
                    <p>AI-Based Network Threat Detection System.</p>
                </div>
            </div>

            <div className="about-hero">
                <div className="about-hero-icon"><FaShieldAlt /></div>
                <div>
                    <h2>AI Network Threat Detection System</h2>
                    <p>
                        A real-time intrusion detection platform that captures live network traffic,
                        builds network flows, extracts 78 machine-learning features and classifies each
                        flow using an XGBoost model trained on the CICIDS2017 dataset. Detections are
                        stored in SQLite, served through a FastAPI REST API and visualised in a
                        professional SOC-style React dashboard.
                    </p>
                </div>
            </div>

            <h3 className="about-section">Technology Stack</h3>
            <div className="stack-grid">
                {STACK.map(({ icon: Icon, name, role }) => (
                    <div className="stack-card" key={name}>
                        <div className="stack-icon"><Icon /></div>
                        <div>
                            <strong>{name}</strong>
                            <span>{role}</span>
                        </div>
                    </div>
                ))}
            </div>

            <h3 className="about-section">Model & Dataset</h3>
            <div className="about-model">
                <div className="about-model-card">
                    <strong>Dataset</strong>
                    <p>CICIDS2017 — a benchmark intrusion dataset covering normal traffic plus attacks such as PortScan, FTP-Patator, SSH-Patator, Bot, DoS Hulk, DoS GoldenEye and web attacks.</p>
                </div>
                <div className="about-model-card">
                    <strong>Model</strong>
                    <p>XGBoost multiclass classifier (78 features) reaching ~99.8% accuracy on the evaluation split, with per-class confidence scoring.</p>
                </div>
            </div>

            <h3 className="about-section">Features Implemented</h3>
            <div className="feature-list">
                {FEATURES.map((f, i) => (
                    <div className="feature-item" key={i}><span>✓</span>{f}</div>
                ))}
            </div>

            <h3 className="about-section">Dashboard Pages</h3>
            <div className="pages-grid">
                {PAGES.map((p) => (
                    <div className="about-page-card" key={p.name}>
                        <strong>{p.name}</strong>
                        <p>{p.desc}</p>
                    </div>
                ))}
            </div>
        </div>
    );
}

export default About;
