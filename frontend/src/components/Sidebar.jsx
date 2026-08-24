import { NavLink } from "react-router-dom";
import {
    FaHome, FaNetworkWired, FaChartBar, FaBell, FaGlobeAmericas,
    FaFileAlt, FaCog, FaInfoCircle, FaShieldAlt,
} from "react-icons/fa";

const LINKS = [
    { to: "/", end: true, icon: FaHome, label: "Dashboard" },
    { to: "/monitoring", end: false, icon: FaNetworkWired, label: "Monitoring" },
    { to: "/analytics", end: false, icon: FaChartBar, label: "Analytics" },
    { to: "/alerts", end: false, icon: FaBell, label: "Alerts" },
    { to: "/network", end: false, icon: FaGlobeAmericas, label: "Network Map" },
    { to: "/reports", end: false, icon: FaFileAlt, label: "Reports" },
    { to: "/settings", end: false, icon: FaCog, label: "Settings" },
    { to: "/about", end: false, icon: FaInfoCircle, label: "About" },
];

function Sidebar() {
    return (
        <div className="sidebar">
            <div className="sidebar-logo">
                <div className="sidebar-logo-icon"><FaShieldAlt /></div>
            </div>

            <nav>
                {LINKS.map(({ to, end, icon: Icon, label }) => (
                    <NavLink to={to} end={end} key={to}>
                        <Icon />
                        <span>{label}</span>
                    </NavLink>
                ))}
            </nav>

            <div className="sidebar-footer">
                <div className="sidebar-shield">
                    <FaShieldAlt />
                    <span>Protected by XGBoost</span>
                </div>
            </div>
        </div>
    );
}

export default Sidebar;
