import { useEffect, useState } from "react";
import { FaShieldAlt } from "react-icons/fa";

function Header() {
    const [now, setNow] = useState(new Date());

    useEffect(() => {
        const timer = setInterval(() => setNow(new Date()), 1000);
        return () => clearInterval(timer);
    }, []);

    return (
        <header className="header">
            <div className="logo">
                <div className="logo-icon-wrap">
                    <FaShieldAlt className="logo-icon" />
                </div>
                <div>
                    <h1>AI Network Threat Detection</h1>
                    <p>Real-Time Intrusion Detection & SOC Dashboard</p>
                </div>
            </div>
            <div className="header-clock">
                <span className="clock-date">
                    {now.toLocaleDateString(undefined, { weekday: "short", day: "numeric", month: "short", year: "numeric" })}
                </span>
                <span className="clock-time">
                    {now.toLocaleTimeString()}
                </span>
            </div>
        </header>
    );
}

export default Header;
