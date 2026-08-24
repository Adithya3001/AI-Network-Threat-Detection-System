import { useMemo } from "react";
import { FaDesktop, FaNetworkWired, FaGlobeAmericas, FaServer } from "react-icons/fa";
import API from "../services/api";
import usePolling from "../hooks/usePolling";
import StatCard from "../components/StatCard";
import NetworkTopology from "../components/NetworkTopology";
import ActiveConnections from "../components/ActiveConnections";
import ProtocolDonut from "../components/ProtocolDonut";

function NetworkMap() {
    const { data } = usePolling(async () => {
        const res = await API.get("/history", { params: { limit: 300 } });
        return res.data;
    }, 3000);

    const history = useMemo(() => data || [], [data]);

    const stats = useMemo(() => {
        const history = data || [];
        const localSet = new Set();
        const extSet = new Set();
        const isLocal = (ip) =>
            ip.startsWith("192.168.") || ip.startsWith("10.") ||
            ip.startsWith("172.16.") || ip === "127.0.0.1";

        history.forEach((r) => {
            if (isLocal(r.source_ip)) localSet.add(r.source_ip);
            else extSet.add(r.source_ip);
            if (isLocal(r.destination_ip)) localSet.add(r.destination_ip);
            else extSet.add(r.destination_ip);
        });

        return {
            local: localSet.size,
            external: extSet.size,
            total: history.length,
        };
    }, [data]);

    return (
        <div className="page">
            <div className="page-title">
                <div>
                    <h1>Network Overview</h1>
                    <p>Topology, local devices and active source-to-destination connections.</p>
                </div>
            </div>

            <div className="cards cards-4">
                <StatCard icon={FaDesktop} label="Local Devices" value={stats.local} sub="192.168.x.x hosts" tone="green" />
                <StatCard icon={FaServer} label="External Hosts" value={stats.external} sub="internet peers" tone="amber" />
                <StatCard icon={FaNetworkWired} label="Connections" value={history.length.toLocaleString()} sub="recent flows" tone="blue" />
                <StatCard icon={FaGlobeAmericas} label="Topology" value="Live" sub="auto-updating" tone="purple" />
            </div>

            <NetworkTopology />

            <div className="grid-2">
                <ActiveConnections />
                <ProtocolDonut />
            </div>
        </div>
    );
}

export default NetworkMap;
