import { useMemo } from "react";
import API from "../services/api";
import usePolling from "../hooks/usePolling";
import { attackColor } from "../constants";

const W = 720;
const H = 360;
const CX = W / 2;
const CY = H / 2;

function NetworkTopology() {
    const { data } = usePolling(async () => {
        const res = await API.get("/active-connections");
        return res.data;
    }, 3000);

    const { localNodes, attackNodes } = useMemo(() => {
        const conns = data || [];
        const localSet = new Map();
        const atkSet = new Map();
        const isLocal = (ip) =>
            ip.startsWith("192.168.") || ip.startsWith("10.") ||
            ip.startsWith("172.16.") || ip === "127.0.0.1";

        for (const c of conns) {
            const local = isLocal(c.destination_ip) ? c.destination_ip : c.source_ip;
            const external = isLocal(c.destination_ip) ? c.source_ip : c.destination_ip;
            const isAttack = c.attack_type && c.attack_type !== "BENIGN";

            if (isAttack) {
                atkSet.set(external, {
                    ip: external, attack: c.attack_type,
                    count: (atkSet.get(external)?.count || 0) + c.packets,
                });
            }
            localSet.set(local, (localSet.get(local) || 0) + c.packets);
        }

        return {
            localNodes: [...localSet.entries()]
                .sort((a, b) => b[1] - a[1])
                .slice(0, 8),
            attackNodes: [...atkSet.values()].slice(0, 6),
        };
    }, [data]);

    // Distribute local nodes in a ring around the gateway
    const gateway = { x: CX, y: CY - 20, label: "Gateway", isGateway: true };

    const positionedLocal = localNodes.map(([ip, packets], i) => {
        const angle = (i / Math.max(localNodes.length, 1)) * Math.PI * 2 - Math.PI / 2;
        const radius = 120;
        return {
            ip, packets,
            x: CX + Math.cos(angle) * radius,
            y: CY - 20 + Math.sin(angle) * radius,
        };
    });

    const positionedAttacks = attackNodes.map((n, i) => {
        const angle = (i / Math.max(attackNodes.length, 1)) * Math.PI * 2 + Math.PI / 6;
        const radius = 250;
        return {
            ...n,
            x: CX + Math.cos(angle) * radius,
            y: CY - 20 + Math.sin(angle) * radius,
        };
    });

    return (
        <div className="panel">
            <div className="panel-head">
                <h2>Network Topology</h2>
                <span className="panel-badge">
                    {localNodes.length} devices · {attackNodes.length} external
                </span>
            </div>
            <div className="topology-wrap">
                <svg viewBox={`0 0 ${W} ${H}`} className="topology-svg">
                    <defs>
                        <radialGradient id="hubGrad" cx="50%" cy="50%" r="50%">
                            <stop offset="0%" stopColor="#0D9488" stopOpacity=".4" />
                            <stop offset="100%" stopColor="#0D9488" stopOpacity="0" />
                        </radialGradient>
                        <radialGradient id="atkGrad" cx="50%" cy="50%" r="50%">
                            <stop offset="0%" stopColor="#DC2626" stopOpacity=".35" />
                            <stop offset="100%" stopColor="#DC2626" stopOpacity="0" />
                        </radialGradient>
                    </defs>

                    {/* hub glow */}
                    <circle cx={gateway.x} cy={gateway.y} r={90} fill="url(#hubGrad)" />
                    <circle cx={gateway.x} cy={gateway.y} r={200} fill="url(#hubGrad)" opacity=".5" />

                    {/* external attack glows */}
                    {positionedAttacks.map((n, i) => (
                        <circle key={`g${i}`} cx={n.x} cy={n.y} r={60} fill="url(#atkGrad)" />
                    ))}

                    {/* local device lines */}
                    {positionedLocal.map((n, i) => (
                        <line
                            key={`l${i}`}
                            x1={gateway.x} y1={gateway.y}
                            x2={n.x} y2={n.y}
                            stroke="#16A34A" strokeOpacity=".35" strokeWidth="2"
                        />
                    ))}

                    {/* attack lines */}
                    {positionedAttacks.map((n, i) => (
                        <line
                            key={`a${i}`}
                            x1={gateway.x} y1={gateway.y}
                            x2={n.x} y2={n.y}
                            stroke="#DC2626" strokeOpacity=".45"
                            strokeWidth="2" strokeDasharray="5 4"
                        />
                    ))}

                    {/* gateway node */}
                    <circle cx={gateway.x} cy={gateway.y} r={26} fill="#FAFCFB" stroke="#0D9488" strokeWidth="3" />
                    <text x={gateway.x} y={gateway.y + 4} textAnchor="middle" fill="#0D9488" fontSize="11" fontWeight="bold">NET</text>
                    <text x={gateway.x} y={gateway.y - 34} textAnchor="middle" fill="#64748B" fontSize="11">Local Network</text>

                    {/* local device nodes */}
                    {positionedLocal.map((n, i) => (
                        <g key={`ln${i}`}>
                            <circle cx={n.x} cy={n.y} r={18} fill="#FAFCFB" stroke="#16A34A" strokeWidth="2.5" />
                            <text x={n.x} y={n.y + 4} textAnchor="middle" fill="#15803D" fontSize="8" fontWeight="bold">
                                {n.ip.split(".")[3]}
                            </text>
                            <text x={n.x} y={n.y + 34} textAnchor="middle" fill="#64748B" fontSize="9">{n.ip}</text>
                        </g>
                    ))}

                    {/* attack nodes */}
                    {positionedAttacks.map((n, i) => (
                        <g key={`an${i}`}>
                            <circle cx={n.x} cy={n.y} r={20} fill="#FAFCFB" stroke={attackColor(n.attack)} strokeWidth="3" />
                            <text x={n.x} y={n.y + 4} textAnchor="middle" fill="#DC2626" fontSize="9" fontWeight="bold">⚠</text>
                            <text x={n.x} y={n.y + 38} textAnchor="middle" fill="#64748B" fontSize="9">{n.ip}</text>
                            <text x={n.x} y={n.y + 52} textAnchor="middle" fill={attackColor(n.attack)} fontSize="8" fontWeight="bold">
                                {n.attack}
                            </text>
                        </g>
                    ))}
                </svg>
                <div className="topology-legend">
                    <span><i style={{ background: "#16A34A" }} />Local devices</span>
                    <span><i style={{ background: "#DC2626" }} />Attack sources</span>
                </div>
            </div>
        </div>
    );
}

export default NetworkTopology;
