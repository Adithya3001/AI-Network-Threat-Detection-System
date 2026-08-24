import threading
import time
from scapy.all import TCP

# Stores active flows (5-tuple -> flow state)
flows = {}

# Guards the flows dict: the packet-capture thread and the background
# flow-predictor thread access it at the same time.
flow_lock = threading.Lock()


def get_flow(packet, src_ip, dst_ip, src_port, dst_port, protocol):

    flow_key = (src_ip, dst_ip, src_port, dst_port, protocol)
    reverse_key = (dst_ip, src_ip, dst_port, src_port, protocol)

    current_time = time.time()

    with flow_lock:

        if flow_key in flows:
            flow = flows[flow_key]
            direction = "FWD"

        elif reverse_key in flows:
            flow = flows[reverse_key]
            direction = "BWD"

        else:
            flow = {
                "start_time": current_time,
                "last_seen": current_time,

                "destination_port": dst_port,
                "protocol": protocol,

                # Packet counters
                "fwd_packets": 0,
                "bwd_packets": 0,

                # Byte counters
                "fwd_bytes": 0,
                "bwd_bytes": 0,

                # Packet lengths
                "fwd_lengths": [],
                "bwd_lengths": [],
                "all_lengths": [],

                # Packet timestamps
                "all_times": [],
                "fwd_times": [],
                "bwd_times": [],

                # IAT
                "fwd_iat": [],
                "bwd_iat": [],

                # TCP Flags
                "FIN": 0,
                "SYN": 0,
                "RST": 0,
                "PSH": 0,
                "ACK": 0,
                "URG": 0,
                "ECE": 0,
                "CWE": 0,

                # Header lengths
                "fwd_header_length": 0,
                "bwd_header_length": 0,

                # Initial TCP Window
                "init_window_fwd": 0,
                "init_window_bwd": 0,

                # Active / Idle times
                "active_times": [],
                "idle_times": [],

                # Last observed TCP flags (for the alert table)
                "tcp_flags": "",

                # Canonical 5-tuple key this flow is stored under
                "flow_key": flow_key,
            }

            flows[flow_key] = flow
            direction = "FWD"

        # -----------------------------
        # Active / Idle Time Tracking
        # -----------------------------
        gap = current_time - flow["last_seen"]

        if flow["last_seen"] != flow["start_time"]:
            if gap <= 1:
                flow["active_times"].append(gap)
            else:
                flow["idle_times"].append(gap)

        # Update timestamps
        flow["last_seen"] = current_time
        flow["all_times"].append(current_time)

        # Packet length
        packet_length = len(packet)
        flow["all_lengths"].append(packet_length)

        # -----------------------------
        # Forward Direction
        # -----------------------------
        if direction == "FWD":

            if len(flow["fwd_times"]) > 0:
                flow["fwd_iat"].append(
                    current_time - flow["fwd_times"][-1]
                )

            flow["fwd_times"].append(current_time)

            flow["fwd_packets"] += 1
            flow["fwd_bytes"] += packet_length
            flow["fwd_lengths"].append(packet_length)

        # -----------------------------
        # Backward Direction
        # -----------------------------
        else:

            if len(flow["bwd_times"]) > 0:
                flow["bwd_iat"].append(
                    current_time - flow["bwd_times"][-1]
                )

            flow["bwd_times"].append(current_time)

            flow["bwd_packets"] += 1
            flow["bwd_bytes"] += packet_length
            flow["bwd_lengths"].append(packet_length)

        # -----------------------------
        # TCP Features
        # -----------------------------
        if TCP in packet:

            tcp = packet[TCP]
            flags = tcp.flags

            if flags.F:
                flow["FIN"] += 1

            if flags.S:
                flow["SYN"] += 1

            if flags.R:
                flow["RST"] += 1

            if flags.P:
                flow["PSH"] += 1

            if flags.A:
                flow["ACK"] += 1

            if flags.U:
                flow["URG"] += 1

            if flags.E:
                flow["ECE"] += 1

            # CWR Flag
            if hasattr(flags, "C") and flags.C:
                flow["CWE"] += 1

            dataofs = getattr(tcp, "dataofs", None)
            if dataofs is None:
                dataofs = 5
            header_length = dataofs * 4

            if direction == "FWD":

                flow["fwd_header_length"] += header_length

                if flow["init_window_fwd"] == 0:
                    flow["init_window_fwd"] = tcp.window

            else:

                flow["bwd_header_length"] += header_length

                if flow["init_window_bwd"] == 0:
                    flow["init_window_bwd"] = tcp.window

            flow["tcp_flags"] = str(flags)

    return flow


def prune_stale_flows(max_age=120.0, lock_held=False):
    """Drop flows that have not seen a packet for `max_age` seconds.

    Keeps the flows dict from growing without bound during a long capture.
    """
    now = time.time()
    stale = [k for k, f in flows.items() if now - f["last_seen"] > max_age]

    if not stale:
        return

    if lock_held:
        for k in stale:
            del flows[k]
    else:
        with flow_lock:
            for k in stale:
                del flows[k]