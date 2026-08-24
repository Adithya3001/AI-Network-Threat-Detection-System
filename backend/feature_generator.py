import numpy as np


def safe_mean(values):
    return float(np.mean(values)) if len(values) > 0 else 0.0


def safe_std(values):
    return float(np.std(values)) if len(values) > 1 else 0.0


def safe_min(values):
    return float(np.min(values)) if len(values) > 0 else 0.0


def safe_max(values):
    return float(np.max(values)) if len(values) > 0 else 0.0


def safe_sum(values):
    return float(np.sum(values)) if len(values) > 0 else 0.0


def generate_features(flow):

    duration = flow["last_seen"] - flow["start_time"]

    if duration <= 0:
        duration = 1e-6

    total_packets = flow["fwd_packets"] + flow["bwd_packets"]
    total_bytes = flow["fwd_bytes"] + flow["bwd_bytes"]

    # -------- Flow IAT --------

    if len(flow["all_times"]) > 1:
        flow_iat = np.diff(flow["all_times"])
    else:
        flow_iat = []

    features = {}

    # 1
    features["Destination Port"] = flow["destination_port"]

    # 2
    features["Flow Duration"] = duration

    # 3
    features["Total Fwd Packets"] = flow["fwd_packets"]

    # 4
    features["Total Backward Packets"] = flow["bwd_packets"]

    # 5
    features["Total Length of Fwd Packets"] = flow["fwd_bytes"]

    # 6
    features["Total Length of Bwd Packets"] = flow["bwd_bytes"]

    # 7
    features["Fwd Packet Length Max"] = safe_max(flow["fwd_lengths"])

    # 8
    features["Fwd Packet Length Min"] = safe_min(flow["fwd_lengths"])

    # 9
    features["Fwd Packet Length Mean"] = safe_mean(flow["fwd_lengths"])

    # 10
    features["Fwd Packet Length Std"] = safe_std(flow["fwd_lengths"])

    # 11
    features["Bwd Packet Length Max"] = safe_max(flow["bwd_lengths"])

    # 12
    features["Bwd Packet Length Min"] = safe_min(flow["bwd_lengths"])

    # 13
    features["Bwd Packet Length Mean"] = safe_mean(flow["bwd_lengths"])

    # 14
    features["Bwd Packet Length Std"] = safe_std(flow["bwd_lengths"])

    # 15
    features["Flow Bytes/s"] = total_bytes / duration

    # 16
    features["Flow Packets/s"] = total_packets / duration

    # 17
    features["Flow IAT Mean"] = safe_mean(flow_iat)

    # 18
    features["Flow IAT Std"] = safe_std(flow_iat)

    # 19
    features["Flow IAT Max"] = safe_max(flow_iat)

    # 20
    features["Flow IAT Min"] = safe_min(flow_iat)
    
        # ---------- Forward IAT ----------
    features["Fwd IAT Total"] = safe_sum(flow["fwd_iat"])
    features["Fwd IAT Mean"] = safe_mean(flow["fwd_iat"])
    features["Fwd IAT Std"] = safe_std(flow["fwd_iat"])
    features["Fwd IAT Max"] = safe_max(flow["fwd_iat"])
    features["Fwd IAT Min"] = safe_min(flow["fwd_iat"])

    # ---------- Backward IAT ----------
    features["Bwd IAT Total"] = safe_sum(flow["bwd_iat"])
    features["Bwd IAT Mean"] = safe_mean(flow["bwd_iat"])
    features["Bwd IAT Std"] = safe_std(flow["bwd_iat"])
    features["Bwd IAT Max"] = safe_max(flow["bwd_iat"])
    features["Bwd IAT Min"] = safe_min(flow["bwd_iat"])

    # ---------- TCP Flags ----------
    features["Fwd PSH Flags"] = flow["PSH"]
    features["Bwd PSH Flags"] = 0

    features["Fwd URG Flags"] = flow["URG"]
    features["Bwd URG Flags"] = 0

    # ---------- Header Length ----------
    features["Fwd Header Length"] = flow["fwd_header_length"]
    features["Bwd Header Length"] = flow["bwd_header_length"]

    # ---------- Packets per Second ----------
    features["Fwd Packets/s"] = flow["fwd_packets"] / duration
    features["Bwd Packets/s"] = flow["bwd_packets"] / duration

    # ---------- Packet Length ----------
    features["Min Packet Length"] = safe_min(flow["all_lengths"])
    features["Max Packet Length"] = safe_max(flow["all_lengths"])
    
        # ---------- Packet Length Statistics ----------
    features["Packet Length Mean"] = safe_mean(flow["all_lengths"])
    features["Packet Length Std"] = safe_std(flow["all_lengths"])
    features["Packet Length Variance"] = float(np.var(flow["all_lengths"])) if len(flow["all_lengths"]) > 1 else 0.0

    # ---------- TCP Flag Counts ----------
    features["FIN Flag Count"] = flow["FIN"]
    features["SYN Flag Count"] = flow["SYN"]
    features["RST Flag Count"] = flow["RST"]
    features["PSH Flag Count"] = flow["PSH"]
    features["ACK Flag Count"] = flow["ACK"]
    features["URG Flag Count"] = flow["URG"]
    features["CWE Flag Count"] = flow["CWE"]
    features["ECE Flag Count"] = flow["ECE"]

    # ---------- Down / Up Ratio ----------
    if flow["fwd_packets"] == 0:
        features["Down/Up Ratio"] = 0
    else:
        features["Down/Up Ratio"] = (
            flow["bwd_packets"] / flow["fwd_packets"]
        )

    # ---------- Average Packet Size ----------
    features["Average Packet Size"] = safe_mean(flow["all_lengths"])

    # ---------- Average Segment Size ----------
    features["Avg Fwd Segment Size"] = safe_mean(flow["fwd_lengths"])
    features["Avg Bwd Segment Size"] = safe_mean(flow["bwd_lengths"])

    # ---------- Duplicate Header Length ----------
    features["Fwd Header Length.1"] = flow["fwd_header_length"]

    # ---------- Bulk Features ----------
    # CICIDS2017 includes these columns, but Scapy alone does not
    # provide bulk transfer information directly.
    # We'll keep them as 0 for now.
    features["Fwd Avg Bytes/Bulk"] = 0
    features["Fwd Avg Packets/Bulk"] = 0
    features["Fwd Avg Bulk Rate"] = 0

    features["Bwd Avg Bytes/Bulk"] = 0
    
        # ---------- Remaining Bulk Features ----------
    features["Bwd Avg Packets/Bulk"] = 0
    features["Bwd Avg Bulk Rate"] = 0

    # ---------- Subflow Features ----------
    features["Subflow Fwd Packets"] = flow["fwd_packets"]
    features["Subflow Fwd Bytes"] = flow["fwd_bytes"]
    features["Subflow Bwd Packets"] = flow["bwd_packets"]
    features["Subflow Bwd Bytes"] = flow["bwd_bytes"]

    # ---------- Initial TCP Window ----------
    features["Init_Win_bytes_forward"] = flow["init_window_fwd"]
    features["Init_Win_bytes_backward"] = flow["init_window_bwd"]

    # ---------- Forward Data Packets ----------
    features["act_data_pkt_fwd"] = max(
        flow["fwd_packets"] - flow["SYN"] - flow["FIN"],
        0
    )

    # ---------- Minimum Segment Size ----------
    if flow["fwd_header_length"] > 0 and flow["fwd_packets"] > 0:
        features["min_seg_size_forward"] = (
            flow["fwd_header_length"] / flow["fwd_packets"]
        )
    else:
        features["min_seg_size_forward"] = 0

    # ---------- Active Time Statistics ----------
    features["Active Mean"] = safe_mean(flow["active_times"])
    features["Active Std"] = safe_std(flow["active_times"])
    features["Active Max"] = safe_max(flow["active_times"])
    features["Active Min"] = safe_min(flow["active_times"])

    # ---------- Idle Time Statistics ----------
    features["Idle Mean"] = safe_mean(flow["idle_times"])
    features["Idle Std"] = safe_std(flow["idle_times"])
    features["Idle Max"] = safe_max(flow["idle_times"])
    features["Idle Min"] = safe_min(flow["idle_times"])

    return features