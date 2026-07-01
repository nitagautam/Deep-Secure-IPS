# ---------- IMPORT REQUIRED MODULES ----------
from collections import defaultdict
import time
import pandas as pd
import csv
import os
from datetime import datetime

from IPS import predict_packet
from firewall_controller import block_ip
from ips_logger import log_event

# ---------- FLOW STORAGE ----------
flows = defaultdict(lambda: {
    "start_time": time.time(),
    "spkts": 0,
    "dpkts": 0,
    "sbytes": 0,
    "dbytes": 0,
    "sttl": 0,
    "dttl": 0,
    "last_time": time.time()
})

# ---------- SYSTEM STATE TRACKING ----------
blocked_ips = set()
ip_packet_counts = defaultdict(int)

# ---------- PROTOCOL MAPPING ----------
proto_map = {
    6: "tcp",
    17: "udp",
    1: "icmp"
}

# ---------- TRUSTED / LOCAL IP LISTS ----------
MY_IPS = ["192.168.1.73", "127.0.0.1", "192.168.56.1"]
SAFE_IPS = ["8.8.8.8", "1.1.1.1"]


# Ensure logs folder exists
os.makedirs("logs", exist_ok=True)

PACKET_LOG = "logs/packet_logs.csv"

# --------Create file with header (only once)--------
if not os.path.exists(PACKET_LOG):
    with open(PACKET_LOG, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Time", "Source_IP", "Destination_IP", "Protocol"])

def log_packet(src, dst, proto):
    with open(PACKET_LOG, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            datetime.now().strftime("%H:%M:%S"),
            src,
            dst,
            proto
        ])
        
# ---------- PACKET PROCESSING FUNCTION ----------
from scapy.layers.inet import IP

def process_packet(packet):
    if not packet.haslayer("IP"):
        return

    src = packet["IP"].src

    if src in MY_IPS:
        return

    if src in blocked_ips: 
        return

    if src in SAFE_IPS:
        return

    
    dst = packet["IP"].dst
    proto_num = packet["IP"].proto
    proto = proto_map.get(proto_num, "other")

    log_packet(src, dst, proto)

    key = (src, dst, proto)
    flow = flows[key]
    current_time = time.time()
    
    # Update flow statistics
    flow["spkts"] += 1
    flow["sbytes"] += len(packet)
    flow["sttl"] = packet["IP"].ttl
    
    duration = current_time - flow["start_time"]

    # Derived features for ML model
    rate = flow["spkts"] / duration if duration > 0 else 0
    sinpkt = current_time - flow["last_time"]
    flow["last_time"] = current_time
    ip_packet_counts[src] += 1
    
    # ---------- FEATURE EXTRACTION THRESHOLD ----------
    if flow["spkts"] >= 10:
        features = {
            "dur": duration,
            "proto": proto,
            "spkts": flow["spkts"],
            "dpkts": flow["dpkts"],
            "sbytes": flow["sbytes"],
            "dbytes": flow["dbytes"],
            "sttl": flow["sttl"],
            "dttl": flow["dttl"],
            "rate": rate,
            "sload": flow["sbytes"]/duration if duration>0 else 0,
            "dload": flow["dbytes"]/duration if duration>0 else 0,
            "sinpkt": sinpkt,
            "dinpkt": 0
        }

        df = pd.DataFrame([features])
        
        result = predict_packet(df)

        # Extract prediction results from ML model
        confidence = result["confidence"]  # Probability/confidence of prediction
        attack_type = result["type"]       # Predicted class (Normal / Attack type)
        
        attacker_ip = src
        action = "IGNORE"
        
        # Step 1: DoS detection 
        if rate > 1000 and ip_packet_counts[src] > 2000 and sinpkt < 0.01:
            attack_type = "DoS"
            action = "BLOCK"

        # Step 2: ML-based alerts only (no blocking)
        elif attack_type != "Normal":
            if confidence > 0.50:
                action = "ALERT"

        # Step 3: Ensure local IPs are never blocked
        if action == "BLOCK":
            if attacker_ip not in blocked_ips and attacker_ip not in MY_IPS:
                block_ip(attacker_ip)             # Apply firewall rule
                blocked_ips.add(attacker_ip)      # Store blocked IP

                ip_packet_counts[attacker_ip] = 0
            
            else:
                print("Already blocked")

        # Step 4: Final decision label
        # This determines whether the traffic is considered a real attack
        is_real_attack = (
            action == "BLOCK"
            or (attack_type !="Normal" and confidence > 0.50)
        )

        # Debug output for detected attacks
        if is_real_attack:
            print("ATTACK DETECTED:", attacker_ip, {
                "type": attack_type,
            })

        # STEP 5: Detection Category for Logging
        # Convert action into human-readable detection label
        if action == "BLOCK":
            detection = "Attack"
        elif action == "ALERT":
            detection = "Suspicious"
        else:
            detection = "Normal"

        # Step 6: Logging event
        log_event(src, dst, proto, {
            "Detection": detection,
            "Attack_Type": attack_type if is_real_attack else "Normal",
            "Confidence": confidence,
            "Action": action
        })

        flows.pop(key)
