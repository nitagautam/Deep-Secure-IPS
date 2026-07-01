# ---------- IMPORT REQUIRED MODULES ----------
import csv
import os
from datetime import datetime

# ---------- SETUP LOG DIRECTORY AND FILE ----------
os.makedirs("logs", exist_ok=True)
LOG_FILE = "logs/ips_logs.csv"

# Create log file with headers if it does not exist
if not os.path.exists(LOG_FILE):
    with open(LOG_FILE, "w", newline="") as f:
        writer = csv.writer(f, delimiter=",")
        writer.writerow([
            "Time",
            "Source_IP",
            "Destination_IP",
            "Protocol",
            "Detection",
            "Attack_Type",
            "Action"  

        ])
        
# ---------- LOGGING FUNCTION ----------
def log_event(src, dst, proto, result):

    # Append detection event to CSV log file
    with open(LOG_FILE, "a", newline="") as f:

        writer = csv.writer(f, delimiter=",")

        writer.writerow([
            datetime.now().strftime("%H:%M:%S"),
            src,
            dst,
            proto,
            result["Detection"],
            result["Attack_Type"],
            result["Action"]
        ])
