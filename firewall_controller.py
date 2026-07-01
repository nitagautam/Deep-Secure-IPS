# ---------- IMPORT SYSTEM COMMAND MODULE ----------
import subprocess

# ---------- CHECK EXISTING FIREWALL RULE ----------
def rule_exists(rule_name):
    command = [
        "netsh",
        "advfirewall",
        "firewall",
        "show",
        "rule",
        f"name={rule_name}"
    ]
    result = subprocess.run(command, capture_output=True, text=True)
    return "No rules match" not in result.stdout

# ---------- BLOCK MALICIOUS IP ----------
def block_ip(ip):

    # Trusted / local IPs (never block these)
    MY_IPS = ["192.168.1.73", "127.0.0.1", "192.168.56.1"]

    if ip in MY_IPS:
        print(f"Skipping own IPS machine IP: {ip}")
        return
    
    # FIREWALL RULE NAME CREATION
    rule_name = f"IPS_Block_{ip}"

    # Prevent duplicate firewall rules
    if rule_exists(rule_name):
        print(f"IP already blocked in firewall: {ip}") # Prevents adding duplicate firewall rules
        return

    # FIREWALL BLOCK COMMAND
    # Windows netsh command used to add a firewall rule
    command = [
        "netsh",
        "advfirewall",
        "firewall",
        "add",
        "rule",
        f"name={rule_name}",
        "dir=in",
        "action=block",
        f"remoteip={ip}"
    ]
    
    # Execute the firewall command at OS level
    subprocess.run(command)

    
    print(f"IP BLOCKED SUCCESSFULLY: {ip}")

# ---------- RESET ALL IPS FIREWALL RULES ----------
def reset_ips_blocks():
    command = [
        "netsh",
        "advfirewall",
        "firewall",
        "delete",
        "rule",
        "name=IPS_Block*"
    ]
    subprocess.run(command)
    print("All IPS firewall rules removed")
    
