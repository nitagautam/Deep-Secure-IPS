# ---------- IMPORT REQUIRED MODULES ----------
from scapy.all import sniff
from flow_builder import process_packet
from firewall_controller import reset_ips_blocks

# ---------- START REAL-TIME PACKET CAPTURE ----------
def start_capture():

    print("Deep Secure IPS engine started.....")
    
    # Reset any previously applied IP blocks in firewall
    reset_ips_blocks()

    # Start sniffing network packets from selected interfaces
    sniff(
        iface=[
            r"\Device\NPF_{DFD0AB5B-86F0-45C8-82F0-09FD48F0CD85}",
            r"\Device\NPF_{130F6FEC-443C-4955-94C5-DF3697C96640}"  
            ],
        
        prn=process_packet,
        store=False
    )

# ---------- PROGRAM ENTRY POINT ----------
if __name__ == "__main__":
    start_capture()
