# scan_test.py
from scapy.all import ARP, Ether, srp

for iface in ["Wi-Fi", "Ethernet"]:
    print(f"\n=== {iface} ===")
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst="192.168.23.0/24")
    ans, _ = srp(pkt, timeout=5, verbose=0, iface=iface)
    print(f"Answered: {len(ans)}")
    for _, r in ans:
        print(f"  {r.psrc:<15} {r.hwsrc}")