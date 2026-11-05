
import socket
import subprocess
import config
from scapy.all import ARP, Ether, srp

try:
    from scapy.arch.windows import get_windows_if_list
except ImportError:
    get_windows_if_list = None


def section(title):
    print(f"\n{'=' * 5} {title} {'=' * 5}")


section("CONFIG")
print(f"SUBNET         : {config.SUBNET}")
print(f"GATEWAY_IP     : {config.GATEWAY_IP}")
print(f"DISCOVERY_IFACE: {config.DISCOVERY_IFACE}")

section("MY IP")
print(f"Hostname: {socket.gethostname()}")
try:
    print(f"IP      : {socket.gethostbyname(socket.gethostname())}")
except Exception as e:
    print(f"Could not resolve: {e}")

section("INTERFACES (Scapy)")
if get_windows_if_list is None:
    print("get_windows_if_list not available in this Scapy version.")
else:
    for i in get_windows_if_list():
        print(f"  name : {i['name']}")
        print(f"  desc : {i.get('description')}")
        print(f"  ips  : {i.get('ips')}")
        print()

section("PING GATEWAY")
try:
    r = subprocess.run(
        ["ping", "-n", "2", config.GATEWAY_IP],
        capture_output=True, text=True, timeout=10,
    )
    print(r.stdout or r.stderr)
except Exception as e:
    print(f"ping failed: {e}")

section("ARP SCAN (auto iface)")
try:
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=config.SUBNET)
    ans, _ = srp(pkt, timeout=3, verbose=0)
    print(f"Found {len(ans)} device(s):")
    for _, r in ans:
        print(f"  {r.psrc:15}  {r.hwsrc}")
except Exception as e:
    print(f"ARP scan failed: {e}")

section("ARP SCAN (configured iface)")
if config.DISCOVERY_IFACE:
    try:
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=config.SUBNET)
        ans, _ = srp(pkt, timeout=3, iface=config.DISCOVERY_IFACE, verbose=0)
        print(f"Found {len(ans)} device(s):")
        for _, r in ans:
            print(f"  {r.psrc:15}  {r.hwsrc}")
    except Exception as e:
        print(f"ARP scan with iface failed: {e}")
else:
    print("DISCOVERY_IFACE is None — skipped.")