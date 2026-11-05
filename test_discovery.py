
import discovery, config

print("Adapters visible to scapy:")
for a in discovery._list_adapters():
    print("  ", a["name"], "->", a["ips"])

print("\nResolved iface:", discovery._resolve_iface(config.DISCOVERY_IFACE))
print("My IPs:", discovery._find_my_ips(discovery._resolve_iface(config.DISCOVERY_IFACE)))
print()

devices = discovery.discover_devices(config.SUBNET)
for d in devices:
    print(d)