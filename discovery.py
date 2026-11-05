"""
ARP-based device discovery + OUI lookup.
Cross-platform (Windows / Linux / macOS).
"""
import os
import csv
import socket
import ipaddress
import platform
from functools import lru_cache
from concurrent.futures import ThreadPoolExecutor

from scapy.all import ARP, Ether, srp, conf, get_if_list, get_if_addr

import config

# --- Platform-specific imports -------------------------------------------------
IS_WINDOWS = platform.system().lower() == "windows"

if IS_WINDOWS:
    try:
        from scapy.arch.windows import get_windows_if_list
    except Exception:
        get_windows_if_list = None
else:
    get_windows_if_list = None

OUI_PATH = os.path.join(config.DATA_DIR, "oui.csv")


# ------------------------------------------------------------------------------
# OUI lookup
# ------------------------------------------------------------------------------
@lru_cache(maxsize=1)
def _load_oui():
    table = {}
    if not os.path.exists(OUI_PATH):
        print(f"[oui] WARNING: {OUI_PATH} not found. "
              f"Domains will be 'unknown.local'.")
        return table

    with open(OUI_PATH, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            prefix = (row.get("Assignment") or "").upper().strip()
            org = (row.get("Organization Name") or "").strip()
            if len(prefix) == 6 and org:
                formatted = ":".join(prefix[i:i+2] for i in range(0, 6, 2))
                table[formatted] = org

    print(f"[oui] loaded {len(table)} OUI prefixes")
    return table


def resolve_domain(mac):
    if not mac:
        return "unknown.local"
    prefix = mac.upper()[0:8]
    return _load_oui().get(prefix, "unknown.local")


def _try_reverse_dns(ip, timeout=1.0):
    """Best-effort reverse DNS. Never blocks more than `timeout` seconds."""
    try:
        # Bound the lookup so a broken DNS can't stall the scan.
        fut = _DNS_POOL.submit(socket.gethostbyaddr, ip)
        hostname, _, _ = fut.result(timeout=timeout)
        if hostname and "." in hostname:
            return hostname.split(".", 1)[1]
    except Exception:
        pass
    return None


_DNS_POOL = ThreadPoolExecutor(max_workers=16)


# ------------------------------------------------------------------------------
# Interface resolution
# ------------------------------------------------------------------------------
def _list_adapters():
    """Return list of dicts: {name, ips, guid}."""
    adapters = []

    if IS_WINDOWS and get_windows_if_list:
        for entry in get_windows_if_list():
            adapters.append({
                "name": entry.get("name") or "",
                "ips": entry.get("ips") or [],
                "guid": entry.get("guid") or "",
            })
    else:
        for name in get_if_list():
            try:
                ip = get_if_addr(name)
            except Exception:
                ip = "0.0.0.0"
            ips = [ip] if ip and ip != "0.0.0.0" else []
            adapters.append({"name": name, "ips": ips, "guid": ""})

    return adapters


def _resolve_iface(iface):
    """
    Resolve `iface` to a scapy-compatible interface name.
    Accepts:
      - None         → auto-detect
      - NPF GUID     → returned as-is (Windows)
      - Adapter name → matched case-insensitively
      - Adapter IP   → matched against adapter IPs
    """
    if not iface:
        try:
            default = conf.iface
            print(f"[discovery] auto-selected interface: {default}")
        except Exception:
            pass
        return None

    iface_str = str(iface)

    if iface_str.startswith("\\Device\\NPF_"):
        return iface_str

    for entry in _list_adapters():
        name = entry.get("name") or ""
        ips = entry.get("ips") or []

        if iface_str.lower() == name.lower():
            return name
        if iface_str in ips:
            return name

    print(f"[discovery] WARNING: interface '{iface}' not found; "
          f"falling back to auto-detect")
    return None


def _find_my_ips(target_iface):
    """IPs that belong to THIS machine (to skip self in results)."""
    my_ips = set()

    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None):
            ip = info[4][0]
            if ":" not in ip:                      # IPv4 only
                my_ips.add(ip)
    except Exception:
        pass

    if IS_WINDOWS and get_windows_if_list:
        for entry in get_windows_if_list():
            if target_iface and entry.get("name") != target_iface:
                continue
            for ip in (entry.get("ips") or []):
                if ":" not in ip:
                    my_ips.add(ip)
    else:
        try:
            ip = get_if_addr(target_iface) if target_iface else conf.iface
            if ip and ip != "0.0.0.0":
                my_ips.add(ip)
        except Exception:
            pass

    return my_ips


# ------------------------------------------------------------------------------
# Core scan — ARP via scapy
# ------------------------------------------------------------------------------
def discover_devices(subnet, timeout=2, iface=None):
    """
    ARP-scan every host in `subnet` using scapy's srp.
    Returns a list of device dicts.
    """
    if not validate_subnet(subnet):
        print(f"[discovery] invalid subnet: {subnet}")
        return []

    scapy_iface = _resolve_iface(iface)

    print(f"[discovery] scanning {subnet} on "
          f"{scapy_iface or 'auto'} (timeout={timeout}s) ...")

    my_ips = _find_my_ips(iface)
    print(f"[discovery] skipping self IPs: {sorted(my_ips)}")

    arp_request = ARP(pdst=subnet)
    broadcast   = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet      = broadcast / arp_request

    # Key tuning knobs:
    #   timeout  — total scan budget (NOT per-host)
    #   retry    — how many times to re-send unanswered ARPs
    #   inter    — min gap between packets (0 = send as fast as possible)
    #   verbose=False + threaded internal loop = much faster
    try:
        answered, _ = srp(
            packet,
            timeout=timeout,
            retry=1,                # 1 retry is plenty on a LAN
            inter=0,                # send back-to-back, no artificial pause
            iface=scapy_iface,
            verbose=False,
        )
    except Exception as exc:
        print(f"[discovery] srp() failed on iface '{scapy_iface}': {exc}")
        return []

    devices = []
    seen_ips = set()

    for _sent, received in answered:
        ip  = (received.psrc or "").strip()
        mac = (received.hwsrc or "").upper().strip()

        if not ip or ip in my_ips or ip in seen_ips:
            continue
        seen_ips.add(ip)

        # Skip reverse DNS — it was adding 100+ seconds on a /24
        # with unreachable DNS. Keep OUI-based domain only.
        domain = resolve_domain(mac) or "unknown.local"

        devices.append({
            "ip":       ip,
            "mac":      mac or None,
            "hostname": None,
            "domain":   domain,
        })

    print(f"[discovery] srp returned {len(answered)} answer(s); "
          f"kept {len(devices)} unique")

    return devices

# ------------------------------------------------------------------------------
# Multi-interface wrapper
# ------------------------------------------------------------------------------
def discover_devices_multi(subnet, timeout=None, ifaces=None):
    """
    Run discovery on each interface in `ifaces`, merge results by MAC.

    - ifaces=None or [] → auto-detect one interface
    - ifaces=["Wi-Fi","Ethernet"] → scan both, dedupe
    """
    if timeout is None:
        timeout = getattr(config, "DISCOVERY_TIMEOUT", 3)

    if not ifaces:
        return discover_devices(subnet, timeout=timeout, iface=None)

    merged = {}
    per_iface_counts = {}

    for iface in ifaces:
        print()
        print(f"[multi] ---- scanning on '{iface}' ----")
        try:
            found = discover_devices(subnet, timeout=timeout, iface=iface)
        except Exception as exc:
            print(f"[multi] iface '{iface}' failed: {exc}")
            per_iface_counts[iface] = 0
            continue

        per_iface_counts[iface] = len(found)

        for dev in found:
            mac = (dev.get("mac") or "").upper()
            key = mac if mac else dev.get("ip")
            if not key:
                continue
            if key not in merged:
                dev = dict(dev)
                dev["seen_on"] = iface
                merged[key] = dev
            else:
                merged[key].setdefault("seen_on_alt", []).append(iface)

    result = list(merged.values())
    print()
    print(f"[multi] per-interface counts: {per_iface_counts}")
    print(f"[multi] unique devices after dedupe: {len(result)}")
    return result


# ------------------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------------------
def validate_subnet(subnet):
    try:
        ipaddress.ip_network(subnet, strict=False)
        return True
    except ValueError:
        return False


def get_network_information(subnet):
    try:
        net = ipaddress.ip_network(subnet, strict=False)
    except ValueError:
        return None
    return {
        "network_address":     str(net.network_address),
        "broadcast_address":   str(net.broadcast_address),
        "num_addresses":       net.num_addresses,
        "prefixlen":           net.prefixlen,
    }