import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")

# ---------- Network ----------
# MUST match the subnet of the adapter you're scanning on.
# Run `ipconfig` in PowerShell and copy your Ethernet IPv4 + subnet here.
# ---------- Network (runtime-mutable) ----------
_DEFAULT_SUBNET     = "192.168.23.0/24"
_DEFAULT_GATEWAY_IP = "192.168.23.1"

SUBNET     = _DEFAULT_SUBNET
GATEWAY_IP = _DEFAULT_GATEWAY_IP


def set_subnet(new_subnet: str) -> None:
    global SUBNET
    SUBNET = new_subnet.strip()


def set_gateway(new_gateway: str) -> None:      
    global GATEWAY_IP
    GATEWAY_IP = new_gateway.strip()


def reset_network_defaults() -> None:
    global SUBNET, GATEWAY_IP
    SUBNET     = _DEFAULT_SUBNET
    GATEWAY_IP = _DEFAULT_GATEWAY_IP
    
# Must EXACTLY match the adapter name from `Get-NetAdapter`.
# Common values: "Ethernet", "Ethernet 2", "Wi-Fi".
# NO leading/trailing spaces.
DISCOVERY_IFACES = ["Ethernet"]
DISCOVERY_IFACE = "Ethernet"

# ---------- Timing ----------
DISCOVERY_INTERVAL = 300
MONITOR_INTERVAL = 60
PING_COUNT = 4
PING_TIMEOUT = 1
PING_INTERVAL = 0.2
DISCOVERY_TIMEOUT = 5

# ---------- Auth (login screen only) ----------
FLASK_SECRET_KEY = "change-me-to-a-long-random-string-please"
BITSFLUX_ADMIN_USERNAME = "admin"
BITSFLUX_ADMIN_PASSWORD = "BitsFlux@Admin2026"
BITSFLUX_MFA_SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"