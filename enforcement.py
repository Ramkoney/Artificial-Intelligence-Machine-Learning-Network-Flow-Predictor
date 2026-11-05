"""
ARP-based device blocking for unknown devices.
For project demonstration only.
"""
import threading
import time
from scapy.all import ARP, send, get_if_hwaddr


class DeviceBlocker:
    def __init__(self, target_ip, gateway_ip, interface):
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.interface = interface
        self.running = False
        self._thread = None

    def _spoof_loop(self):
        my_mac = get_if_hwaddr(self.interface)
        while self.running:
            send(ARP(op=2, pdst=self.target_ip,
                     hwdst="ff:ff:ff:ff:ff:ff",
                     psrc=self.gateway_ip,
                     hwsrc=my_mac),
                 iface=self.interface, verbose=False)
            time.sleep(1)

    def start(self):
        self.running = True
        self._thread = threading.Thread(target=self._spoof_loop, daemon=True)
        self._thread.start()
        print(f"[blocker] Blocking {self.target_ip}")

    def stop(self):
        self.running = False
        if self._thread:
            self._thread.join(timeout=2)
        print(f"[blocker] Stopped blocking {self.target_ip}")


_active_blockers = {}


def block_device(target_ip, gateway_ip, interface):
    if target_ip in _active_blockers:
        return False
    blocker = DeviceBlocker(target_ip, gateway_ip, interface)
    blocker.start()
    _active_blockers[target_ip] = blocker
    return True


def unblock_device(target_ip):
    blocker = _active_blockers.pop(target_ip, None)
    if blocker:
        blocker.stop()
        return True
    return False


def list_blocked():
    return list(_active_blockers.keys())