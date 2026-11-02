
"""
Live network flow capture + intrusion prediction.

Captures IP packets, groups them into bidirectional flows, builds
UNSW-NB15-style features, and sends each completed flow to the model.

Note:
- TCP timing and several statistical features are currently approximated.
- Live predictions should be treated as experimental until validated.
- Packet capture on Windows may require Npcap and administrator privileges.
"""

import os
import sys
import time
import threading
from datetime import datetime

from scapy.all import sniff, IP, TCP, UDP

# Ensure predict.py can be imported from this directory.
SRC_DIR = os.path.dirname(os.path.abspath(__file__))
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from predict import IntrusionPredictor


FLOW_TIMEOUT = 5.0
CLEANUP_INTERVAL = 2.0


class Flow:
    """Represents a bidirectional network flow."""

    def __init__(self, key, start_time, forward_is_first=True):
        self.key = key
        self.start = start_time
        self.last_seen = start_time

        self.spkts = 0
        self.dpkts = 0
        self.sbytes = 0
        self.dbytes = 0

        self.tcp_flags = set()
        self.sttl = 0
        self.dttl = 0
        self.swin = 0
        self.dwin = 0

        self.service = "-"
        self.state = "INT"


class FlowTracker:
    """Tracks active flows and sends completed flows to the predictor."""

    def __init__(self, predictor, on_result):
        self.predictor = predictor
        self.on_result = on_result
        self.flows = {}
        self.lock = threading.Lock()

    def _flow_key(self, pkt):
        """
        Create a consistent bidirectional flow key.

        The key is sorted so packets travelling in either direction map
        to the same flow. The boolean indicates the direction relative
        to the sorted key, not necessarily the original client direction.
        """
        ip = pkt[IP]
        proto = ip.proto

        sport = 0
        dport = 0

        if pkt.haslayer(TCP):
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
        elif pkt.haslayer(UDP):
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport

        source = (ip.src, sport)
        destination = (ip.dst, dport)

        if source <= destination:
            key = (ip.src, sport, ip.dst, dport, proto)
            return key, True

        key = (ip.dst, dport, ip.src, sport, proto)
        return key, False

    def process(self, pkt):
        """Process one captured packet."""
        if not pkt.haslayer(IP):
            return

        now = time.time()
        key, is_forward = self._flow_key(pkt)

        ip = pkt[IP]
        packet_size = len(pkt)

        with self.lock:
            flow = self.flows.get(key)

            if flow is None:
                flow = Flow(key, now)
                self.flows[key] = flow

            flow.last_seen = now

            if is_forward:
                flow.spkts += 1
                flow.sbytes += packet_size

                if flow.sttl == 0:
                    flow.sttl = ip.ttl

                if pkt.haslayer(TCP):
                    flow.swin = pkt[TCP].window
                    flow.tcp_flags.add(int(pkt[TCP].flags))

            else:
                flow.dpkts += 1
                flow.dbytes += packet_size

                if flow.dttl == 0:
                    flow.dttl = ip.ttl

                if pkt.haslayer(TCP):
                    flow.dwin = pkt[TCP].window
                    flow.tcp_flags.add(int(pkt[TCP].flags))

            if flow.service == "-":
                flow.service = self._guess_service(pkt)

    def _guess_service(self, pkt):
        """Infer a service from well-known TCP/UDP ports."""
        ports = set()

        if pkt.haslayer(TCP):
            ports = {pkt[TCP].sport, pkt[TCP].dport}
        elif pkt.haslayer(UDP):
            ports = {pkt[UDP].sport, pkt[UDP].dport}

        mapping = {
            20: "ftp-data",
            21: "ftp",
            22: "ssh",
            25: "smtp",
            53: "dns",
            80: "http",
            110: "pop3",
            143: "imap",
            443: "https",
            3306: "mysql",
            3389: "rdp",
        }

        for port in ports:
            if port in mapping:
                return mapping[port]

        return "-"

    def finalize(self, flow):
        """Convert a completed flow into model features and predict."""
        duration = max(flow.last_seen - flow.start, 1e-6)
        total_packets = flow.spkts + flow.dpkts

        features = {
            # Core flow features
            "dur": round(duration, 6),
            "proto": self._proto_name(flow.key[4]),
            "service": flow.service,
            "state": self._tcp_state(flow),

            # Packet and byte counts
            "spkts": flow.spkts,
            "dpkts": flow.dpkts,
            "sbytes": flow.sbytes,
            "dbytes": flow.dbytes,

            # Estimated packet rate
            "rate": round(total_packets / duration, 2),

            # Packet loads
            "sload": round(flow.sbytes / duration, 2),
            "dload": round(flow.dbytes / duration, 2),

            # Loss and inter-packet timing estimates
            "sloss": 0,
            "dloss": 0,
            "sinpkt": round(
                duration * 1000 / max(flow.spkts, 1), 3
            ),
            "dinpkt": round(
                duration * 1000 / max(flow.dpkts, 1), 3
            ),
            "sjit": 0.0,
            "djit": 0.0,

            # TCP features
            "swin": flow.swin,
            "stcpb": 0,
            "dtcpb": 0,
            "dwin": flow.dwin,

            # TCP timing placeholders: these are not measured yet
            "tcprtt": 0.0,
            "synack": 0.0,
            "ackdat": 0.0,

            # Mean packet sizes
            "smean": flow.sbytes // max(flow.spkts, 1),
            "dmean": flow.dbytes // max(flow.dpkts, 1),

            # Application and connection statistics
            "trans_depth": 0,
            "response_body_len": 0,
            "ct_src_dport_ltm": 0,
            "ct_dst_sport_ltm": 0,
            "is_ftp_login": 0,
            "ct_ftp_cmd": 0,
            "ct_flw_http_mthd": 0,
            "is_sm_ips_ports": 0,

            # Additional features; ignored if the model does not expect them
            "sttl": flow.sttl or 64,
            "dttl": flow.dttl or 64,
            "ct_srv_src": 0,
            "ct_state_ttl": 0,
            "ct_dst_ltm": 0,
            "ct_src_ltm": 0,
            "ct_dst_src_ltm": 0,

            # Endpoint metadata for alerts and logging
            "srcip": flow.key[0],
            "sport": flow.key[1],
            "dstip": flow.key[2],
            "dsport": flow.key[3],
        }

        try:
            result = self.predictor.predict(features)
        except Exception as exc:
            print(
                f"[!] Prediction failed for flow {flow.key}: {exc}"
            )
            return

        try:
            self.on_result(features, result)
        except Exception as exc:
            print(f"[!] Alert callback failed: {exc}")

    @staticmethod
    def _proto_name(proto):
        return {
            6: "tcp",
            17: "udp",
            1: "icmp",
        }.get(proto, "other")

    @staticmethod
    def _tcp_state(flow):
        """Estimate connection state from observed TCP flags."""
        flags = flow.tcp_flags

        if any(flag & 0x04 for flag in flags):
            return "RST"

        if any(flag & 0x01 for flag in flags):
            return "FIN"

        has_syn = any(flag & 0x02 for flag in flags)
        has_ack = any(flag & 0x10 for flag in flags)

        if has_syn and has_ack:
            return "CON"

        return "INT"

    def cleanup_loop(self):
        """Finalize flows that have been idle for FLOW_TIMEOUT seconds."""
        while True:
            time.sleep(CLEANUP_INTERVAL)
            now = time.time()
            expired = []

            with self.lock:
                for key, flow in list(self.flows.items()):
                    if now - flow.last_seen > FLOW_TIMEOUT:
                        expired.append(flow)
                        del self.flows[key]

            for flow in expired:
                self.finalize(flow)


def default_on_result(features, result):
    """Print each flow's prediction."""
    timestamp = datetime.now().strftime("%H:%M:%S")

    source = f"{features['srcip']}:{features['sport']}"
    destination = f"{features['dstip']}:{features['dsport']}"

    label = result.get("label", "Unknown")
    confidence = result.get("confidence", 0.0)

    if label == "Attack" or result.get("prediction") == 1:
        status = "ATTACK"
    else:
        status = "Normal"

    print(
        f"[{timestamp}] {status} "
        f"{source} -> {destination} "
        f"({features['proto']}/{features['service']}) "
        f"confidence={confidence:.1%}"
    )


def start(
    interface=None,
    on_result=None,
    bpf_filter="ip",
    predictor=None,
):
    """Start packet capture and flow analysis."""
    if predictor is None:
        print("Loading intrusion detection model...")
        predictor = IntrusionPredictor().load()

    tracker = FlowTracker(
        predictor=predictor,
        on_result=on_result or default_on_result,
    )

    cleanup_thread = threading.Thread(
        target=tracker.cleanup_loop,
        daemon=True,
    )
    cleanup_thread.start()

    print(
        f"Starting packet capture on {interface or 'default interface'} "
        f"(filter={bpf_filter!r})..."
    )
    print("Press Ctrl+C to stop.")

    try:
        sniff(
            iface=interface,
            filter=bpf_filter,
            prn=tracker.process,
            store=False,
        )
    except PermissionError:
        print(
            "[!] Permission denied. Try running PowerShell as "
            "Administrator and check that Npcap is installed."
        )
        raise
    except Exception as exc:
        print(f"[!] Packet capture failed: {exc}")
        raise


if __name__ == "__main__":
    interface = sys.argv[1] if len(sys.argv) > 1 else None
    start(interface=interface)
