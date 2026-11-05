"""
Live Engine — runs the Scapy packet capture in the background 
and feeds it to the ML model.
"""
import threading
import time
from prediction.predict import IntrusionPredictor
# CHANGE THIS to match your actual sniffer file name (e.g., live_capture)
from live_capture import start as start_sniffing 

# 1. Shared stats for the dashboard
live_stats = {
    "flows_received": 0,
    "attacks_predicted": 0,
    "normal_predictions": 0,
    "recent_alerts": []
}

# 2. Callback function triggered every time a flow ends
def on_flow_predicted(features, result):
    live_stats["flows_received"] += 1
    
    if result["prediction"] == 1: # Attack
        live_stats["attacks_predicted"] += 1
        live_stats["recent_alerts"].insert(0, {
            "src_ip": features.get("srcip", "Unknown"),
            "dst_ip": features.get("dstip", "Unknown"),
            "proto": features.get("proto", "tcp"),
            "confidence": round(result["confidence"] * 100, 1),
            "time": time.strftime("%H:%M:%S")
        })
        live_stats["recent_alerts"] = live_stats["recent_alerts"][:5] # Keep last 5
    else:
        live_stats["normal_predictions"] += 1

# 3. Function to start it
def start_engine(interface=None):
    print("[live_engine] Starting background network sniffer...")
    # This starts the Scapy sniff loop
    start_sniffing(interface=interface, on_result=on_flow_predicted)

# 4. Run it as a background thread
def start_background():
    threading.Thread(target=start_engine, daemon=True).start()

if __name__ == "__main__":
    print("Starting engine directly...")
    start_engine()