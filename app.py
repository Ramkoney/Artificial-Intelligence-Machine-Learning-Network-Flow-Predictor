import os
import json
import hmac
import time
import pyotp
import logging
import queue
from datetime import datetime
from functools import wraps
from pathlib import Path
import threading

import pandas as pd
from flask import (
    Flask, Response, jsonify, render_template, request,
    session, redirect, url_for,
)

import config
import database
import discovery
import enforcement
from prediction.predict import IntrusionPredictor


# ==========================================
# 0. ADMIN PRIVILEGE CHECK (Windows)
# ==========================================
def _is_admin():
    import sys, ctypes
    if sys.platform != "win32":
        return True
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


# ==========================================
# 1. CONFIG & FLASK INIT
# ==========================================
FRONTEND_DIR = os.path.join(config.BASE_DIR, "frontend")
BASE_DIR = Path(__file__).resolve().parent
MODEL_DIR = BASE_DIR / "prediction" / "models"
SIMULATION_CSV = BASE_DIR / "prediction" / "synthetic_attacks.csv"
TEST_DATASET = BASE_DIR / "prediction" / "data" / "UNSW_NB15_testing-set.parquet"

SECRET_KEY = getattr(config, "FLASK_SECRET_KEY", "dev-secret")
ADMIN_USERNAME = getattr(config, "BITSFLUX_ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = getattr(config, "BITSFLUX_ADMIN_PASSWORD", "admin123")
MFA_SECRET = getattr(config, "BITSFLUX_MFA_SECRET", pyotp.random_base32())
totp = pyotp.TOTP(MFA_SECRET)

app = Flask(
    __name__,
    template_folder=os.path.join(FRONTEND_DIR, "templates"),
    static_folder=os.path.join(FRONTEND_DIR, "static"),
    static_url_path="/static",
)
app.secret_key = SECRET_KEY
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,
    PERMANENT_SESSION_LIFETIME=3600,
)
app.logger.setLevel(logging.INFO)

database.init_db()

if not _is_admin():
    print("!" * 60)
    print("  WARNING: Flask is NOT running as Administrator.")
    print("  ARP discovery WILL return 0 devices on Windows.")
    print("  Close this window and reopen PowerShell as Administrator.")
    print("!" * 60)


# ==========================================
# 2. ML MODEL & ALERT QUEUE
# ==========================================
alert_queue = queue.Queue(maxsize=1000)

DEFAULT_SCENARIOS = [
    "High-volume traffic", "Port-scan-like pattern", "HTTP-flood-like pattern",
    "SSH-brute-force-like pattern", "FTP-brute-force-like pattern",
    "RST-heavy pattern", "ICMP-like pattern", "Possible data-exfiltration pattern",
]

predictor = None
try:
    print("[BitsFlux] Loading intrusion detection model...")
    predictor = IntrusionPredictor(model_dir=str(MODEL_DIR)).load()
    print("[BitsFlux] Model loaded.")
except Exception as exc:
    app.logger.error(f"Model load failed: {exc}")


# ==========================================
# 3. HELPERS
# ==========================================
def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("logged_in"):
            if request.path.startswith("/api/"):
                return jsonify({"error": "authentication required"}), 401
            return redirect(url_for("page_login"))
        return view(*args, **kwargs)
    return wrapped


def confidence_as_probability(value):
    value = float(value)
    if value > 1:
        value /= 100.0
    return max(0.0, min(1.0, value))


def enqueue_alert(alert):
    try:
        alert_queue.put_nowait(alert)
    except queue.Full:
        app.logger.warning("Alert queue full; alert skipped.")


def get_scenario_names(traffic_df):
    if "scenario" in traffic_df.columns:
        return traffic_df["scenario"].astype(str).tolist()
    if len(traffic_df) == len(DEFAULT_SCENARIOS):
        return DEFAULT_SCENARIOS.copy()
    return [f"Simulated scenario {i + 1}" for i in range(len(traffic_df))]


def get_expected_labels(traffic_df, row_count):
    if "expected_label" in traffic_df.columns:
        return traffic_df["expected_label"].astype(str).str.strip().str.title().tolist()
    if row_count == len(DEFAULT_SCENARIOS):
        return ["Attack"] * row_count
    return [None] * row_count


# ==========================================
# 4. PAGE ROUTES
# ==========================================
@app.route("/")
def page_root():
    return redirect(url_for("page_login"))


@app.route("/login")
def page_login():
    if session.get("logged_in"):
        return redirect(url_for("unified_portal"))
    return render_template("login.html")


@app.route("/portal")
@login_required
def unified_portal():
    return render_template("unified_dashboard.html")


@app.route("/dashboard")
def page_dashboard():
     return render_template("monitor.html")


@app.route("/register")
def page_register():
    return render_template("register.html")


@app.route("/live")
def live_page():
    return render_template("live.html")


# ==========================================
# 5. AUTH API
# ==========================================
@app.route("/api/auth/login", methods=["POST"])
def api_auth_login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    mfa_code = str(data.get("mfa_code") or "").strip()

    if not username or not password or not mfa_code:
        return jsonify({"error": "username, password and mfa_code required"}), 400

    if not (hmac.compare_digest(username, ADMIN_USERNAME)
            and hmac.compare_digest(password, ADMIN_PASSWORD)):
        return jsonify({"error": "invalid credentials"}), 401

    if not mfa_code.isdigit() or len(mfa_code) != 6:
        return jsonify({"error": "invalid MFA code"}), 401

    if not totp.verify(mfa_code, valid_window=1):
        return jsonify({"error": "invalid MFA code"}), 401

    session.clear()
    session["logged_in"] = True
    session["username"] = username
    session.permanent = True
    return jsonify({"ok": True, "message": "Logged in", "username": username})


@app.route("/api/auth/logout", methods=["POST"])
def api_auth_logout():
    session.clear()
    return jsonify({"ok": True, "message": "Logged out"})


@app.route("/api/auth/me", methods=["GET"])
def api_auth_me():
    if not session.get("logged_in"):
        return jsonify({"logged_in": False}), 401
    return jsonify({"logged_in": True, "username": session.get("username")})


@app.route("/api/auth/mfa/current", methods=["GET"])
def api_auth_mfa_current():
    if os.getenv("FLASK_ENV") == "production":
        return jsonify({"error": "disabled in production"}), 403
    return jsonify({"code": totp.now()})


# ==========================================
# 5b. NETWORK CONFIG API
# ==========================================
import ipaddress


@app.route("/api/config/network", methods=["GET"])
def api_config_network_get():
    return jsonify({
        "subnet":     config.SUBNET,
        "gateway_ip": config.GATEWAY_IP,
        "interfaces": getattr(config, "DISCOVERY_IFACES", []),
    })


@app.route("/api/config/network", methods=["POST"])
@login_required
def api_config_network_update():
    data    = request.get_json(silent=True) or {}
    subnet  = (data.get("subnet") or "").strip()
    gateway = (data.get("gateway_ip") or "").strip()

    if subnet and not discovery.validate_subnet(subnet):
        return jsonify({"error": f"Invalid subnet: {subnet}"}), 400

    if gateway:
        try:
            gw = ipaddress.ip_address(gateway)
        except ValueError:
            return jsonify({"error": f"Invalid gateway IP: {gateway}"}), 400
        if subnet:
            try:
                net = ipaddress.ip_network(subnet, strict=False)
            except ValueError as exc:
                return jsonify({"error": str(exc)}), 400
            if gw not in net:
                return jsonify({
                    "error": f"Gateway {gateway} is not inside subnet {subnet}"
                }), 400

    if subnet:
        config.set_subnet(subnet)
    if gateway:
        config.set_gateway(gateway)

    return jsonify({
        "ok": True,
        "subnet": config.SUBNET,
        "gateway_ip": config.GATEWAY_IP,
    })

# ==========================================
# 6. DEVICE APIs  (no masking, no temp state)
# ==========================================
@app.route("/api/devices", methods=["GET"])
def api_devices_list():
    """Return every device in the DB, raw IP/MAC."""
    return jsonify(database.get_all_devices())


@app.route("/api/devices/known", methods=["GET"])
def api_known_devices():
    return jsonify(database.get_known_devices())


@app.route("/api/devices/unknown", methods=["GET"])
def api_unknown_devices():
    return jsonify(database.get_unknown_devices())


@app.route("/api/devices/blocked", methods=["GET"])
def api_devices_blocked():
    return jsonify(enforcement.list_blocked())


@app.route("/api/devices", methods=["POST"])
def api_devices_create():
    data = request.get_json(silent=True) or {}
    name = (data.get("device_name") or "").strip()
    ip = (data.get("ip_address") or "").strip()
    mac = (data.get("mac_address") or "").strip() or None
    domain = (data.get("domain") or "").strip() or None
    hostname = (data.get("hostname") or "").strip() or None
    subnet = (data.get("subnet") or "").strip() or None

    if not name or not ip:
        return jsonify({"error": "device_name and ip_address required"}), 400

    existing = database.get_device_by_ip(ip)
    if existing:
        if existing.get("is_known"):
            return jsonify({"error": "This IP is already registered"}), 409
        try:
            database.approve_device(existing["id"], name)
            if mac or domain or hostname:
                database.update_device_metadata(
                    existing["id"], mac=mac, domain=domain,
                    hostname=hostname, subnet=subnet,
                )
        except Exception as exc:
            return jsonify({"error": str(exc)}), 500
        return jsonify({"id": existing["id"], "message": "Upgraded to known"}), 200

    try:
        new_id = database.create_device(
            device_name=name, ip_address=ip, mac_address=mac,
            domain=domain, hostname=hostname, subnet=subnet,
            classification="known", is_known=1,
        )
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500
    return jsonify({"id": new_id, "message": "Device registered"}), 201


@app.route("/api/devices/<int:device_id>", methods=["GET"])
def api_device_get(device_id):
    device = database.get_device(device_id)
    if not device:
        return jsonify({"error": "not found"}), 404
    return jsonify(device)


@app.route("/api/devices/<int:device_id>", methods=["PUT"])
def api_device_update(device_id):
    device = database.get_device(device_id)
    if not device:
        return jsonify({"error": "not found"}), 404
    data = request.get_json(silent=True) or {}
    name = (data.get("device_name") or "").strip()
    ip = (data.get("ip_address") or "").strip()
    mac = (data.get("mac_address") or "").strip()
    if not name or not ip:
        return jsonify({"error": "name and ip required"}), 400
    if ip != device["ip_address"]:
        clash = database.get_device_by_ip(ip)
        if clash and clash["id"] != device_id:
            return jsonify({"error": "IP belongs to another device"}), 409
    try:
        database.update_device(device_id, name, ip, mac)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500
    return jsonify({"ok": True})


@app.route("/api/devices/<int:device_id>", methods=["DELETE"])
def api_device_delete(device_id):
    if not database.get_device(device_id):
        return jsonify({"error": "not found"}), 404
    try:
        database.delete_device(device_id)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500
    return jsonify({"ok": True})


@app.route("/api/devices/<int:device_id>/approve", methods=["POST"])
def api_device_approve(device_id):
    if not database.get_device(device_id):
        return jsonify({"error": "not found"}), 404
    data = request.get_json(silent=True) or {}
    name = (data.get("device_name") or "").strip() or None
    try:
        database.approve_device(device_id, name)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500
    return jsonify({"ok": True, "message": "Device approved"})


@app.route("/api/devices/<int:device_id>/unknown", methods=["POST"])
def api_device_mark_unknown(device_id):
    if not database.get_device(device_id):
        return jsonify({"error": "not found"}), 404
    try:
        database.mark_device_unknown(device_id)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500
    return jsonify({"ok": True, "message": "Device marked unknown"})


@app.route("/api/devices/<int:device_id>/block", methods=["POST"])
def api_device_block(device_id):
    device = database.get_device(device_id)
    if not device:
        return jsonify({"error": "not found"}), 404
    if device.get("is_known"):
        return jsonify({"error": "cannot block a known device"}), 400
    try:
        enforcement.block_device(
            target_ip=device["ip_address"],
            gateway_ip=config.GATEWAY_IP,
            interface=config.DISCOVERY_IFACE,
        )
        database.set_device_blocked(device_id, True)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500
    return jsonify({"ok": True, "message": "Device blocked"})


@app.route("/api/devices/<int:device_id>/unblock", methods=["POST"])
def api_device_unblock(device_id):
    device = database.get_device(device_id)
    if not device:
        return jsonify({"error": "not found"}), 404
    try:
        enforcement.unblock_device(device["ip_address"])
        database.set_device_blocked(device_id, False)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500
    return jsonify({"ok": True, "message": "Device unblocked"})

@app.route("/api/discovery", methods=["POST"])
def api_discovery():
    data = request.get_json(silent=True) or {}
    subnet = (data.get("subnet") or "").strip() or config.SUBNET

    if not discovery.validate_subnet(subnet):
        return jsonify({"error": f"Invalid subnet: {subnet}"}), 400 
    
        # Remember this subnet so block/unblock and future scans use it
    if subnet != config.SUBNET:
        config.set_subnet(subnet)
        
    # Run the scan
       # ---- Run the scan with a hard wall-clock timeout ----


    HARD_TIMEOUT = 60          # seconds — total budget for the whole scan
    result_box   = {"devices": None, "error": None}

    def _worker():
        try:
            result_box["devices"] = discovery.discover_devices_multi(
                subnet,
                timeout=getattr(config, "DISCOVERY_TIMEOUT", 2),
                ifaces=getattr(config, "DISCOVERY_IFACES", None),
            )
        except Exception as exc:
            result_box["error"] = exc

    worker = threading.Thread(target=_worker, daemon=True)
    worker.start()
    worker.join(HARD_TIMEOUT)

    if worker.is_alive():
        app.logger.error(f"discovery exceeded {HARD_TIMEOUT}s on {subnet} — aborting")
        return jsonify({
            "error": (
                f"Scan timed out after {HARD_TIMEOUT}s.\n\n"
                "Likely causes:\n"
                "• Not running as Administrator (ARP won't work)\n"
                "• Subnet too large (use /24, not /16)\n"
                f"• DISCOVERY_IFACES name wrong (currently: {config.DISCOVERY_IFACES})\n"
                "• DISCOVERY_TIMEOUT too high for a big subnet"
            )
        }), 504

    if result_box["error"]:
        app.logger.exception("discovery raised", exc_info=result_box["error"])
        return jsonify({"error": str(result_box["error"])}), 500

    discovered = result_box["devices"] or []
   
   # Nothing found → tell the UI exactly why
    if not discovered:
        return jsonify({
            "success": True,
            "total_discovered": 0,
            "new_unknowns": 0,
            "devices": [],
            "warning": (
                "Scan found 0 devices.\n\n"
                "Check these in order:\n"
                "1. Is Flask running as Administrator? (required for ARP on Windows)\n"
                "2. Does config.SUBNET match your Ethernet IP? Run 'ipconfig'.\n"
                "3. Does config.DISCOVERY_IFACES exactly match Get-NetAdapter 'Name'?\n"
                f"   (currently: {config.DISCOVERY_IFACES})\n"
                "4. Is the Ethernet adapter Status = Up?"
            ),
        })

    # Load whitelist once
    try:
        registered_macs = database.get_registered_macs()
    except Exception:
        app.logger.exception("whitelist read failed")
        registered_macs = set()

    saved_devices = []
    new_unknowns = []

    for dev in discovered:
        ip = (dev.get("ip") or "").strip()
        if not ip:
            continue
        mac = (dev.get("mac") or "").upper()
        is_registered = mac in registered_macs
        is_known = 1 if is_registered else 0
        classification = "known" if is_registered else "unknown"

        try:
            existing = database.get_device_by_ip(ip)

            if existing:
                database.update_device_metadata(
                    existing["id"],
                    mac=dev.get("mac"),
                    domain=dev.get("domain"),
                    hostname=dev.get("hostname"),
                    subnet=subnet,
                    status="Online",
                )
                # Promote / demote only if the whitelist status changed
                if existing.get("is_known") != is_known:
                    conn = database.get_connection()
                    conn.execute(
                        "UPDATE devices SET is_known=?, classification=? WHERE id=?",
                        (is_known, classification, existing["id"]),
                    )
                    conn.commit()
                    conn.close()

                updated = database.get_device(existing["id"])
                saved_devices.append({**updated, **dev, "id": existing["id"]})
                continue

            
            if is_registered:
                # ONLY save to the DB if it's whitelisted
                new_id = database.save_discovered_device(
                    ip=ip,
                    mac=dev.get("mac"),
                    domain=dev.get("domain"),
                    subnet=subnet,
                    classification=classification,
                    is_known=is_known,
                )
                record = {"id": new_id, **dev}
                saved_devices.append(record)
            else:
                record = {"id": None, **dev}
                saved_devices.append(record)
                new_unknowns.append(record)
            
        except Exception as exc:
            app.logger.exception(f"save failed for {ip}")
            saved_devices.append({**dev, "database_error": str(exc)})

    return jsonify({
        "success": True,
        "total_discovered": len(saved_devices),
        "new_unknowns": len(new_unknowns),
        "devices": saved_devices,
    })


@app.route("/api/discovery/network", methods=["GET"])
def api_discovery_network():
    subnet = request.args.get("subnet", config.SUBNET).strip()
    info = discovery.get_network_information(subnet)
    if not info:
        return jsonify({"error": f"Invalid subnet: {subnet}"}), 400
    return jsonify({"subnet": subnet, **info})



@app.route("/api/metrics/latest", methods=["GET"])
def api_metrics_latest():
    return jsonify(database.get_latest_metrics_all())


@app.route("/api/metrics/<int:device_id>/history", methods=["GET"])
def api_metrics_history(device_id):
    if not database.get_device(device_id):
        return jsonify({"error": "device not found"}), 404
    limit = max(1, min(request.args.get("limit", default=50, type=int), 1000))
    return jsonify(database.get_metrics_history(device_id, limit))


@app.route("/api/health", methods=["GET"])
def api_health():
    return jsonify({
        "status": "online",
        "database": "connected",
        "blocked_devices": len(enforcement.list_blocked()),
        "admin": _is_admin(),
    })



@app.route("/features", methods=["GET"])
def features():
    if not TEST_DATASET.exists():
        return jsonify({"error": f"Test dataset not found: {TEST_DATASET}"}), 404
    try:
        sample = pd.read_parquet(TEST_DATASET).head(1)
        sample = sample.drop(
            columns=["label", "attack_cat", "scenario",
                     "expected_label", "expected_prediction"],
            errors="ignore",
        )
        if sample.empty:
            return jsonify({"error": "Test dataset is empty."}), 500
        out = {}
        for col in sample.columns:
            val = sample.iloc[0][col]
            if pd.isna(val):
                val = None
            elif hasattr(val, "item"):
                val = val.item()
            out[col] = {
                "value": val,
                "type": ("number" if pd.api.types.is_numeric_dtype(sample[col]) else "text"),
            }
        return jsonify({"features": out, "count": len(out)})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/predict", methods=["POST"])
def predict():
    if predictor is None:
        return jsonify({"error": "Model not loaded."}), 503
    try:
        data = request.get_json(silent=True)
        if not isinstance(data, dict) or not data:
            return jsonify({"error": "Send a non-empty JSON object."}), 400
        result = dict(predictor.predict(data))
        result["confidence_probability"] = confidence_as_probability(result["confidence"])
        result["confidence_percent"] = round(result["confidence_probability"] * 100, 2)
        return jsonify(result)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/simulate/attacks", methods=["POST"])
def simulate_attacks():
    if predictor is None:
        return jsonify({"error": "Model not loaded."}), 503
    if not SIMULATION_CSV.exists():
        return jsonify({"error": f"Simulation file not found: {SIMULATION_CSV}"}), 404
    try:
        traffic_df = pd.read_csv(SIMULATION_CSV)
        if traffic_df.empty:
            return jsonify({"error": "Simulation CSV is empty."}), 400

        model_input = traffic_df.drop(
            columns=["scenario", "expected_label", "expected_prediction"],
            errors="ignore",
        )
        scenario_names = get_scenario_names(traffic_df)
        expected_labels = get_expected_labels(traffic_df, len(traffic_df))
        predictions = predictor.predict_batch(model_input)

        results, alerts = [], []
        for i, pred in enumerate(predictions):
            scenario = scenario_names[i]
            expected = expected_labels[i]
            label = str(pred["label"]).strip().title()
            conf = confidence_as_probability(pred["confidence"])
            raw_ap = pred.get("attack_probability", pred.get("probability", 0.0))
            ap = float(raw_ap)
            if ap > 1:
                ap /= 100.0
            ap = max(0.0, min(1.0, ap))
            correct = (label == expected) if expected is not None else None

            results.append({
                "scenario": scenario,
                "expected_label": expected,
                "prediction": int(pred["prediction"]),
                "label": label,
                "probability": ap,
                "attack_probability_percent": round(ap * 100, 2),
                "confidence": conf,
                "confidence_percent": round(conf * 100, 2),
                "correct": correct,
                "result": ("Correct" if correct is True
                           else "Misclassified" if correct is False
                           else "Not evaluated"),
            })
            alerts.append({
                "timestamp": datetime.now().strftime("%H:%M:%S"),
                "source": "simulation", "src_ip": "SIMULATED",
                "dst_ip": "SIMULATED", "attack_type": scenario,
                "scenario": scenario, "prediction": int(pred["prediction"]),
                "label": label, "expected_label": expected,
                "probability": ap, "confidence": conf,
                "confidence_percent": round(conf * 100, 2),
                "correct": correct,
                "message": f"{scenario}: predicted {label}",
            })
            enqueue_alert(alerts[-1])

        evaluated = [r for r in results if r["correct"] is not None]
        return jsonify({
            "status": "simulation_complete",
            "mode": "simulation_only",
            "total": len(results),
            "attacks_detected": sum(r["label"] == "Attack" for r in results),
            "normal_predictions": sum(r["label"] == "Normal" for r in results),
            "correct_predictions": sum(r["correct"] is True for r in evaluated),
            "misclassified_predictions": sum(r["correct"] is False for r in evaluated),
            "evaluated_predictions": len(evaluated),
            "results": results,
            "alerts": alerts,
        })
    except Exception as exc:
        app.logger.exception("simulation failed")
        return jsonify({"error": str(exc)}), 500


@app.route("/stream")
def stream():
    def event_stream():
        while True:
            try:
                alert = alert_queue.get(timeout=15)
                yield f"data: {json.dumps(alert)}\n\n"
            except queue.Empty:
                yield ": keepalive\n\n"
    return Response(
        event_stream(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


if __name__ == "__main__":
    print("=" * 55)
    print(" BitsFlux Unified Monitoring & IDS")
    print(" http://0.0.0.0:5000")
    print("=" * 55)
    app.run(host="0.0.0.0", port=5000, debug=True, use_reloader=False)