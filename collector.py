"""
Collector — discovery + monitoring loop.
"""
import time
import statistics
import traceback
from ping3 import ping
import config
import database
import discovery
from concurrent.futures import ThreadPoolExecutor, as_completed

# ------------------------------------------------------------------------------
# Admin check (Windows)
# ------------------------------------------------------------------------------
def _check_admin():
    import sys, ctypes
    if sys.platform != "win32":
        return True
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


# ------------------------------------------------------------------------------
# Metrics
# ------------------------------------------------------------------------------
def measure_device(ip):
    samples = []
    sent = config.PING_COUNT
    received = 0

    for _ in range(config.PING_COUNT):
        try:
            result = ping(ip, timeout=config.PING_TIMEOUT, unit="ms")
            if result is not None:
                received += 1
                samples.append(float(result))
        except Exception as exc:
            print(f"  ping error for {ip}: {exc}")
        time.sleep(config.PING_INTERVAL)

    packet_loss = ((sent - received) / sent) * 100

    if received == 0:
        return {
            "status": "Offline",
            "packets_sent": sent,
            "packets_received": 0,
            "packet_loss": round(packet_loss, 2),
            "latency_ms": None,
            "jitter_ms": None,
        }

    latency = statistics.mean(samples)
    jitter = 0.0
    if len(samples) >= 2:
        diffs = [abs(samples[i] - samples[i - 1])
                 for i in range(1, len(samples))]
        jitter = statistics.mean(diffs)

    return {
        "status": "Online",
        "packets_sent": sent,
        "packets_received": received,
        "packet_loss": round(packet_loss, 2),
        "latency_ms": round(latency, 2),
        "jitter_ms": round(jitter, 2),
    }


# ------------------------------------------------------------------------------
# Discovery
# ------------------------------------------------------------------------------
def run_discovery():
    print()
    print("=" * 60)
    print("NETWORK DISCOVERY")
    print("=" * 60)

    try:
        found = discovery.discover_devices_multi(
            config.SUBNET,
            timeout=getattr(config, "DISCOVERY_TIMEOUT", 5),
            ifaces=getattr(config, "DISCOVERY_IFACES", None),
        )
    except Exception as exc:
        print(f"[discovery] EXCEPTION: {exc}")
        traceback.print_exc()
        return []

    print(f"[discovery] raw results: {len(found)} device(s)")

    # Only dump individual devices when the list is small
    if len(found) <= 20:
        for dev in found:
            print(f"    -> {dev}")
    elif found:
        print(f"    (showing first 3 of {len(found)})")
        for dev in found[:3]:
            print(f"    -> {dev}")

    if not found:
        print("[discovery] nothing found — check:")
        print("   - are you running as Administrator / root?")
        print("   - does config.SUBNET match your real subnet?")
        print("   - is Wi-Fi client isolation disabled on the router?")
        return []

    try:
        registered_macs = database.get_registered_macs()
    except Exception as exc:
        print(f"[whitelist] ERROR reading whitelist: {exc}")
        registered_macs = set()

    print(f"[whitelist] {len(registered_macs)} MACs registered")

    new_unknowns = []
    saved_count = 0
    updated_count = 0

    for dev in found:
        ip     = dev.get("ip")
        mac    = (dev.get("mac") or "").upper()
        domain = dev.get("domain") or "unknown.local"

        if not ip:
            continue

        is_registered = mac in registered_macs
        is_known = 1 if is_registered else 0
        classification = "known" if is_registered else "unknown"

        try:
            existing = database.get_device_by_ip(ip)
        except Exception as exc:
            print(f"  [ERROR] get_device_by_ip({ip}): {exc}")
            continue

        if existing is None:
            # ONLY save to the database if the device is KNOWN
            if is_registered:
                try:
                    database.save_discovered_device(
                        ip=ip,
                        mac=mac,
                        domain=domain,
                        subnet=config.SUBNET,
                        classification=classification,
                        is_known=is_known,
                    )
                    saved_count += 1
                except Exception as exc:
                    print(f"  [SAVE FAILED] {ip} {mac}: {exc}")
            else:
                # If it's unknown, just keep it in memory to alert the admin
                new_unknowns.append(dev)
        else:
            # Only log transitions, not every device every scan
            if existing["is_known"] != is_known:
                try:
                    conn = database.get_connection()
                    conn.execute("""
                        UPDATE devices
                           SET is_known = ?, classification = ?
                         WHERE id = ?
                    """, (is_known, classification, existing["id"]))
                    conn.commit()
                    conn.close()
                    updated_count += 1
                    print(f"  [UPDATED] {ip:<15} {mac} "
                          f"-> {'KNOWN' if is_known else 'UNKNOWN'}")
                except Exception as exc:
                    print(f"  [UPDATE FAILED] {ip}: {exc}")

    print(f"[discovery] {len(found)} found, "
          f"{saved_count} newly saved, "
          f"{updated_count} state change(s), "
          f"{len(new_unknowns)} new unknown(s)")

    if new_unknowns:
        alert_administrator(new_unknowns)

    return new_unknowns


def alert_administrator(devices):
    print()
    print("!" * 60)
    print(f"  ALERT: {len(devices)} NEW UNKNOWN DEVICE(S) DETECTED")
    print("!" * 60)
    # Only print the first 10 to keep the log readable
    for d in devices[:10]:
        ip     = d.get("ip", "?")
        mac    = d.get("mac", "?")
        domain = d.get("domain") or "unknown.local"
        print(f"  IP: {ip:<15} MAC: {mac}  Domain: {domain}")
    if len(devices) > 10:
        print(f"  ... and {len(devices) - 10} more")
    print("!" * 60)
    print()


# ------------------------------------------------------------------------------
# Monitoring cycle
# ------------------------------------------------------------------------------

def run_monitoring_cycle():
    devices = database.get_known_devices()

    if not devices:
        print("No known devices to monitor.")
        return

    # Start with 10 simultaneous device measurements.
    max_workers = min(10, len(devices))

    print(
        f"\nMonitoring {len(devices)} known devices "
        f"using {max_workers} workers..."
    )

    online = 0
    offline = 0
    errors = 0

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Workers only ping devices; database operations stay in this thread.
        futures = {
            executor.submit(measure_device, device["ip_address"]): device
            for device in devices
        }

        for future in as_completed(futures):
            device = futures[future]
            ip = device["ip_address"]

            try:
                result = future.result()

                database.update_device_status(
                    device["id"], result["status"]
                )
                database.save_metrics(device["id"], result)

                if result["status"] == "Online":
                    online += 1
                else:
                    offline += 1

                name = device.get("device_name") or ip
                print(
                    f"{name:<25} {result['status']:<8} "
                    f"loss={result['packet_loss']}% "
                    f"lat={result['latency_ms']}ms "
                    f"jit={result['jitter_ms']}ms"
                )

            except Exception as exc:
                errors += 1
                print(f"[MONITORING ERROR] {ip}: {exc}")

    print(
        f"\nCycle complete: {online} online, "
        f"{offline} offline, {errors} errors "
        f"(of {len(devices)} devices)."
    )


# ------------------------------------------------------------------------------
# Main
# ------------------------------------------------------------------------------
def run():
    if not _check_admin():
        print("!" * 60)
        print("  WARNING: NOT running as Administrator.")
        print("  ARP discovery WILL return 0 devices on Windows.")
        print("  Close this window and reopen PowerShell as Administrator.")
        print("!" * 60)
        print()

    database.init_db()

    print("=" * 60)
    print("COLLECTOR STARTED")
    print(f"subnet          : {config.SUBNET}")
    print(f"discovery iface : {config.DISCOVERY_IFACES}")
    print(f"monitor every   : {config.MONITOR_INTERVAL}s")
    print(f"discovery every : {config.DISCOVERY_INTERVAL}s")
    print("=" * 60)

    run_discovery()
    last_discovery = time.time()

    try:
        while True:
            if time.time() - last_discovery >= config.DISCOVERY_INTERVAL:
                run_discovery()
                last_discovery = time.time()

            run_monitoring_cycle()

            print(f"\nsleeping {config.MONITOR_INTERVAL}s...\n")
            time.sleep(config.MONITOR_INTERVAL)
    except KeyboardInterrupt:
        print("\n[collector] stopped by user")


if __name__ == "__main__":
    run()