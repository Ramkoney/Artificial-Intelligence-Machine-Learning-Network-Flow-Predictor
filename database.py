"""
SQLite database + CSV Whitelist for network monitoring.
"""
import sqlite3
import os
import csv
from datetime import datetime
import config

DB_PATH = os.path.join(config.DATA_DIR, "bitsflux.db")
REGISTERED_MACS_CSV=os.path.join(config.DATA_DIR,"registered_macs.csv")
REGISTERED_FIELDS=["mac","device_name","owner"]

def get_connection():
    os.makedirs(config.DATA_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            device_name     TEXT,
            ip_address      TEXT UNIQUE NOT NULL,
            mac_address     TEXT,
            domain          TEXT,
            hostname        TEXT,
            subnet          TEXT,
            classification  TEXT DEFAULT 'unknown',
            is_known        INTEGER DEFAULT 0,
            is_blocked      INTEGER DEFAULT 0,
            status          TEXT DEFAULT 'Unknown',
            first_seen      TEXT,
            last_seen       TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS metrics (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id       INTEGER NOT NULL,
            timestamp       TEXT,
            status          TEXT,
            packets_sent    INTEGER,
            packets_received INTEGER,
            packet_loss     REAL,
            latency_ms      REAL,
            jitter_ms       REAL,
            FOREIGN KEY (device_id) REFERENCES devices(id)
        )
    """)
    conn.commit()
    conn.close()
    _ensure_registered_csv()

def _ensure_registered_csv():
    if not os.path.exists(REGISTERED_MACS_CSV):
        os.makedirs(config.DATA_DIR,exist_ok=True)
        with open(REGISTERED_MACS_CSV, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f,fieldnames=REGISTERED_FIELDS)
            writer.writeheader()
        print(f"[registered] created {REGISTERED_MACS_CSV}")

def get_registered_macs():
    """Return set of all registered MACs( uppercase)"""
    _ensure_registered_csv()
    macs =set()
    with open(REGISTERED_MACS_CSV,"r", encoding="utf-8")as f:
        for row in csv.DictReader(f):
            mac =(row.get("mac") or "").upper().strip()
            if mac:
                macs.add(mac)
    return macs
     
def add_registered_mac(mac, device_name="", owner="admin"):
    """Add a MAC to the whitelist CSV. Ignores duplicates."""
    if not mac:
        return False

    _ensure_registered_csv()
    mac = mac.upper().strip()

    if mac in get_registered_macs():
        return False

    with open(REGISTERED_MACS_CSV, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=REGISTERED_FIELDS)
        writer.writerow({
            "mac": mac,
            "device_name": device_name,
            "owner": owner,
        })

    print(f"[registered] + {mac} ({device_name})")
    return True
def remove_registered_mac(mac):
    """Remove a MAC from the whitelist CSV."""
    if not mac or not os.path.exists(REGISTERED_MACS_CSV):
        return False

    mac = mac.upper().strip()
    rows = []

    with open(REGISTERED_MACS_CSV, "r", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if (row.get("mac") or "").upper().strip() != mac:
                rows.append(row)

    with open(REGISTERED_MACS_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=REGISTERED_FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    print(f"[registered] - {mac}")
    return True  

def get_all_devices():
    conn = get_connection()
    rows = conn.execute("SELECT * FROM devices ORDER BY ip_address").fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_known_devices():
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM devices WHERE is_known = 1 ORDER BY ip_address"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_unknown_devices():
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM devices WHERE is_known = 0 ORDER BY ip_address"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_device(device_id):
    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM devices WHERE id = ?", (device_id,)
    ).fetchone()
    conn.close()
    return dict(row) if row else None

def get_device_by_ip(ip):
    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM devices WHERE ip_address = ?", (ip,)
    ).fetchone()
    conn.close()
    return dict(row) if row else None

def create_device(device_name, ip_address, mac_address=None, domain=None,
                  hostname=None, subnet=None,
                  classification="known", is_known=1):
    now = datetime.now().isoformat()
    conn = get_connection()
    cursor = conn.execute("""
        INSERT INTO devices
            (device_name, ip_address, mac_address, domain, hostname,
             subnet, classification, is_known, first_seen, last_seen)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (device_name, ip_address, mac_address, domain, hostname,
          subnet, classification, is_known, now, now))
    conn.commit()
    new_id = cursor.lastrowid
    conn.close()
    if mac_address:
        add_registered_mac(mac_address,device_name,owner="web-form")
    return new_id

def save_discovered_device(ip, mac=None, domain=None, subnet=None,
                           classification="unknown", is_known=0):
    now = datetime.now().isoformat()
    conn = get_connection()
    cursor = conn.execute("""
        INSERT INTO devices
            (device_name, ip_address, mac_address, domain, hostname,
             subnet, classification, is_known, first_seen, last_seen)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        None,              
        ip, mac, domain, None,
        subnet, classification, is_known, now, now
    ))
    conn.commit()
    new_id = cursor.lastrowid
    conn.close()
    return new_id

def create_unknown_device(ip, mac=None, domain=None):
    return save_discovered_device(
        ip=ip, mac=mac, domain=domain,
        classification="unknown", is_known=0,
    )

def update_device(device_id, name, ip, mac):
    now = datetime.now().isoformat()
    conn = get_connection()
    conn.execute("""
        UPDATE devices
           SET device_name = ?, ip_address = ?, mac_address = ?, last_seen = ?
         WHERE id = ?
    """, (name, ip, mac, now, device_id))
    conn.commit()
    conn.close()


def update_device_metadata(
    device_id,
    mac=None,
    domain=None,
    hostname=None,
    subnet=None,
    status=None
):
    conn = get_connection()

    try:
        fields = []
        values = []

        if mac is not None:
            fields.append("mac_address = ?")
            values.append(mac)

        if domain is not None:
            fields.append("domain = ?")
            values.append(domain)

        if hostname is not None:
            fields.append("hostname = ?")
            values.append(hostname)

        if subnet is not None:
            fields.append("subnet = ?")
            values.append(subnet)

        if status is not None:
            fields.append("status = ?")
            values.append(status)

        fields.append("last_seen = ?")
        values.append(datetime.now().isoformat())

        values.append(device_id)

        conn.execute(
            f"UPDATE devices SET {', '.join(fields)} WHERE id = ?",
            values
        )

        conn.commit()
    finally:
        conn.close()

def update_device_status(device_id, status):
    now = datetime.now().isoformat()
    conn = get_connection()
    conn.execute("""
        UPDATE devices SET status = ?, last_seen = ? WHERE id = ?
    """, (status, now, device_id))
    conn.commit()
    conn.close()


def approve_device(device_id, name=None):
    """Approve an existing discovered device and whitelist its MAC."""
    conn = get_connection()

    try:
        device = conn.execute(
            "SELECT * FROM devices WHERE id = ?",
            (device_id,)
        ).fetchone()

        if device is None:
            return False

        device = dict(device)
        approved_name = (
            name or device.get("device_name") or device["ip_address"]
        ).strip()

        conn.execute("""
            UPDATE devices
               SET is_known = 1,
                   classification = 'known',
                   device_name = ?,
                   last_seen = ?
             WHERE id = ?
        """, (
            approved_name,
            datetime.now().isoformat(),
            device_id
        ))

        conn.commit()

    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

    mac = (device.get("mac_address") or "").strip()

    if mac:
        add_registered_mac(
            mac,
            approved_name,
            owner="approved-by-admin"
        )

    return True

def mark_device_unknown(device_id):
    conn = get_connection()
    conn.execute("""
        UPDATE devices
           SET is_known = 0, classification = 'unknown'
         WHERE id = ?
    """, (device_id,))
    conn.commit()
    conn.close()

    device = get_device(device_id)
    if device and device.get("mac_address"):          
        remove_registered_mac(device["mac_address"])
        
def set_device_blocked(device_id, blocked):
     conn = get_connection()
     conn.execute(
        "UPDATE devices SET is_blocked = ? WHERE id = ?",
        (1 if blocked else 0, device_id),
    )
     conn.commit()
     conn.close()
    
def delete_device(device_id):
    device = get_device(device_id)  
    conn = get_connection()
    conn.execute("DELETE FROM metrics WHERE device_id = ?", (device_id,))
    conn.execute("DELETE FROM devices WHERE id = ?", (device_id,))
    conn.commit()
    conn.close()
    
    if device and device.get("mac_address"):
        remove_registered_mac(device["mac_address"])
     

def save_metrics(device_id, result):
    now = datetime.now().isoformat()
    conn = get_connection()

    try:
        conn.execute("""
            INSERT INTO metrics (
                device_id, timestamp, status,
                packets_sent, packets_received,
                packet_loss, latency_ms, jitter_ms
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            device_id,
            now,
            result.get("status"),
            result.get("packets_sent", 0),
            result.get("packets_received", 0),
            result.get("packet_loss", 0.0),
            result.get("latency_ms"),
            result.get("jitter_ms")
        ))

        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()

def get_latest_metrics_all():
    conn = get_connection()

    try:
        rows = conn.execute("""
            SELECT
                m.*,
                d.device_name,
                d.ip_address,
                d.status AS device_status
            FROM metrics m
            JOIN devices d ON d.id = m.device_id
            WHERE d.is_known = 1
              AND m.id = (
                  SELECT MAX(m2.id)
                  FROM metrics m2
                  WHERE m2.device_id = d.id
              )
            ORDER BY m.id DESC
        """).fetchall()

        return [dict(row) for row in rows]

    finally:
        conn.close()
def get_metrics_history(device_id, limit=50):
    conn = get_connection()
    rows = conn.execute("""
        SELECT * FROM metrics
         WHERE device_id = ?
         ORDER BY id DESC
         LIMIT ?
    """, (device_id, limit)).fetchall()
    conn.close()
    return [dict(r) for r in rows]