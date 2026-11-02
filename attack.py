"""
Generate a synthetic UNSW-NB15-format attack file
that matches the trained NetPulse XGBoost model.
"""

import os
import pandas as pd

MODELS_DIR = r"C:\Users\User\Downloads\archive (1)\models"
OUT_PATH   = os.path.join(os.path.dirname(__file__), "synthetic_attacks.csv")


NUMERIC_COLS = [
    "dur", "spkts", "dpkts", "sbytes", "dbytes",
    "rate", "sload", "dload", "sloss", "dloss",
    "sinpkt", "dinpkt", "sjit", "djit", "swin",
    "stcpb", "dtcpb", "dwin", "tcprtt", "synack",
    "ackdat", "smean", "dmean", "trans_depth",
    "response_body_len", "ct_src_dport_ltm",
    "ct_dst_sport_ltm", "is_ftp_login",
    "ct_ftp_cmd", "ct_flw_http_mthd",
    "is_sm_ips_ports",
]
CATEGORICAL_COLS = ["proto", "service", "state"]
ALL_COLS = NUMERIC_COLS + CATEGORICAL_COLS


def blank_record():
    rec = {c: 0 for c in NUMERIC_COLS}
    for c in CATEGORICAL_COLS:
        rec[c] = "-"
    return rec


attacks = []

# 1. DDoS — huge outbound volume, tiny duration
rec = blank_record()
rec.update({
    "dur": 0.005, "proto": "tcp", "service": "-", "state": "INT",
    "spkts": 8000, "dpkts": 0, "sbytes": 9000000, "dbytes": 0,
    "rate": 999999, "sload": 999999999, "dload": 0,
    "sinpkt": 0.0001, "dinpkt": 0, "smean": 1125,
    "swin": 0, "dwin": 0,
})
attacks.append(rec)

# 2. Port scan — many small packets, no response
rec = blank_record()
rec.update({
    "dur": 0.8, "proto": "tcp", "service": "-", "state": "INT",
    "spkts": 2000, "dpkts": 0, "sbytes": 120000, "dbytes": 0,
    "rate": 2500, "sload": 150000, "dload": 0,
    "ct_src_dport_ltm": 800, "ct_dst_sport_ltm": 800,
    "sinpkt": 0.0004,
})
attacks.append(rec)

# 3. FTP brute force
rec = blank_record()
rec.update({
    "dur": 0.05, "proto": "tcp", "service": "ftp", "state": "CON",
    "spkts": 20, "dpkts": 18, "sbytes": 2000, "dbytes": 1800,
    "rate": 400, "sload": 40000, "dload": 36000,
    "ct_src_dport_ltm": 300, "ct_dst_sport_ltm": 300,
    "swin": 8192, "dwin": 8192,
})
attacks.append(rec)

# 4. SSH brute force
rec = blank_record()
rec.update({
    "dur": 0.2, "proto": "tcp", "service": "ssh", "state": "CON",
    "spkts": 40, "dpkts": 35, "sbytes": 4000, "dbytes": 3500,
    "rate": 200, "sload": 20000, "dload": 17500,
    "ct_src_dport_ltm": 500, "ct_dst_sport_ltm": 500,
    "swin": 64240, "dwin": 64240,
})
attacks.append(rec)

# 5. Data exfiltration — huge inbound, long duration
rec = blank_record()
rec.update({
    "dur": 600, "proto": "tcp", "service": "ssl", "state": "CON",
    "spkts": 50, "dpkts": 12000, "sbytes": 5000, "dbytes": 100000000,
    "rate": 20, "sload": 8000, "dload": 166666666,
    "dinpkt": 0.05, "dmean": 8333,
    "swin": 64240, "dwin": 64240,
})
attacks.append(rec)

# 6. HTTP flood — HIGH-rate, state INT, no HTTP-depth features
rec = blank_record()
rec.update({
    "dur": 0.05, "proto": "tcp", "service": "http", "state": "INT",
    "spkts": 30000, "dpkts": 0, "sbytes": 60000000, "dbytes": 0,
    "rate": 999999, "sload": 999999999, "dload": 0,
    "sinpkt": 0.000001, "dinpkt": 0,
    "trans_depth": 0, "response_body_len": 0,
    "ct_flw_http_mthd": 0,
    "swin": 0, "dwin": 0,
})
attacks.append(rec)

# 7. RST storm — asymmetric, very fast, no symmetric TTL
rec = blank_record()
rec.update({
    "dur": 0.0005, "proto": "tcp", "service": "-", "state": "RST",
    "spkts": 5000, "dpkts": 5, "sbytes": 250000, "dbytes": 250,
    "rate": 9999999, "sload": 999999999, "dload": 1000,
    "sloss": 500, "dloss": 0,
    "smean": 50, "dmean": 50,
})
attacks.append(rec)

# 8. ICMP flood — very high rate, no responses
rec = blank_record()
rec.update({
    "dur": 0.001, "proto": "icmp", "service": "-", "state": "INT",
    "spkts": 50000, "dpkts": 0, "sbytes": 4000000, "dbytes": 0,
    "rate": 9999999, "sload": 999999999, "dload": 0,
    "sinpkt": 0.0000001, "smean": 80,
})
attacks.append(rec)


df = pd.DataFrame(attacks, columns=ALL_COLS)
df.to_csv(OUT_PATH, index=False)

print(f"Wrote {len(df)} attack rows to {OUT_PATH}")
print(f"Columns: {len(df.columns)}")
print(df.head(10).to_string())