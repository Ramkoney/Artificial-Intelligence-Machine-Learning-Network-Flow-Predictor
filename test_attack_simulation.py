
import pandas as pd
from predict import IntrusionPredictor

def make_record(**overrides):
    """Create one record using the preprocessor's raw input features."""
    record = {
        "dur": 1.0,
        "proto": "tcp",
        "service": "-",
        "state": "FIN",
        "spkts": 10,
        "dpkts": 8,
        "sbytes": 800,
        "dbytes": 600,
        "rate": 18.0,
        "sload": 6400.0,
        "dload": 4800.0,
        "sloss": 0,
        "dloss": 0,
        "sinpkt": 100.0,
        "dinpkt": 125.0,
        "sjit": 0.0,
        "djit": 0.0,
        "swin": 255,
        "stcpb": 0,
        "dtcpb": 0,
        "dwin": 255,
        "tcprtt": 0.05,
        "synack": 0.02,
        "ackdat": 0.03,
        "smean": 80,
        "dmean": 75,
        "trans_depth": 0,
        "response_body_len": 0,
        "ct_src_dport_ltm": 1,
        "ct_dst_sport_ltm": 1,
        "is_ftp_login": 0,
        "ct_ftp_cmd": 0,
        "ct_flw_http_mthd": 0,
        "is_sm_ips_ports": 0,
    }
    record.update(overrides)
    return record


test_cases = [
    (
        "Normal baseline",
        make_record(),
    ),
    (
        "High-volume traffic",
        make_record(
            dur=0.01, spkts=1000, dpkts=5,
            sbytes=500000, dbytes=200,
            rate=50000.0, sload=400000000.0,
        ),
    ),
    (
        "Port-scan-like pattern",
        make_record(
            dur=0.2, spkts=80, dpkts=2,
            sbytes=4800, dbytes=80,
            ct_src_dport_ltm=50, ct_dst_sport_ltm=40,
            state="INT",
        ),
    ),
    (
        "HTTP-flood-like pattern",
        make_record(
            proto="tcp", service="http", state="REQ",
            dur=0.1, spkts=500, dpkts=10,
            sbytes=30000, dbytes=500,
            rate=10000.0, ct_src_dport_ltm=100,
            ct_flw_http_mthd=1,
        ),
    ),
    (
        "SSH brute-force-like pattern",
        make_record(
            service="ssh", state="CON",
            ct_src_dport_ltm=30, ct_dst_sport_ltm=25,
            spkts=60, dpkts=30,
        ),
    ),
    (
        "FTP brute-force-like pattern",
        make_record(
            service="ftp", state="CON",
            is_ftp_login=1, ct_ftp_cmd=1,
            ct_src_dport_ltm=25,
        ),
    ),
    (
        "RST-heavy pattern",
        make_record(
            state="RST", spkts=100, dpkts=1,
            sbytes=6000, dbytes=40,
            ct_src_dport_ltm=30,
        ),
    ),
    (
        "ICMP-like pattern",
        make_record(
            proto="icmp", service="-", state="ECO",
            spkts=200, dpkts=200,
            sbytes=12000, dbytes=12000,
            rate=400.0,
        ),
    ),
    (
        "Possible data-exfiltration pattern",
        make_record(
            dur=10.0, spkts=100, dpkts=5,
            sbytes=1000000, dbytes=200,
            sload=800000.0, dload=160.0,
            smean=10000, ct_src_dport_ltm=10,
        ),
    ),
]


def main():
    predictor = IntrusionPredictor().load()
    records = [record for _, record in test_cases]
    results = predictor.predict_batch(pd.DataFrame(records))

    output = []

    for (scenario, _), result in zip(test_cases, results):
        row = {
            "scenario": scenario,
            "prediction": result["label"],
            "confidence": round(result["confidence"] * 100, 2),
            "attack_probability": round(
                result["probability"] * 100, 2
            ),
        }
        output.append(row)

        print(
            f"{scenario}: {result['label']} "
            f"(confidence {result['confidence']:.2%})"
        )

    output_path = "attack_simulation_results.csv"
    pd.DataFrame(output).to_csv(output_path, index=False)
    print(f"\nResults saved to {output_path}")


if __name__ == "__main__":
    main()
