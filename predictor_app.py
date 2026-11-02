
import json
import logging
import queue
from datetime import datetime
from pathlib import Path

import pandas as pd
from flask import Flask, Response, jsonify, render_template, request

from predict import IntrusionPredictor




BASE_DIR = Path(__file__).resolve().parent
MODEL_DIR = BASE_DIR / "models"
SIMULATION_CSV = BASE_DIR / "synthetic_attacks.csv"
TEST_DATASET = BASE_DIR / "data" / "UNSW_NB15_testing-set.parquet"

app = Flask(__name__)
app.logger.setLevel(logging.INFO)

# Queue used by the dashboard's Server-Sent Events endpoint.
alert_queue = queue.Queue(maxsize=1000)

# These names must match the row order in synthetic_attacks.csv.
# Verify the order before relying on the correctness statistics.
DEFAULT_SCENARIOS = [
    "High-volume traffic",
    "Port-scan-like pattern",
    "HTTP-flood-like pattern",
    "SSH-brute-force-like pattern",
    "FTP-brute-force-like pattern",
    "RST-heavy pattern",
    "ICMP-like pattern",
    "Possible data-exfiltration pattern",
]


# --------------------------------------------------
# Load the trained model once
# --------------------------------------------------

predictor = None

try:
    print("[NetPulse] Loading trained intrusion detection model...")
    predictor = IntrusionPredictor(model_dir=str(MODEL_DIR)).load()
    print("[NetPulse] Model loaded successfully.")
except FileNotFoundError:
    app.logger.exception(
        "Model files were not found. Check the models directory."
    )
except Exception:
    app.logger.exception("Failed to load the intrusion detection model.")


# --------------------------------------------------
# Helpers
# --------------------------------------------------

def enqueue_alert(alert):
    """Add an alert to the dashboard stream without blocking."""
    try:
        alert_queue.put_nowait(alert)
    except queue.Full:
        app.logger.warning("Alert queue is full; an alert was skipped.")


def get_scenario_names(traffic_df):
    """
    Use scenario names in the CSV when available.
    Otherwise, use configured names only when the row count matches.
    """
    if "scenario" in traffic_df.columns:
        return traffic_df["scenario"].astype(str).tolist()

    if len(traffic_df) == len(DEFAULT_SCENARIOS):
        return DEFAULT_SCENARIOS.copy()

    return [
        f"Simulated scenario {index + 1}"
        for index in range(len(traffic_df))
    ]

def get_expected_labels(traffic_df, row_count):
    """
    Prefer explicit expected labels in the CSV.
    If absent, the configured eight scenarios are assumed to be attacks.
    This fallback is valid only if the CSV row order and contents match.
    """
    if "expected_label" in traffic_df.columns:
        return (
            traffic_df["expected_label"]
            .astype(str)
            .str.strip()
            .str.title()
            .tolist()
        )

    if row_count == len(DEFAULT_SCENARIOS):
        return ["Attack"] * row_count

    # Do not claim correctness when the expected labels are unknown.
    return [None] * row_count


def confidence_as_probability(value):
    """
    Normalize confidence to a 0-1 probability.
    Supports predictors that return either fractions or percentages.
    """
    value = float(value)

    if value > 1:
        value /= 100.0

    return max(0.0, min(1.0, value))


# --------------------------------------------------
# Dashboard pages
# --------------------------------------------------

@app.route("/")
def home():
    return render_template("live.html")


@app.route("/live")
def live_page():
    return render_template("live.html")


# --------------------------------------------------
# Feature information for the prediction form
# --------------------------------------------------

@app.route("/features", methods=["GET"])
def features():
    """Return expected dataset features and a sample value for each."""
    if not TEST_DATASET.exists():
        return jsonify({
            "error": f"Test dataset not found: {TEST_DATASET}"
        }), 404

    try:
        sample = pd.read_parquet(TEST_DATASET).head(1)
        sample = sample.drop(
            columns=["label", "attack_cat", "scenario",
                     "expected_label", "expected_prediction"],
            errors="ignore",
        )

        if sample.empty:
            return jsonify({"error": "The test dataset is empty."}), 500

        sample_dict = {}

        for column in sample.columns:
            value = sample.iloc[0][column]

            if pd.isna(value):
                value = None
            elif hasattr(value, "item"):
                value = value.item()

            sample_dict[column] = {
                "value": value,
                "type": (
                    "number"
                    if pd.api.types.is_numeric_dtype(sample[column])
                    else "text"
                ),
            }

        return jsonify({
            "features": sample_dict,
            "count": len(sample_dict),
        })

    except Exception as exc:
        app.logger.exception("Could not load feature information.")
        return jsonify({"error": str(exc)}), 500


# --------------------------------------------------
# Predict one network-flow record
# --------------------------------------------------

@app.route("/predict", methods=["POST"])
def predict():
    if predictor is None:
        return jsonify({"error": "Intrusion model is not loaded."}), 503

    try:
        data = request.get_json(silent=True)

        if not isinstance(data, dict) or not data:
            return jsonify({
                "error": "Send a non-empty JSON object of model features."
            }), 400

        result = predictor.predict(data)

        # Preserve the original prediction fields and add a display value.
        response = dict(result)
        response["confidence_probability"] = confidence_as_probability(
            result["confidence"]
        )
        response["confidence_percent"] = round(
            response["confidence_probability"] * 100, 2
        )

        return jsonify(response)

    except Exception as exc:
        app.logger.exception("Single-record prediction failed.")
        return jsonify({"error": str(exc)}), 500


# --------------------------------------------------
# Simulated network traffic
# --------------------------------------------------

@app.route("/api/simulate/attacks", methods=["POST"])
def simulate_attacks():
    """
    Predict labels for synthetic network-flow records.
    No live packet capture or real network traffic is used.
    """
    if predictor is None:
        return jsonify({"error": "Intrusion model is not loaded."}), 503

    if not SIMULATION_CSV.exists():
        return jsonify({
            "error": f"Simulation file not found: {SIMULATION_CSV}"
        }), 404

    try:
        traffic_df = pd.read_csv(SIMULATION_CSV)

        if traffic_df.empty:
            return jsonify({"error": "The simulation CSV is empty."}), 400

        # Scenario metadata is for reporting, not for model inference.
        metadata_columns = [
            "scenario",
            "expected_label",
            "expected_prediction",
        ]

        model_input = traffic_df.drop(
            columns=metadata_columns,
            errors="ignore",
        )

        scenario_names = get_scenario_names(traffic_df)
        expected_labels = get_expected_labels(
            traffic_df,
            len(traffic_df),
        )

        # Run the simulated records through the trained model.
        predictions = predictor.predict_batch(model_input)

        if len(predictions) != len(traffic_df):
            raise ValueError(
                "The model returned a different number of predictions "
                "than the number of simulated records."
            )

        results = []
        alerts = []

        for index, prediction in enumerate(predictions):
            scenario = scenario_names[index]
            expected = expected_labels[index]
            predicted = str(prediction["label"]).strip().title()

            confidence_probability = confidence_as_probability(
                prediction["confidence"]
            )

            # The model's probability of the Attack class.
            raw_attack_probability = prediction.get(
                "attack_probability",
                prediction.get("probability", 0.0),
            )
            attack_probability = float(raw_attack_probability)

            # Support attack probabilities returned as fractions or percent.
            if attack_probability > 1:
                attack_probability /= 100.0

            attack_probability = max(
                0.0,
                min(1.0, attack_probability),
            )

            correct = (
                predicted == expected
                if expected is not None
                else None
            )

            result = {
                "scenario": scenario,
                "expected_label": expected,
                "prediction": int(prediction["prediction"]),
                "label": predicted,
                "probability": attack_probability,
                "attack_probability_percent": round(
                    attack_probability * 100, 2
                ),
                "confidence": confidence_probability,
                "confidence_percent": round(
                    confidence_probability * 100, 2
                ),
                "correct": correct,
                "result": (
                    "Correct" if correct is True
                    else "Misclassified" if correct is False
                    else "Not evaluated"
                ),
            }

            results.append(result)

            # Publish both Attack and Normal predictions.
            alert = {
                "timestamp": datetime.now().strftime("%H:%M:%S"),
                "source": "simulation",
                "src": "SIMULATED",
                "dst": "NETPULSE MODEL",
                "src_ip": "SIMULATED",
                "dst_ip": "SIMULATED",
                "attack_type": scenario,
                "scenario": scenario,
                "prediction": result["prediction"],
                "label": predicted,
                "expected_label": expected,
                "probability": attack_probability,
                "confidence": confidence_probability,
                "confidence_percent": result["confidence_percent"],
                "correct": correct,
                "message": f"{scenario}: model predicted {predicted}",
            }

            alerts.append(alert)
            enqueue_alert(alert)

        evaluated_results = [
            result for result in results
            if result["correct"] is not None
        ]

        response = {
            "status": "simulation_complete",
            "mode": "simulation_only",
            "total": len(results),
            "attacks_detected": sum(
                result["label"] == "Attack"
                for result in results
            ),
            "normal_predictions": sum(
                result["label"] == "Normal"
                for result in results
            ),
            "correct_predictions": sum(
                result["correct"] is True
                for result in evaluated_results
            ),
            "misclassified_predictions": sum(
                result["correct"] is False
                for result in evaluated_results
            ),
            "evaluated_predictions": len(evaluated_results),
            "results": results,
            "alerts": alerts,
        }

        app.logger.info(
            "Simulation completed: %s records, %s Attack predictions, "
            "%s Normal predictions.",
            response["total"],
            response["attacks_detected"],
            response["normal_predictions"],
        )

        return jsonify(response)

    except Exception as exc:
        app.logger.exception("Traffic simulation failed.")
        return jsonify({"error": str(exc)}), 500


# --------------------------------------------------
# Dashboard alert stream (Server-Sent Events)
# --------------------------------------------------

@app.route("/stream")
def stream():
    """
    Stream simulated predictions to browsers connected to /stream.
    The frontend must subscribe to this endpoint to display streamed alerts.
    """
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


# --------------------------------------------------
# Start application - simulation-only mode
# --------------------------------------------------

if __name__ == "__main__":
    print("=" * 55)
    print("NetPulse Predictive Monitoring & IDS")
    print("Mode: SIMULATION ONLY")
    print("Live packet capture: DISABLED")
    print("=" * 55)

    app.run(
        debug=True,
        use_reloader=False,
        host="127.0.0.1",
        port=5000,
    )
