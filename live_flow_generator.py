import os
import time
import threading
import queue
from datetime import datetime

import pandas as pd

from prediction.predict import IntrusionPredictor


class LiveFlowGenerator:

    def __init__(self):

        self.running = False
        self.stop_event = threading.Event()

        self.lock = threading.Lock()
        self.events = queue.Queue()

        self.batch_size = 10
        self.interval = 30

        self.current_index = 0

        script_dir = os.path.dirname(os.path.abspath(__file__))
        base_dir = os.path.dirname(script_dir)

        self.dataset_path = os.path.join(
            base_dir,
            "prediction",
            "data",
            "UNSW_NB15_testing-set.parquet"
        )

        self.dataset = None
        self.predictor = IntrusionPredictor().load()

    def load_dataset(self):

        if self.dataset is None:

            self.dataset = pd.read_parquet(self.dataset_path)

            # Use the features expected by the trained model.
            features = self.predictor.feature_names

            if features:
                self.dataset = self.dataset[features]

            print(f"Loaded {len(self.dataset)} network flows")

        return self.dataset

    def start(self):

        with self.lock:

            if self.running:
                return False

            self.load_dataset()

            if self.current_index >= len(self.dataset):
                self.current_index = 0

            self.stop_event.clear()
            self.running = True

            self.thread = threading.Thread(
                target=self.generate,
                daemon=True
            )

            self.thread.start()

            return True

    def stop(self):

        with self.lock:

            if not self.running:
                return False

            self.running = False
            self.stop_event.set()

            return True

    def generate(self):

        try:

            while not self.stop_event.is_set():

                start = self.current_index
                end = min(
                    start + self.batch_size,
                    len(self.dataset)
                )

                batch = self.dataset.iloc[start:end]

                if batch.empty:
                    self.current_index = 0
                    continue

                predictions = self.predictor.predict_batch(batch)

                for (_, record), prediction in zip(
                    batch.iterrows(),
                    predictions
                ):

                    if self.stop_event.is_set():
                        break

                    flow = record.to_dict()

                    event = {
                        "timestamp": datetime.now().strftime(
                            "%Y-%m-%d %H:%M:%S"
                        ),

                        "label": prediction["label"],
                        "prediction": prediction["prediction"],
                        "confidence": prediction["confidence"],

                        "src": str(flow.get("srcip", "Unknown")),
                        "dst": str(flow.get("dstip", "Unknown")),

                        "proto": str(flow.get("proto", "Unknown")),
                        "service": str(flow.get("service", "Unknown")),

                        "sbytes": int(flow.get("sbytes", 0)),
                        "dbytes": int(flow.get("dbytes", 0))
                    }

                    self.events.put(event)

                self.current_index = end

                if self.current_index >= len(self.dataset):
                    self.current_index = 0

                # Wait 30 seconds before reading the next batch.
                if self.stop_event.wait(self.interval):
                    break

        except Exception as error:

            print("Live flow generation error:", error)

        finally:

            with self.lock:
                self.running = False