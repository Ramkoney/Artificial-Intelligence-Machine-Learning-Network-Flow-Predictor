 
import os
import joblib
import pandas as pd
import numpy as np
from scipy.sparse import issparse   

class IntrusionPredictor:
    """Load trained model and predict on new network traffic."""

    def __init__(self, model_dir=None):
      if model_dir is None:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        base_dir = os.path.dirname(script_dir)
        model_dir = os.path.join(base_dir, "prediction","models")
      self.model_dir = model_dir
      self.model = None
      self.preprocessor = None
      self.feature_names = None
      

    def load(self):
        """Load model artifacts."""
        model_path = os.path.join(self.model_dir, "xgboost_model.joblib")
        preprocessor_path = os.path.join(self.model_dir, "preprocessor.joblib")
        feature_names_path = os.path.join(self.model_dir, "feature_names.joblib")

        if not os.path.exists(model_path):
            raise FileNotFoundError(
                f"Model not found at {model_path}. Run 'python train_model.py' first."
            )

        self.model = joblib.load(model_path)
        self.preprocessor = joblib.load(preprocessor_path)
        self.feature_names = joblib.load(feature_names_path)

        print("Model loaded successfully")
        return self

    def _transform(self, data):
        """Helper: transform data and always return a dense array."""
        X_proc = self.preprocessor.transform(data)
        
        if issparse(X_proc):
            X_proc = X_proc.toarray()
        return X_proc

    def predict(self, data):
        """Predict a single record (dict) or DataFrame."""
        if self.model is None:
            self.load()

        if isinstance(data, dict):
            data = pd.DataFrame([data])

        X_proc = self._transform(data)

        pred = int(self.model.predict(X_proc)[0])
        proba = float(self.model.predict_proba(X_proc)[:, 1][0])

        return {
            "prediction": pred,
            "label": "Attack" if pred == 1 else "Normal",
            "probability": proba,
            "confidence": proba if pred == 1 else 1 - proba,
        }

    def predict_batch(self, data):
        """Predict on a list of dicts or DataFrame."""
        if self.model is None:
            self.load()

        if isinstance(data, list):
            data = pd.DataFrame(data)

        X_proc = self._transform(data)

        preds = self.model.predict(X_proc)
        probas = self.model.predict_proba(X_proc)[:, 1]

        return [
            {
                "prediction": int(p),
                "label": "Attack" if p == 1 else "Normal",
                "probability": float(pr),
                "confidence": float(pr if p == 1 else 1 - pr),
            }
            for p, pr in zip(preds, probas)
        ]


if __name__ == "__main__":
    print("Testing predictor...")
    predictor = IntrusionPredictor().load()

       
    script_dir = os.path.dirname(os.path.abspath(__file__))
    base_dir = os.path.dirname(script_dir)
    test_path = os.path.join(base_dir, "prediction","data", "UNSW_NB15_testing-set.parquet")
    sample_df = pd.read_parquet(test_path).head(5)
    results = predictor.predict_batch(sample_df)
    for i, r in enumerate(results):
        print(f"Row {i+1}: {r['label']} (confidence: {r['confidence']:.2%})")
        
   