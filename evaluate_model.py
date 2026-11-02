
import os
import pandas as pd
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score,
)

from predict import IntrusionPredictor


def main():
    predictor = IntrusionPredictor().load()

    script_dir = os.path.dirname(os.path.abspath(__file__))
    base_dir = os.path.dirname(script_dir)
    test_path = os.path.join(
        base_dir, "data", "UNSW_NB15_testing-set.parquet"
    )

    df = pd.read_parquet(test_path)

    if "label" not in df.columns:
        raise ValueError(
            "The testing dataset has no 'label' column. "
            "Inspect its columns and identify the target column."
        )

    # UNSW-NB15 uses 0 for normal and 1 for attack.
    y_true = df["label"].astype(int)

    # Exclude target/metadata columns; the predictor selects
    # the exact raw input features required by the preprocessor.
    results = predictor.predict_batch(df)
    y_pred = [result["prediction"] for result in results]

    print(f"Testing records: {len(df)}")
    print(f"Accuracy: {accuracy_score(y_true, y_pred):.4f}")
    print("\nConfusion matrix (rows=true, columns=predicted):")
    print(confusion_matrix(y_true, y_pred, labels=[0, 1]))
    print("\nClassification report:")
    print(
        classification_report(
            y_true,
            y_pred,
            labels=[0, 1],
            target_names=["Normal", "Attack"],
            zero_division=0,
        )
    )


if __name__ == "__main__":
    main()
