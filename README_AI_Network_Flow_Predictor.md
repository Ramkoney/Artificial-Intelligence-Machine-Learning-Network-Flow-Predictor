# AI Network Flow Predictor

### Machine-Learning-Based Network Traffic Classification and Intrusion Detection

## Overview

AI Network Flow Predictor is a Python-based prototype that uses a
trained XGBoost model to classify network-flow records as **attack** or
**normal**. The project uses the UNSW-NB15 intrusion-detection dataset
for model evaluation and includes prediction, feature-validation and
attack-simulation components.

It is intended for educational and defensive research. Model predictions
are decision-support signals, not proof that traffic is malicious or
safe.

## Key Features

-   XGBoost-based network-flow classification.
-   Evaluation against the UNSW-NB15 testing dataset.
-   Flask prediction interface/API.
-   Attack-scenario simulation for demonstrations.
-   Validation of the input features expected by the trained model.
-   Dashboard display of attack and normal prediction counts.

## Technology Stack

-   Python, XGBoost
-   Pandas and NumPy
-   Flask
-   Joblib model artifacts
-   UNSW-NB15 dataset
-   HTML, CSS and JavaScript for the dashboard, where included

## Project Structure

The project has included the following scripts and artifacts; paths may
vary by version.

``` text
AI-Network-Flow-Predictor/
├── app.py
├── train_model.py
├── evaluate_model.py
├── live_capture.py
├── attack.py
├── test_attack_simulation.py
├── src/
│   └── predict.py
├── models/
│   ├── xgboost_model.joblib
│   ├── preprocessor.joblib
│   └── feature_names.joblib
└── data/
    └── UNSW_NB15_testing-set.parquet
```

## Dataset and Model Evaluation

The project uses the **UNSW-NB15** network intrusion-detection dataset.
The testing split is intended to evaluate the trained model on held-out
records.

### Reported model test result

  Item                          Result
  ----------------------------- ---------------------------------------
  Model                         XGBoost
  Test data                     `UNSW_NB15_testing-set.parquet`
  Reported test accuracy        **90.25%**
  Precision, recall, F1-score   Not available in the recorded results
  Confusion matrix              Not available in the recorded results

**Verification note:** The 90.25% accuracy was recorded in the project's
earlier testing notes; it was not independently rerun while preparing
this README. Run `evaluate_model.py` against the current model and
dataset to confirm it before treating it as the final reproducible
result. Accuracy alone does not show per-class performance, so report
precision, recall, F1-score and a confusion matrix when the evaluation
script provides them.

## Functional and Integration Test Results

These results come from recorded project checks and a dashboard
demonstration. They are not all model-accuracy measurements.

  ------------------------------------------------------------------------
  Check                              Recorded result What it means
  --------------------- ---------------------------- ---------------------
  Model evaluation      **90.25% reported accuracy** Dataset-based result;
                                                     rerun to verify

  Expected input                              **34** The recorded
  features                                           model/live-input
                                                     integration expected
                                                     34 feature fields

  Missing-feature                           **`[]`** No missing required
  validation                                         features were
                                                     reported in that
                                                     check

  Dashboard                    **21 flows received** Number of flow
  demonstration                                      records shown in that
                                                     run

  Predictions in             **16 attack, 5 normal** Prediction counts
  demonstration                                      from that run only
  ------------------------------------------------------------------------

### Dashboard result interpretation

During the recorded dashboard demonstration, 21 flows were received: 16
were predicted as attacks and 5 as normal. These are **prediction
counts, not accuracy**. Without ground-truth labels for those same 21
records, the counts do not show how many predictions were correct.

### Recommended tests before release

-   Run `python evaluate_model.py` and save the actual output.
-   Run `python test_attack_simulation.py` and record its pass/fail
    results.
-   Verify the model, preprocessor and feature-name artifacts load
    successfully.
-   Test valid input and malformed or missing feature input.
-   Clearly label simulated results; do not describe them as live
    detection.
-   Test live capture only in an authorised environment and document its
    limitations.

Only mark a test as passed after checking the current output.

## Running the Project

These commands assume the scripts are in the project root and the
required dependencies are installed. Adjust paths if your repository
differs.

1.  Create and activate a Python virtual environment.

2.  Install dependencies from `requirements.txt`, if the project
    provides one.

3.  Check that model artifacts and the dataset exist at the paths
    expected by the scripts.

4.  Evaluate the model:

    ``` bash
    python evaluate_model.py
    ```

5.  Start the Flask application, if `app.py` is the entry point:

    ``` bash
    python app.py
    ```

6.  Run the simulation tests:

    ``` bash
    python test_attack_simulation.py
    ```

## Prediction Workflow

1.  Receive a flow record with the expected feature fields.
2.  Validate and preprocess the input using the training-time
    preprocessing pipeline.
3.  Pass the processed record to the XGBoost model.
4.  Return the predicted class and confidence value.
5.  Display the result in the dashboard or simulation output.

A confidence value is not a guarantee that a prediction is correct.

## Limitations

-   Results depend on dataset quality, preprocessing and feature-column
    alignment.
-   UNSW-NB15 results may not generalise to every real network or
    previously unseen attack.
-   Synthetic traffic is useful for functional demonstrations but is not
    equivalent to independently labelled live traffic.
-   Live capture depends on permissions, network-interface configuration
    and accurate feature extraction.
-   Recheck the feature schema and evaluation metrics after changing the
    model or preprocessing pipeline.

## Future Improvements

-   Publish reproducible precision, recall, F1-score and
    confusion-matrix results.
-   Add automated unit and integration tests to CI.
-   Track model versions and evaluation datasets.
-   Evaluate false-positive and false-negative rates on additional
    labelled traffic.
-   Ensure runtime feature extraction matches the training feature
    schema.

## Responsible Use

Capture traffic and simulate attacks only on networks and devices for
which you have explicit authorisation.

## Author

Masola Ramokone Respector , repository https://github.com/Ramkoney/Artificial-Intelligence-Machine-Learning-Network-Flow-Predictor
