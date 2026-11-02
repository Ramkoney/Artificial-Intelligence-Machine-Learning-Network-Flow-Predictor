import os
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import joblib
import xgboost as xgb

from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.compose import ColumnTransformer
from sklearn.model_selection import RandomizedSearchCV, StratifiedKFold
from sklearn.metrics import (
    accuracy_score, roc_auc_score, classification_report, confusion_matrix
)

# ==========================================
# FOLDER PATHS (FIXED)
# ==========================================
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(SCRIPT_DIR)  # This points to the 'backend' folder

# Correct paths based on your VS Code structure
DATA_DIR = os.path.join(BASE_DIR, "prediction", "data")
MODEL_DIR = os.path.join(BASE_DIR, "prediction", "models")
PLOT_DIR = os.path.join(BASE_DIR, "prediction", "plots")

TRAIN_PATH = os.path.join(DATA_DIR, "UNSW_NB15_training-set.parquet")
TEST_PATH  = os.path.join(DATA_DIR, "UNSW_NB15_testing-set.parquet")

# Create directories if they don't exist
os.makedirs(MODEL_DIR, exist_ok=True)
os.makedirs(PLOT_DIR, exist_ok=True)

print(f"Data dir:   {DATA_DIR}")
print(f"Model dir:  {MODEL_DIR}")
print(f"Train file: {TRAIN_PATH}")

RANDOM_STATE = 42

# ==========================================
# LOADING DATA
# ==========================================
print("\n" + "=" * 60)
print(" LOADING DATA")
print("=" * 60)

train_df = pd.read_parquet(TRAIN_PATH)
test_df = pd.read_parquet(TEST_PATH)

print(f"Training: {train_df.shape[0]:,} rows, {train_df.shape[1]} cols")
print(f"Testing:  {test_df.shape[0]:,} rows, {test_df.shape[1]} cols")

# ==========================================
# SPLITTING FEATURES AND TARGET
# ==========================================
print("\n" + "=" * 60)
print(" SPLITTING FEATURES AND TARGET")
print("=" * 60)

X_train = train_df.drop(columns=["label", "attack_cat"])
X_test = test_df.drop(columns=["label", "attack_cat"])
y_train = train_df["label"]
y_test = test_df["label"]

print(f"X_train: {X_train.shape}")
print(f"X_test:  {X_test.shape}")
print(f"Attack rate (train): {y_train.mean():.2%}")
print(f"Attack rate (test):  {y_test.mean():.2%}")

# ==========================================
# DATA CLEANING
# ==========================================
print("\n" + "=" * 60)
print(" DATA CLEANING")
print("=" * 60)

num_cols = X_train.select_dtypes(include=[np.number]).columns.tolist()
X_train[num_cols] = X_train[num_cols].replace([np.inf, -np.inf], np.nan)
X_test[num_cols] = X_test[num_cols].replace([np.inf, -np.inf], np.nan)

# Remove zero-variance features
zero_var = [c for c in num_cols if X_train[c].nunique() <= 1]
if zero_var:
    print(f"Removing zero-variance features: {zero_var}")
    X_train = X_train.drop(columns=zero_var)
    X_test = X_test.drop(columns=zero_var)
    num_cols = [c for c in num_cols if c not in zero_var]

cat_cols = X_train.select_dtypes(include=["object", "category"]).columns.tolist()

print(f"Numerical features: {len(num_cols)}")
print(f"Categorical features: {len(cat_cols)}")

# ==========================================
# CREATING EDA PLOTS
# ==========================================
print("\n" + "=" * 60)
print(" CREATING EDA PLOTS")
print("=" * 60)

plt.figure(figsize=(6, 4))
y_train.value_counts().plot(kind="bar", color=["steelblue", "crimson"])
plt.title("Class Distribution")
plt.xlabel("Class (0=Normal, 1=Attack)")
plt.ylabel("Count")
plt.tight_layout()
plt.savefig(os.path.join(PLOT_DIR, "class_distribution.png"), dpi=150)
plt.close()
print("Saved: plots/class_distribution.png")

if len(num_cols) > 1:
    plt.figure(figsize=(14, 10))
    sns.heatmap(X_train[num_cols].corr(), cmap="coolwarm", center=0)
    plt.title("Correlation Matrix")
    plt.tight_layout()
    plt.savefig(os.path.join(PLOT_DIR, "correlation_heatmap.png"), dpi=150)
    plt.close()
    print("Saved: plots/correlation_heatmap.png")

# ==========================================
# BUILDING PREPROCESSOR
# ==========================================
print("\n" + "=" * 60)
print(" BUILDING PREPROCESSOR")
print("=" * 60)

preprocessor = ColumnTransformer([
    ("num", StandardScaler(), num_cols),
    ("cat", OneHotEncoder(handle_unknown="ignore", sparse_output=True), cat_cols),
])

X_train_proc = preprocessor.fit_transform(X_train)
X_test_proc = preprocessor.transform(X_test)

if hasattr(X_train_proc, "toarray"):
    X_train_proc = X_train_proc.toarray()
    X_test_proc = X_test_proc.toarray()

print(f"Processed X_train: {X_train_proc.shape}")
print(f"Processed X_test:  {X_test_proc.shape}")

# ==========================================
# TRAINING XGBOOST
# ==========================================
print("\n" + "=" * 60)
print(" TRAINING XGBOOST")
print("=" * 60)

scale_pos_weight = (y_train == 0).sum() / (y_train == 1).sum()
print(f"scale_pos_weight: {scale_pos_weight:.3f}")

xgb_model = xgb.XGBClassifier(
    objective="binary:logistic",
    scale_pos_weight=scale_pos_weight,
    random_state=RANDOM_STATE,
    n_jobs=-1,
    eval_metric="logloss",
)

param_grid = {
    "n_estimators": [100, 200, 300],
    "max_depth": [4, 6, 8],
    "learning_rate": [0.01, 0.05, 0.1],
    "subsample": [0.7, 0.8, 0.9],
    "colsample_bytree": [0.7, 0.8, 0.9],
    "min_child_weight": [1, 3, 5],
}

cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=RANDOM_STATE)

print("Running hyperparameter search (this may take a few minutes)...")
search = RandomizedSearchCV(
    xgb_model,
    param_distributions=param_grid,
    n_iter=15,
    cv=cv,
    scoring="roc_auc",
    n_jobs=-1,
    verbose=1,
    random_state=RANDOM_STATE,
)
search.fit(X_train_proc, y_train)

best_model = search.best_estimator_
print(f"\nBest parameters: {search.best_params_}")
print(f"Best CV ROC-AUC: {search.best_score_:.4f}")

# ==========================================
# EVALUATION
# ==========================================
print("\n" + "=" * 60)
print(" EVALUATION")
print("=" * 60)

y_pred = best_model.predict(X_test_proc)
y_proba = best_model.predict_proba(X_test_proc)[:, 1]

accuracy = accuracy_score(y_test, y_pred)
roc_auc = roc_auc_score(y_test, y_proba)

print(f"Accuracy: {accuracy:.4f}")
print(f"ROC-AUC:  {roc_auc:.4f}")
print("\nClassification Report:")
print(classification_report(y_test, y_pred, target_names=["Normal", "Attack"]))

cm = confusion_matrix(y_test, y_pred)
plt.figure(figsize=(6, 5))
sns.heatmap(cm, annot=True, fmt="d", cmap="Blues",
            xticklabels=["Normal", "Attack"],
            yticklabels=["Normal", "Attack"])
plt.title("Confusion Matrix")
plt.ylabel("Actual")
plt.xlabel("Predicted")
plt.tight_layout()
plt.savefig(os.path.join(PLOT_DIR, "confusion_matrix.png"), dpi=150)
plt.close()
print("Saved: plots/confusion_matrix.png")

# ==========================================
# SAVING MODEL
# ==========================================
print("\n" + "=" * 60)
print(" SAVING MODEL")
print("=" * 60)

joblib.dump(best_model, os.path.join(MODEL_DIR, "xgboost_model.joblib"))
joblib.dump(preprocessor, os.path.join(MODEL_DIR, "preprocessor.joblib"))
joblib.dump(preprocessor.get_feature_names_out(), os.path.join(MODEL_DIR, "feature_names.joblib"))

print("Saved: models/xgboost_model.joblib")
print("Saved: models/preprocessor.joblib")
print("Saved: models/feature_names.joblib")
print("\nTraining Complete! ")