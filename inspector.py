
import joblib
import os

MODELS_DIR = r"C:\Users\User\Downloads\archive (1)\models"   


preprocessor   = joblib.load(os.path.join(MODELS_DIR, "preprocessor.joblib"))
feature_names  = joblib.load(os.path.join(MODELS_DIR, "feature_names.joblib"))
model          = joblib.load(os.path.join(MODELS_DIR, "xgboost_model.joblib"))

print("=" * 60)
print("FEATURE NAMES")
print("=" * 60)
print(f"Total features: {len(feature_names)}")
for i, name in enumerate(feature_names, 1):
    print(f"  {i:2}. {name}")

print()
print("=" * 60)
print("PREPROCESSOR")
print("=" * 60)
print(type(preprocessor))
print(preprocessor)

print()
print("=" * 60)
print("MODEL")
print("=" * 60)
print(type(model))
print(f"Classes: {model.classes_}")
print(f"Number of features: {model.n_features_in_}")