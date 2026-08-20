import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report


INPUT = "data/processed/threat_results.csv"
RAW_INPUT = "data/raw/multi_cloud_security_events.csv"
MODEL = "models/threat_classifier.joblib"
OUTPUT = "data/processed/final_threat_results.csv"

df = pd.read_csv(INPUT)
raw_df = pd.read_csv(RAW_INPUT)

if len(df) != len(raw_df):
    raise ValueError("Processed and raw datasets have different row counts.")

df["attack_type"] = raw_df["attack_type"].values

FEATURES = [
    "cloud_encoded",
    "bytes_transferred",
    "auth_risk",
    "privilege_risk",
    "failed_login",
    "large_data_transfer",
    "iam_risk",
    "data_access_risk",
    "cross_cloud_risk",
    "hour",
    "unusual_hour",
    "auth_encoded",
    "privilege_encoded",
]

X = df[FEATURES]
y = df["attack_type"]

encoder = LabelEncoder()
y_encoded = encoder.fit_transform(y)

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y_encoded,
    test_size=0.20,
    random_state=42,
    stratify=y_encoded
)

model = RandomForestClassifier(
    n_estimators=200,
    random_state=42,
    class_weight="balanced",
    n_jobs=-1
)

model.fit(X_train, y_train)

predictions = model.predict(X_test)

accuracy = accuracy_score(
    y_test,
    predictions
)

print("=" * 60)
print("THREAT CLASSIFICATION")
print("=" * 60)

print(f"\nAccuracy: {accuracy:.4f}")

print("\nClassification Report:")
print(
    classification_report(
        y_test,
        predictions,
        target_names=encoder.classes_,
        zero_division=0
    )
)

# Predict threat type for every event
df["predicted_threat"] = encoder.inverse_transform(
    model.predict(X)
)

# Prediction confidence
df["threat_confidence"] = (
    model.predict_proba(X).max(axis=1) * 100
).round(2)

df.to_csv(
    OUTPUT,
    index=False
)

joblib.dump(
    {
        "model": model,
        "encoder": encoder,
        "features": FEATURES
    },
    MODEL
)

print("\nModel saved:")
print(MODEL)

print("\nResults saved:")
print(OUTPUT)