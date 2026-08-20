import pandas as pd
import joblib
from sklearn.ensemble import IsolationForest

INPUT = "data/processed/ml_ready_security_events.csv"
OUTPUT = "data/processed/anomaly_results.csv"
MODEL = "models/isolation_forest_model.joblib"

# Load data
df = pd.read_csv(INPUT)

print("=" * 60)
print("MULTI-CLOUD ANOMALY DETECTION")
print("=" * 60)

print("Dataset:", df.shape)

# IMPORTANT:
# Only use the original 13 ML features.
# Do not pass anomaly_score/risk back into the model.
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

X = df[FEATURES].copy()

print("Features used:", X.shape)

# Isolation Forest
model = IsolationForest(
    n_estimators=200,
    contamination=0.20,
    random_state=42
)

# Train
model.fit(X)

# Predict
df["anomaly_score"] = model.decision_function(X)
df["anomaly"] = model.predict(X)

# Convert prediction to readable label
df["risk"] = df["anomaly"].map({
    1: "Normal",
    -1: "Suspicious"
})

# Save results
df.to_csv(OUTPUT, index=False)

# Save model
joblib.dump(model, MODEL)

print("\nRESULTS")
print("-" * 40)
print(df["risk"].value_counts())

print("\nModel saved:")
print(MODEL)

print("\nResults saved:")
print(OUTPUT)