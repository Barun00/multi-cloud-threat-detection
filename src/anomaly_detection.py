from sklearn.ensemble import IsolationForest
import pandas as pd
import joblib

# Load ML-ready dataset
df = pd.read_csv("data/processed/ml_ready_security_events.csv")

print("=" * 60)
print("MULTI-CLOUD ANOMALY DETECTION")
print("=" * 60)

print(f"Dataset Shape : {df.shape}")

# Create model
model = IsolationForest(
    contamination=0.20,
    random_state=42
)

# Train model
model.fit(df)

# Predict anomalies
prediction = model.predict(df)

# Convert prediction
# 1 = Normal
# -1 = Anomaly

df["anomaly"] = prediction

# Risk label
df["risk"] = df["anomaly"].apply(
    lambda x: "Suspicious" if x == -1 else "Normal"
)

# Save results
df.to_csv(
    "data/processed/anomaly_results.csv",
    index=False
)

# Save trained model
joblib.dump(
    model,
    "models/isolation_forest_model.joblib"
)

print("\nRESULTS")
print("-" * 30)

print(df["risk"].value_counts())

print("\nModel saved successfully.")
print("CSV saved successfully.")