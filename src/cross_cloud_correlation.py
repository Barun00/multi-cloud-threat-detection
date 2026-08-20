import pandas as pd

INPUT = "data/processed/final_threat_results.csv"
RAW_INPUT = "data/raw/multi_cloud_security_events.csv"
OUTPUT = "data/processed/correlated_threats.csv"

# Final ML results
df = pd.read_csv(INPUT)

# Original cloud/security information
raw_df = pd.read_csv(RAW_INPUT)

# Make sure both datasets contain the same events
if len(df) != len(raw_df):
    raise ValueError(
        "Final results and raw dataset have different row counts."
    )

# Restore metadata required for cross-cloud correlation
df["timestamp"] = raw_df["timestamp"].values
df["cloud_provider"] = raw_df["cloud_provider"].values
df["user_id"] = raw_df["user_id"].values
df["source_ip"] = raw_df["source_ip"].values
df["action"] = raw_df["action"].values
df["resource"] = raw_df["resource"].values

df["timestamp"] = pd.to_datetime(df["timestamp"])

# Count how many different clouds each user accessed
cloud_counts = (
    df.groupby("user_id")["cloud_provider"]
    .nunique()
    .rename("cloud_count")
)

df = df.merge(
    cloud_counts,
    on="user_id",
    how="left"
)

# User active in 2 or more clouds
df["cross_cloud_activity"] = (
    df["cloud_count"] >= 2
).astype(int)

# Add additional risk for cross-cloud behavior
df.loc[
    df["cross_cloud_activity"] == 1,
    "risk_score"
] = (
    df.loc[
        df["cross_cloud_activity"] == 1,
        "risk_score"
    ] + 15
).clip(0, 100)


def get_severity(score):
    if score >= 75:
        return "CRITICAL"
    elif score >= 50:
        return "HIGH"
    elif score >= 25:
        return "MEDIUM"
    return "LOW"


df["severity"] = df["risk_score"].apply(get_severity)

# Save final correlated results
df.to_csv(
    OUTPUT,
    index=False
)

print("=" * 60)
print("CROSS-CLOUD THREAT CORRELATION")
print("=" * 60)

multi_cloud_users = df.loc[
    df["cross_cloud_activity"] == 1,
    "user_id"
].nunique()

print(
    f"\nMulti-cloud users detected: {multi_cloud_users}"
)

print("\nCloud distribution:")
print(
    df["cloud_provider"].value_counts()
)

print("\nSeverity distribution:")
print(
    df["severity"].value_counts()
)

print("\nTop cross-cloud threats:")

top_threats = (
    df[df["cross_cloud_activity"] == 1]
    .sort_values("risk_score", ascending=False)
    [
        [
            "user_id",
            "cloud_provider",
            "predicted_threat",
            "risk_score",
            "severity"
        ]
    ]
    .head(10)
)

print(top_threats)

print(f"\nSaved: {OUTPUT}")