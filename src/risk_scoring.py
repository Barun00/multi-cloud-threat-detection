import pandas as pd

INPUT = "data/processed/anomaly_results.csv"
OUTPUT = "data/processed/threat_results.csv"

df = pd.read_csv(INPUT)

# Convert Isolation Forest score into a 0–100 risk score
df["risk_score"] = (
    (0.5 - df["anomaly_score"]) * 100
).clip(0, 100)

# Add security-specific risk factors
df["risk_score"] += df["auth_risk"] * 10
df["risk_score"] += df["privilege_risk"] * 15
df["risk_score"] += df["failed_login"] * 10
df["risk_score"] += df["large_data_transfer"] * 15
df["risk_score"] += df["iam_risk"] * 15
df["risk_score"] += df["data_access_risk"] * 10
df["risk_score"] += df["cross_cloud_risk"] * 20

df["risk_score"] = df["risk_score"].clip(0, 100).round(2)


def severity(score):
    if score >= 75:
        return "CRITICAL"
    elif score >= 50:
        return "HIGH"
    elif score >= 25:
        return "MEDIUM"
    return "LOW"


df["severity"] = df["risk_score"].apply(severity)

df.to_csv(OUTPUT, index=False)

print("=" * 60)
print("THREAT RISK SCORING")
print("=" * 60)

print("\nSeverity distribution:")
print(df["severity"].value_counts())

print("\nTop 10 threats:")
print(
    df.sort_values("risk_score", ascending=False)
    [
        [
            "risk_score",
            "severity",
            "anomaly_score",
            "anomaly",
        ]
    ]
    .head(10)
)

print(f"\nSaved: {OUTPUT}")