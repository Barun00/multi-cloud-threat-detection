import numpy as np
import pandas as pd


INPUT_PATH = "data/raw/multi_cloud_security_events.csv"
OUTPUT_PATH = "data/processed/ml_ready_security_events.csv"


def load_data():
    """Load the raw multi-cloud security events."""
    df = pd.read_csv(INPUT_PATH)

    print(f"Loaded {len(df)} events")

    return df


def create_features(df):
    """Create security-related numerical features."""

    df = df.copy()

    # Convert timestamp
    df["timestamp"] = pd.to_datetime(df["timestamp"])

    # Authentication risk
    df["auth_risk"] = (
        df["authentication_method"] == "Password"
    ).astype(int)

    # Privilege risk
    df["privilege_risk"] = (
        df["privilege_level"] == "admin"
    ).astype(int)

    # Failed authentication
    df["failed_login"] = (
        df["status"] == "failed"
    ).astype(int)

    # Large data transfer
    df["large_data_transfer"] = (
        df["bytes_transferred"] > 500000
    ).astype(int)

    # IAM-related suspicious actions
    iam_actions = [
        "CreateAccessKey",
        "ModifyIAMPolicy",
        "AssumeAdminRole",
    ]

    df["iam_risk"] = (
        df["action"].isin(iam_actions)
    ).astype(int)

    # Data-access actions
    data_actions = [
        "ReadDatabase",
        "DownloadData",
        "LargeDataTransfer",
    ]

    df["data_access_risk"] = (
        df["action"].isin(data_actions)
    ).astype(int)

    # Cross-cloud activity
    cross_cloud_actions = [
        "CrossCloudLogin",
        "CrossCloudResourceAccess",
    ]

    df["cross_cloud_risk"] = (
        df["action"].isin(cross_cloud_actions)
    ).astype(int)

    # Hour of activity
    df["hour"] = df["timestamp"].dt.hour

    # Activity outside normal hours
    df["unusual_hour"] = (
        (df["hour"] < 6) |
        (df["hour"] > 22)
    ).astype(int)

    # Cloud encoding
    cloud_mapping = {
        "AWS": 0,
        "Azure": 1,
        "GCP": 2,
    }

    df["cloud_encoded"] = (
        df["cloud_provider"].map(cloud_mapping)
    )

    # Authentication encoding
    auth_mapping = {
        "Password": 0,
        "MFA": 1,
    }

    df["auth_encoded"] = (
        df["authentication_method"].map(auth_mapping)
    )

    # Privilege encoding
    privilege_mapping = {
        "user": 0,
        "developer": 1,
        "admin": 2,
    }

    df["privilege_encoded"] = (
        df["privilege_level"].map(privilege_mapping)
    )

    return df


def prepare_ml_data(df):
    """Select numerical features for ML."""

    features = [
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

    X = df[features].copy()

    X = X.replace(
        [np.inf, -np.inf],
        np.nan
    )

    X = X.fillna(0)

    return X


def main():

    print("=" * 60)
    print("MULTI-CLOUD DATA PREPROCESSING")
    print("=" * 60)

    df = load_data()

    df = create_features(df)

    X = prepare_ml_data(df)

    X.to_csv(
        OUTPUT_PATH,
        index=False
    )

    print(f"\nOriginal shape : {df.shape}")
    print(f"ML data shape  : {X.shape}")
    print(f"Saved to       : {OUTPUT_PATH}")

    print("\nML Features:")

    for feature in X.columns:
        print(f"  - {feature}")


if __name__ == "__main__":
    main()