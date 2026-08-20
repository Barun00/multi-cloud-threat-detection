import random
from datetime import datetime, timedelta

import numpy as np
import pandas as pd


random.seed(42)
np.random.seed(42)

CLOUDS = ["AWS", "Azure", "GCP"]

NORMAL_ACTIONS = [
    "Login",
    "ReadResource",
    "ListResources",
    "APIRequest",
    "Logout",
]

ATTACK_SCENARIOS = [
    "Credential Attack",
    "Privilege Escalation",
    "Data Exfiltration",
    "Cross-Cloud Attack",
]

REGIONS = {
    "AWS": ["ap-south-1", "us-east-1", "eu-west-1"],
    "Azure": ["Central India", "East US", "West Europe"],
    "GCP": ["asia-south1", "us-central1", "europe-west1"],
}


def random_ip():
    return (
        f"{random.randint(10, 220)}."
        f"{random.randint(0, 255)}."
        f"{random.randint(0, 255)}."
        f"{random.randint(1, 254)}"
    )


def generate_normal_event(timestamp, user_id):
    cloud = random.choice(CLOUDS)

    return {
        "timestamp": timestamp,
        "cloud_provider": cloud,
        "user_id": user_id,
        "source_ip": random_ip(),
        "action": random.choice(NORMAL_ACTIONS),
        "resource": random.choice(
            ["IAM", "Storage", "Compute", "Database"]
        ),
        "region": random.choice(REGIONS[cloud]),
        "status": random.choice(
            ["success", "success", "success", "failed"]
        ),
        "bytes_transferred": random.randint(0, 50000),
        "authentication_method": random.choice(
            ["MFA", "Password"]
        ),
        "privilege_level": random.choice(
            ["user", "user", "developer"]
        ),
        "attack_type": "Normal",
    }


def generate_attack_event(timestamp, user_id):
    scenario = random.choice(ATTACK_SCENARIOS)
    cloud = random.choice(CLOUDS)

    if scenario == "Credential Attack":
        action = random.choice(
            ["FailedLogin", "Login", "CreateAccessKey"]
        )
        auth = "Password"
        privilege = "user"
        bytes_transferred = random.randint(0, 10000)

    elif scenario == "Privilege Escalation":
        action = random.choice(
            [
                "CreateAccessKey",
                "ModifyIAMPolicy",
                "AssumeAdminRole",
            ]
        )
        auth = random.choice(["Password", "MFA"])
        privilege = "admin"
        bytes_transferred = random.randint(0, 20000)

    elif scenario == "Data Exfiltration":
        action = random.choice(
            [
                "ReadDatabase",
                "DownloadData",
                "LargeDataTransfer",
            ]
        )
        auth = "MFA"
        privilege = "developer"
        bytes_transferred = random.randint(
            500000, 5000000
        )

    else:
        action = random.choice(
            [
                "CrossCloudLogin",
                "CrossCloudResourceAccess",
                "LargeDataTransfer",
            ]
        )
        auth = random.choice(["Password", "MFA"])
        privilege = random.choice(
            ["developer", "admin"]
        )
        bytes_transferred = random.randint(
            300000, 5000000
        )

    return {
        "timestamp": timestamp,
        "cloud_provider": cloud,
        "user_id": user_id,
        "source_ip": random_ip(),
        "action": action,
        "resource": random.choice(
            ["IAM", "Storage", "Compute", "Database"]
        ),
        "region": random.choice(REGIONS[cloud]),
        "status": random.choice(
            ["success", "success", "failed"]
        ),
        "bytes_transferred": bytes_transferred,
        "authentication_method": auth,
        "privilege_level": privilege,
        "attack_type": scenario,
    }


def generate_dataset(n_events=10000):
    start_time = datetime(2026, 8, 1, 0, 0, 0)

    events = []

    for _ in range(n_events):
        timestamp = start_time + timedelta(
            minutes=random.randint(
                0,
                60 * 24 * 20
            )
        )

        user_id = (
            f"user_{random.randint(1, 200):03d}"
        )

        if random.random() < 0.80:
            event = generate_normal_event(
                timestamp,
                user_id
            )
        else:
            event = generate_attack_event(
                timestamp,
                user_id
            )

        events.append(event)

    df = pd.DataFrame(events)

    df = df.sort_values(
        "timestamp"
    ).reset_index(drop=True)

    return df


if __name__ == "__main__":

    df = generate_dataset(10000)

    output_path = (
        "data/raw/"
        "multi_cloud_security_events.csv"
    )

    df.to_csv(
        output_path,
        index=False
    )

    print("=" * 60)
    print("MULTI-CLOUD SECURITY DATASET GENERATED")
    print("=" * 60)

    print(f"Total events : {len(df)}")
    print(f"Columns      : {len(df.columns)}")
    print(f"Saved to     : {output_path}")

    print("\nCloud distribution:")
    print(
        df["cloud_provider"]
        .value_counts()
    )

    print("\nAttack distribution:")
    print(
        df["attack_type"]
        .value_counts()
    )