import os
import pandas as pd


def test_raw_dataset_exists():
    path = "data/raw/multi_cloud_security_events.csv"
    assert os.path.exists(path)


def test_raw_dataset():
    path = "data/raw/multi_cloud_security_events.csv"

    df = pd.read_csv(path)

    assert len(df) == 10000
    assert "cloud_provider" in df.columns
    assert "attack_type" in df.columns


def test_ml_dataset():
    path = "data/processed/ml_ready_security_events.csv"

    assert os.path.exists(path)

    df = pd.read_csv(path)

    assert len(df) == 10000
    assert len(df.columns) == 13


def test_final_results():
    path = "data/processed/correlated_threats.csv"

    assert os.path.exists(path)

    df = pd.read_csv(path)

    assert len(df) == 10000
    assert "risk_score" in df.columns
    assert "severity" in df.columns
    assert "predicted_threat" in df.columns