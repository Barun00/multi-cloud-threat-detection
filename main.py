import subprocess
import sys


STEPS = [
    ["src/data_generator.py"],
    ["src/preprocessing.py"],
    ["src/anomaly_detection.py"],
    ["src/risk_scoring.py"],
    ["src/threat_classifier.py"],
    ["src/cross_cloud_correlation.py"],
]


def run_step(script):
    print("\n" + "=" * 60)
    print(f"RUNNING: {script[0]}")
    print("=" * 60)

    result = subprocess.run(
        [sys.executable] + script,
        check=False
    )

    if result.returncode != 0:
        print(f"\nERROR: {script[0]} failed.")
        sys.exit(result.returncode)


def main():
    print("=" * 60)
    print("MULTI-CLOUD THREAT DETECTION PIPELINE")
    print("=" * 60)

    for step in STEPS:
        run_step(step)

    print("\n" + "=" * 60)
    print("PIPELINE COMPLETED SUCCESSFULLY")
    print("=" * 60)


if __name__ == "__main__":
    main()