#!/usr/bin/env python3
"""
Created by Tanmay Patil
Copyright © 2025 Tanmay Patil. All rights reserved.

This module implements advanced security compliance and auditing.
It uses Isolation Forest for anomaly detection and a zero-shot classification pipeline
to categorize each audit log entry. The implementation is optimized for low-end hardware.
"""

import os
import numpy as np
import threading
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest
from transformers import pipeline

# Define candidate labels for compliance analysis.
CANDIDATE_LABELS = ["data breach", "unauthorized access", "policy violation", "malware detection", "failed login"]


def extract_features_from_logs(log_file="audit.log"):
    """Extract a simple feature (line length) from each log entry."""
    features = []
    if not os.path.exists(log_file):
        return features
    with open(log_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                features.append([len(line)])
    return features


def detect_anomalies(log_file="audit.log"):
    """Run Isolation Forest on simple features for anomaly detection."""
    print("Running anomaly detection on audit logs...")
    features = extract_features_from_logs(log_file)
    if not features:
        print("No log data found.")
        return []
    scaler = StandardScaler()
    features = scaler.fit_transform(features)
    clf = IsolationForest(contamination=0.05, random_state=42)
    clf.fit(features)
    anomalies = np.where(clf.predict(features) == -1)[0].tolist()
    print(f"Anomaly detection complete. Found anomalies at lines: {anomalies}")
    return anomalies


def run_advanced_nlp_analysis(log_file="audit.log"):
    """
    Run zero-shot classification on each log entry using the Hugging Face zero-shot pipeline.
    The pipeline uses the "facebook/bart-large-mnli" model for classification.
    Each log line is processed individually with truncation for efficiency.
    """
    if not os.path.exists(log_file):
        print("No log data found.")
        return
    with open(log_file, "r", encoding="utf-8") as f:
        log_lines = f.readlines()

    # Initialize the zero-shot classification pipeline.
    classifier = pipeline("zero-shot-classification", model="facebook/bart-large-mnli",
                          device=0 if os.environ.get("CUDA_VISIBLE_DEVICES") or False else -1)
    results = {}

    def classify_line(line, idx):
        text = line.strip()
        # Process text with a maximum length of 64 characters to reduce resource usage.
        truncated_text = text if len(text) <= 64 else text[:64]
        result = classifier(truncated_text, candidate_labels=CANDIDATE_LABELS, multi_label=False)
        # The pipeline returns a dictionary with "labels" and "scores"
        results[idx] = result["labels"][0]

    threads = []
    for i, log in enumerate(log_lines):
        t = threading.Thread(target=classify_line, args=(log, i))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()

    print("NLP Compliance Analysis Results:")
    for idx, category in results.items():
        print(f"Line {idx}: {category}")


def run_audit_analysis():
    """Run the full compliance analysis pipeline."""
    detect_anomalies()
    run_advanced_nlp_analysis()


if __name__ == "__main__":
    run_audit_analysis()
