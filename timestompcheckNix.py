# -*- coding: utf-8 -*-
"""
Created on Tue Oct 21 16:13:29 2025
DeStompADonk - A TimeStomp Checker for Linux/Unix
@author: rickemorris
"""

import os
import time
import csv
from datetime import datetime

# Folders that will be searched and other config items
DATASET_DIR = "forensic_dataset"

# Dynamic Time Modification for the Results - 11-10-2025 modfiication
timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
RESULTS_FILE = f"timestomp_results_{timestamp}.csv"

TARGET_DIR = input("Please enter an additional folder to analyze (or hit Enter to skip): ").strip()


# Timestamp Functions
def get_file_timestamps(filepath):
    stats = os.stat(filepath)
    return {
        "filename": os.path.basename(filepath),
        "path": filepath,
        "metadata_changed": datetime.fromtimestamp(stats.st_ctime),
        "modified": datetime.fromtimestamp(stats.st_mtime),
        "accessed": datetime.fromtimestamp(stats.st_atime)
    }

def timestomp_file(filepath, fake_time):
    """Simulate timestamps with timestomping technique"""
    os.utime(filepath, (fake_time, fake_time))

def detect_anomalies(timestamps):
    c, m, a = timestamps["metadata_changed"], timestamps["modified"], timestamps["accessed"]
    anomalies = []

    # Metadata Change < Modified
    if c < m:
        anomalies.append("Metadata Change < Modified (suspicious)")

    # Access earlier than Modified (>1 day)
    if a < m and (m - a).total_seconds() > 86400:
        anomalies.append("Accessed much earlier than Modified (unusual)")

    # Modified and Accessed identical (±1 second)
    if abs((m - a).total_seconds()) < 1:
        anomalies.append("Modified and Accessed identical (potential timestomp)")

    # Large gap between Metadata Change and Modified (>180 days)
    if abs((c - m).total_seconds()) > 60 * 60 * 24 * 180:
        anomalies.append("Large gap between Metadata Change and Modify (possible timestomp)")

    # Modified >> Accessed (>30 days) — added from Windows script
    if (m - a).total_seconds() > 60 * 60 * 24 * 30:
        anomalies.append("Modified >> Accessed (>30 days gap)")

    return anomalies


# Create Dataset Script
os.makedirs(DATASET_DIR, exist_ok=True)
normal_dir = os.path.join(DATASET_DIR, "normal")
timestomped_dir = os.path.join(DATASET_DIR, "timestomped")
os.makedirs(normal_dir, exist_ok=True)
os.makedirs(timestomped_dir, exist_ok=True)

for i in range(3):
    path = os.path.join(normal_dir, f"normal_file_{i}.txt")
    with open(path, "w") as f:
        f.write(f"Normal log entry {i}")
    time.sleep(1)

for i in range(3):
    path = os.path.join(timestomped_dir, f"timestomped_file_{i}.txt")
    with open(path, "w") as f:
        f.write(f"Timestomped log {i}")
    fake_past = time.time() - 60 * 60 * 24 * 365
    timestomp_file(path, fake_past)

# Detect Timestomping with Data
results = []

for folder in [normal_dir, timestomped_dir]:
    for file in os.listdir(folder):
        fullpath = os.path.join(folder, file)
        if not os.path.isfile(fullpath):
            continue
        ts = get_file_timestamps(fullpath)
        issues = detect_anomalies(ts)
        results.append({
            "file": ts["filename"],
            "path": ts["path"],
            "metadata_changed": ts["metadata_changed"],
            "modified": ts["modified"],
            "accessed": ts["accessed"],
            "anomalies": ", ".join(issues) if issues else "None"
        })

# Detect User Specific for Timestomping IF NEEDED
if TARGET_DIR and os.path.exists(TARGET_DIR):
    print(f"[+] Scanning user folder: {TARGET_DIR}")
    for root, dirs, files in os.walk(TARGET_DIR):
        for file in files:
            fullpath = os.path.join(root, file)
            try:
                ts = get_file_timestamps(fullpath)
                issues = detect_anomalies(ts)
                results.append({
                    "file": ts["filename"],
                    "path": ts["path"],
                    "metadata_changed": ts["metadata_changed"],
                    "modified": ts["modified"],
                    "accessed": ts["accessed"],
                    "anomalies": ", ".join(issues) if issues else "None"
                })
            except Exception as e:
                print(f"[!] Error reading {fullpath}: {e}")

# Save Results and Generate File
if results:
    with open(RESULTS_FILE, "w", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)

    print(f"\n[+] Timestomp checking complete. {len(results)} files analyzed.")
    print(f"[+] Results can be found in {RESULTS_FILE}")
else:
    print("[-] No files analyzed. Please check if files existed or permissions are properly set")