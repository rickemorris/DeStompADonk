# -*- coding: utf-8 -*-
"""
Created on Tue Nov 6 01:35:27 2025
DeStompADonk - A Timestomp Checker For Windows
@author: rickemoris
"""

import os
import time
import csv
from datetime import datetime
import ctypes
from ctypes import wintypes

# Folders that will be searched and other config items
DATASET_DIR = "forensic_dataset"

# Dynamic Time Modification for the Results - 11-10-2025 modfiication
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
RESULTS_FILE = f"timestomp_results_{timestamp}.csv"

TARGET_DIR = input("Please enter an additional folder to analyze (or hit Enter to skip): ").strip()

# Windows FILETIME converter
def filetime_to_dt(ft):
    """Windows FILETIME to Python datetime."""
    try:
        return datetime.fromtimestamp((ft.dwHighDateTime << 32 | ft.dwLowDateTime) / 1e7 - 11644473600)
    except Exception:
        return None

# Timestamp Functions
def get_file_timestamps(filepath):
    """Retrieve Windows timestamps: Created, Modified, Accessed, Metadata Changed."""
    stats = os.stat(filepath)

    # Timestamp Converter
    def safe_time(ts):
        try:
            return datetime.fromtimestamp(ts)
        except Exception:
            return None

    created = safe_time(stats.st_ctime)
    modified = safe_time(stats.st_mtime)
    accessed = safe_time(stats.st_atime)

    # Getting NTFS timestamps
    try:
        handle = ctypes.windll.kernel32.CreateFileW(
            filepath,
            0x80,  # FILE_READ_ATTRIBUTES
            0x01 | 0x02,  # share read and write
            None,
            3,  # OPEN_EXISTING
            0x02000000,  # FILE_FLAG_BACKUP_SEMANTICS
            None
        )
        if handle != -1:
            ctime = wintypes.FILETIME()
            atime = wintypes.FILETIME()
            mtime = wintypes.FILETIME()

            if ctypes.windll.kernel32.GetFileTime(
                handle,
                ctypes.byref(ctime),
                ctypes.byref(atime),
                ctypes.byref(mtime)
            ):
                created = filetime_to_dt(ctime)
                accessed = filetime_to_dt(atime)
                modified = filetime_to_dt(mtime)

            ctypes.windll.kernel32.CloseHandle(handle)
    except Exception:
        pass

    metadata_changed = created or modified

    return {
        "filename": os.path.basename(filepath),
        "path": filepath,
        "created": created,
        "modified": modified,
        "accessed": accessed,
        "metadata_changed": metadata_changed
    }

# Create Timestomp Data
def timestomp_file(filepath, fake_time):
    """Apply fake timestamps to simulate timestomping."""
    try:
        os.utime(filepath, (fake_time, fake_time))
    except Exception as e:
        print(f"[!] Could not timestomp {filepath}: {e}")

# Detect Timestomping with Data
def detect_anomalies(ts):
    created = ts.get("created")
    modified = ts.get("modified")
    accessed = ts.get("accessed")
    metadata_changed = ts.get("metadata_changed")

    # Ensure timestamps are valid
    if not all(isinstance(t, datetime) for t in (created, modified, accessed, metadata_changed)):
        return ["Missing or unreadable timestamps"]

    anomalies = []

    # Created > Modified
    if created > modified:
        anomalies.append("Created > Modified (impossible normally)")

    # Created much older than modified (>6 months)
    if (modified - created).total_seconds() > 60 * 60 * 24 * 180:
        anomalies.append("Modified much newer than Created (>6 months) - (good to research)")

    # Metadata Change < Modified
    if metadata_changed < modified:
        anomalies.append("Metadata Changed < Modified (suspicious)")

    # Access earlier than Modified (>1 day)
    if accessed < modified and (modified - accessed).total_seconds() > 86400:
        anomalies.append("Accessed much earlier than Modified (unusual)")

    # Modified and Accessed identical (± 1 sec)
    if abs((modified - accessed).total_seconds()) < 1:
        anomalies.append("Modified and Accessed identical (potential timestomp)")

    # Large gap between Metadata Change and Modified (> 180 days)
    if abs((metadata_changed - modified).total_seconds()) > 60 * 60 * 24 * 180:
        anomalies.append("Large gap between Metadata Change and Modify (possible timestomp)")

    # Modified much newer than Accessed (> 30 days)
    if (modified - accessed).total_seconds() > 60 * 60 * 24 * 30:
        anomalies.append("Modified >> Accessed (>30 days gap)")


    return anomalies

# --- Dataset Generation ---
os.makedirs(DATASET_DIR, exist_ok=True)
normal_dir = os.path.join(DATASET_DIR, "normal")
timestomped_dir = os.path.join(DATASET_DIR, "timestomped")

os.makedirs(normal_dir, exist_ok=True)
os.makedirs(timestomped_dir, exist_ok=True)

print("[+] Creating test dataset...")

# Normal test files
for i in range(3):
    path = os.path.join(normal_dir, f"normal_file_{i}.txt")
    with open(path, "w") as f:
        f.write(f"Normal log entry {i}")
    time.sleep(1)

# Timestomped test files
for i in range(3):
    path = os.path.join(timestomped_dir, f"timestomped_file_{i}.txt")
    with open(path, "w") as f:
        f.write(f"Timestomped log {i}")
    fake_time = time.time() - 60 * 60 * 24 * 365  # 1 year old
    timestomp_file(path, fake_time)

print("[+] Dataset ready. Beginning analysis...")

# --- Detection Phase ---
results = []

# Analyze script created files/folders
for folder in [normal_dir, timestomped_dir]:
    for file in os.listdir(folder):
        fullpath = os.path.join(folder, file)
        if os.path.isfile(fullpath):
            ts = get_file_timestamps(fullpath)
            issues = detect_anomalies(ts)
            results.append({
                "file": ts["filename"],
                "path": ts["path"],
                "created": ts["created"],
                "modified": ts["modified"],
                "accessed": ts["accessed"],
                "metadata_changed": ts["metadata_changed"],
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
                    "created": ts["created"],
                    "modified": ts["modified"],
                    "accessed": ts["accessed"],
                    "metadata_changed": ts["metadata_changed"],
                    "anomalies": ", ".join(issues) if issues else "None"
                })
            except Exception as e:
                print(f"[!] Error reading {fullpath}: {e}")

#  Save Results and Generate File
if results:
    with open(RESULTS_FILE, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)

    print(f"\n[+] Timestomp checking complete. {len(results)} files analyzed.")
    print(f"[+] Results can be found in  {RESULTS_FILE}")
else:
    print("[-] No files analyzed. Please check if files existed or permissions are properly set.")
