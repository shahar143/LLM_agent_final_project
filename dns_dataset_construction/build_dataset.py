import os
import subprocess
import shutil
from datetime import datetime

# --- Configuration ---
ROOT_DIR = "."  # current directory (DNS-Tunnel-Datasets)
FAILED_DIR = "failed_pcaps"
OUTPUT_CSV = "dns_features_labeled.csv"
EXTRACTION_SCRIPT = "parse_pcap_files_req_n_resp.py"
LOG_FILE = "extraction_log.txt"

# --- Setup ---
os.makedirs(FAILED_DIR, exist_ok=True)

# --- Walk and Collect PCAP Paths ---
all_pcaps = []
for dirpath, _, filenames in os.walk(ROOT_DIR):
    for fname in filenames:
        if fname.endswith(".pcap") or fname.endswith(".pcapng"):
            rel_path = os.path.relpath(os.path.join(dirpath, fname), ROOT_DIR)
            if not rel_path.startswith(FAILED_DIR) and rel_path != EXTRACTION_SCRIPT:
                all_pcaps.append(rel_path)

print(len(all_pcaps))

# --- Process Each PCAP File ---
first = True
with open(LOG_FILE, "a", encoding="utf-8") as log:
    for pcap_path in all_pcaps:
        label = "0" if "normal" in os.path.basename(pcap_path).lower() else "1"
        mode = "append" if first else "append"

        cmd = [
            "python", EXTRACTION_SCRIPT,
            "-p", pcap_path,
            "-l", label,
            "-o", OUTPUT_CSV,
            "-m", mode
        ]

        # Log the command
        log_line = f"[{datetime.now().isoformat()}] Running: {' '.join(cmd)}\n"
        log.write(log_line)
        log.flush()
        print(log_line.strip())

        try:
            subprocess.run(cmd, capture_output=True, text=True, check=True)
        except subprocess.CalledProcessError as e:
            error_msg = f"[ERROR] {pcap_path} failed.\n{e.stderr}\n"
            log.write(error_msg)
            log.flush()
            print(error_msg)

            # Copy to failed_pcaps directory
            failed_path = os.path.join(FAILED_DIR, os.path.basename(pcap_path))
            shutil.copy2(pcap_path, failed_path)
        else:
            first = False
