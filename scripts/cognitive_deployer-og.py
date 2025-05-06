#!/usr/bin/env python3

import json
import time
from pathlib import Path
import subprocess

# Log paths (updated for dcd-unified)
COWRIE_LOG_PATH = Path.home() / "dcd-unified/data/cowrie/logs/cowrie.json"
DIONAEA_LOG_PATH = Path.home() / "dcd-unified/data/dionaea/logs/dionaea.json"

# Map bias types to triggered Swarm services
BIAS_DEPLOY_MAP = {
    "anchoring": "honeypot_honeypot_elasticpot_triggered",
    "confirmation": "honeypot_honeypot_heralding_triggered",
    "overconfidence": "honeypot_honeypot_tanner_triggered"
}

# Tracks which events we've already seen (in-memory)
SEEN_LINES = set()

def scale_service(service_name, replicas=1):
    try:
        subprocess.run(
            ["docker", "service", "scale", f"{service_name}={replicas}"],
            check=True
        )
        print(f"[+] Scaled {service_name} to {replicas} replicas.")
    except subprocess.CalledProcessError as e:
        print(f"[!] Failed to scale {service_name}: {e}")

def parse_log_line(line):
    try:
        entry = json.loads(line)
        src_ip = entry.get("src_ip", "N/A")
        bias = entry.get("bias")
        if bias and bias in BIAS_DEPLOY_MAP:
            service = BIAS_DEPLOY_MAP[bias]
            print(f"[!] Bias detected: {bias} from {src_ip} -> triggering {service}")
            scale_service(service, replicas=1)
    except json.JSONDecodeError:
        pass

def follow_log(path):
    if not path.exists():
        print(f"[!] Log file not found: {path}")
        return
    with path.open("r") as f:
        f.seek(0, 2)  # Jump to end
        while True:
            line = f.readline()
            if not line:
                time.sleep(1)
                continue
            if line not in SEEN_LINES:
                SEEN_LINES.add(line)
                parse_log_line(line)

def main():
    print("[*] Cognitive Deployer watching Cowrie and Dionaea logs...")
    while True:
        follow_log(COWRIE_LOG_PATH)
        follow_log(DIONAEA_LOG_PATH)

if __name__ == "__main__":
    main()
