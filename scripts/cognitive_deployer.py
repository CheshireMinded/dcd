#!/usr/bin/env python3
"""
cognitive_deployer.py

Behavioral dispatcher that tails honeypot JSON logs and
triggers DynamicResponseManager in response to attacker actions.
"""

import os
import json
import time
import glob
import logging
from datetime import datetime
from dynamic_response import DynamicResponseManager

# Logging config
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("cognitive_deployer")

# Base data directory
DATA_DIR = "/home/student/dcd-unified/data"

# Honeypot → bias mapping (only tail these three)
MONITOR_TARGETS = {
    "cowrie":     "anchoring",
    "dionaea":    "confirmation",
    "elasticpot": "overconfidence",
}

# Dynamic response engine
response_manager = DynamicResponseManager()


def wait_for_services():
    """
    Block until Elasticsearch and Docker are reachable,
    then ensure cowrie & dionaea are running with 1 replica each.
    """
    import requests
    import docker

    logger.info("Waiting for Elasticsearch and Docker to become available...")
    while True:
        try:
            # ES health check
            requests.get(f"http://{response_manager.es_url.split('//',1)[1]}/_cluster/health", timeout=2).raise_for_status()
            # Docker check
            docker.from_env().ping()
            logger.info("Elasticsearch and Docker are reachable")
            break
        except Exception:
            logger.warning("Services unreachable, retrying in 5s …")
            time.sleep(5)

    # Ensure initial attractor honeypots are up
    for svc in ("cowrie_cowrie", "dionaea_dionaea"):
        try:
            service = response_manager.docker_client.services.get(svc)
            service.scale(1)
            logger.info(f"Ensured Swarm service {svc} scaled to 1")
        except Exception as e:
            logger.error(f"Failed to scale initial service {svc}: {e}")


def extract_attacker_ip(log_line: str) -> str:
    """
    Parse JSON and extract the attacker IP from known fields.
    """
    try:
        data = json.loads(log_line)
        return data.get("src_ip") or data.get("attacker_ip") or data.get("remote_host") or "0.0.0.0"
    except json.JSONDecodeError:
        return "0.0.0.0"


def handle_trigger(log_line: str, bias: str):
    """
    Fire off a scale-up + deception response for one log line.
    """
    ip = extract_attacker_ip(log_line)
    logger.info(f"[Trigger] bias={bias}, attacker_ip={ip}")
    try:
        response_manager.trigger_honeypot(bias, ip)
        response_manager.apply_response(bias, ip)
    except Exception as e:
        logger.exception(f"Error handling trigger for {ip}/{bias}: {e}")


def monitor_logs():
    """
    Tail all *.json files under each honeypot’s logs/ directory,
    dispatching through handle_trigger() whenever we see keywords.
    """
    logger.info("Starting behavioral log monitor…")

    # Initialize file positions for every JSON file under each honeypot
    file_positions = {}
    for svc in MONITOR_TARGETS:
        pattern = os.path.join(DATA_DIR, svc, "logs", "*.json")
        for path in glob.glob(pattern):
            file_positions[path] = 0

    while True:
        # Discover any new log files
        for svc in MONITOR_TARGETS:
            pattern = os.path.join(DATA_DIR, svc, "logs", "*.json")
            for path in glob.glob(pattern):
                if path not in file_positions:
                    file_positions[path] = 0

        # Iterate each monitored file
        for path, last_pos in list(file_positions.items()):
            bias = MONITOR_TARGETS.get(os.path.basename(os.path.dirname(path)))
            if bias is None:
                continue

            try:
                with open(path, "r") as f:
                    f.seek(last_pos)
                    for line in f:
                        if not line.strip():
                            continue
                        # simple keyword filter; tune as needed
                        if any(k in line for k in ("login attempt", "scan", "exploit")):
                            handle_trigger(line.strip(), bias)
                    file_positions[path] = f.tell()
            except Exception as e:
                logger.warning(f"Failed to read {path}: {e}")

        time.sleep(10)


if __name__ == "__main__":
    wait_for_services()
    monitor_logs()
