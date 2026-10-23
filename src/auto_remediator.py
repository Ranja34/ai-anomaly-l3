#!/usr/bin/env python3
import subprocess
import os
import time
from pathlib import Path

import requests

BASE = Path(__file__).resolve().parent.parent
ANSIBLE_DIR = BASE / "ansible"
ALERTS_URL = "http://localhost:9090/api/v1/alerts"
TARGET = os.getenv("REMEDIATION_TARGET", "10.10.0.20:9100")
PLAYBOOK = "remediate_nginx_auto.yml"
INTERVAL = 10
handled = False

print("=== REMÉDIATION AUTOMATIQUE ACTIVE ===", flush=True)

while True:
    try:
        response = requests.get(ALERTS_URL, timeout=5)
        response.raise_for_status()
        payload = response.json()
        if payload.get("status") != "success":
            raise RuntimeError("Réponse Prometheus invalide")

        alerts = payload.get("data", {}).get("alerts", [])
        incident = any(
            a.get("state") == "firing"
            and a.get("labels", {}).get("alertname") == "NginxUnavailable"
            and a.get("labels", {}).get("instance") == TARGET
            for a in alerts
        )

        if incident and not handled:
            print("[ALERTE] Nginx indisponible : lancement Ansible.", flush=True)
            result = subprocess.run(
                [
                    "ansible-playbook",
                    "-i", str(ANSIBLE_DIR / "inventory.ini"),
                    str(ANSIBLE_DIR / PLAYBOOK),
                ],
                cwd=str(ANSIBLE_DIR),
                timeout=120,
                check=False,
            )
            print(f"[RÉSULTAT] Code Ansible : {result.returncode}", flush=True)
            handled = result.returncode == 0

        elif not incident:
            handled = False

    except Exception as exc:
        print(f"[ERREUR] {exc}", flush=True)

    time.sleep(INTERVAL)
