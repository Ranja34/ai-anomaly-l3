#!/usr/bin/env python3

import argparse
import os
import subprocess
import sys
from pathlib import Path

import requests

PROMETHEUS_ALERTS_URL = "http://localhost:9090/api/v1/alerts"
TARGET_INSTANCE = os.getenv("REMEDIATION_TARGET", "10.10.0.20:9100")
SUPPORTED_ALERTS = {"NginxUnavailable"}
TIMEOUT_SECONDS = 5

PROJECT_DIR = Path(__file__).resolve().parent.parent
ANSIBLE_DIR = PROJECT_DIR / "ansible"
PLAYBOOK = ANSIBLE_DIR / "remediate_nginx.yml"


def get_firing_alerts():
    try:
        response = requests.get(
            PROMETHEUS_ALERTS_URL,
            timeout=TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        payload = response.json()

        if payload.get("status") != "success":
            raise RuntimeError("Réponse Prometheus invalide.")

        return payload.get("data", {}).get("alerts", [])

    except (requests.RequestException, ValueError, RuntimeError) as exc:
        print(f"[ERREUR] Lecture des alertes impossible : {exc}")
        raise SystemExit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Contrôleur de remédiation Prometheus-Ansible"
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Autoriser l'appel du playbook Ansible si une alerte compatible est active.",
    )
    args = parser.parse_args()

    print("===== CONTRÔLEUR DE REMÉDIATION =====")
    print(f"Mode : {'EXÉCUTION AUTORISÉE' if args.execute else 'SIMULATION'}")
    print(f"Cible : {TARGET_INSTANCE}\n")

    alerts = get_firing_alerts()
    candidates = []

    for alert in alerts:
        if alert.get("state") != "firing":
            continue

        labels = alert.get("labels", {})
        if (
            labels.get("alertname") in SUPPORTED_ALERTS
            and labels.get("instance") == TARGET_INSTANCE
        ):
            candidates.append(alert)

    if not candidates:
        print("[INFO] Aucune alerte prise en charge pour cette cible.")
        print("[INFO] Aucun playbook Ansible ne sera lancé.")
        return

    for alert in candidates:
        labels = alert.get("labels", {})
        annotations = alert.get("annotations", {})

        print(f"[ALERTE] {labels.get('alertname')}")
        print(f"  Cible       : {labels.get('instance')}")
        print(f"  Sévérité    : {labels.get('severity', 'non définie')}")
        print(f"  Description : {annotations.get('summary', 'Non renseignée')}")

    if not args.execute:
        print("\n[SIMULATION] Aucune commande Ansible exécutée.")
        print("[INFO] Pour autoriser l'appel du playbook, utilise --execute.")
        return

    if not PLAYBOOK.is_file():
        print(f"[ERREUR] Playbook introuvable : {PLAYBOOK}")
        raise SystemExit(1)

    print("\n[ANsible] Appel du playbook avec demande du mot de passe sudo.")
    print("[SÉCURITÉ] Le playbook conserve sa demande de confirmation OUI.")

    try:
        result = subprocess.run(
            [
                "ansible-playbook",
                str(PLAYBOOK),
                "--ask-become-pass",
            ],
            cwd=ANSIBLE_DIR,
            check=False,
        )
    except FileNotFoundError:
        print("[ERREUR] La commande ansible-playbook est introuvable.")
        raise SystemExit(1)

    if result.returncode == 0:
        print("\n[INFO] Le playbook s'est terminé sans erreur Ansible.")
    else:
        print(
            f"\n[ATTENTION] Le playbook s'est terminé avec le code "
            f"{result.returncode}."
        )
        raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
