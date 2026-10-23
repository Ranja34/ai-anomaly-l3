#!/usr/bin/env python3

import requests

PROMETHEUS_ALERTS_URL = "http://localhost:9090/api/v1/alerts"
TIMEOUT_SECONDS = 5


def main():
    print("===== DETECTEUR D'INCIDENTS - LABORATOIRE =====")
    print("Source : règles d'alerte Prometheus")
    print("Mode : lecture seule, aucune réparation automatique.\n")

    try:
        response = requests.get(
            PROMETHEUS_ALERTS_URL,
            timeout=TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        payload = response.json()

        if payload.get("status") != "success":
            raise RuntimeError("Prometheus n'a pas confirmé la requête.")

        alerts = payload.get("data", {}).get("alerts", [])

    except (requests.RequestException, ValueError, RuntimeError) as exc:
        print(f"[ERREUR] Impossible de lire les alertes Prometheus : {exc}")
        raise SystemExit(1)

    active_alerts = [
        alert for alert in alerts
        if alert.get("state") in ("pending", "firing")
    ]

    if not active_alerts:
        print("[OK] Aucune alerte en attente ou déclenchée.")
    else:
        for alert in active_alerts:
            labels = alert.get("labels", {})
            annotations = alert.get("annotations", {})

            name = alert.get("labels", {}).get("alertname", "Inconnue")
            state = alert.get("state", "inconnu")
            severity = labels.get("severity", "non définie")
            instance = labels.get("instance", "machine inconnue")
            summary = annotations.get("summary", "Aucun résumé disponible")
            description = annotations.get("description", "")

            print(f"[{severity.upper()}] {name}")
            print(f"  État      : {state}")
            print(f"  Machine   : {instance}")
            print(f"  Résumé    : {summary}")
            if description:
                print(f"  Détail    : {description}")
            print()

    print("Fin du contrôle. Aucune action corrective exécutée.")


if __name__ == "__main__":
    main()
