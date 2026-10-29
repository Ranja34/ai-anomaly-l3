import csv
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

BASE = Path(__file__).resolve().parent.parent
OUTPUT = BASE / "data/prometheus/metrics.csv"
PROMETHEUS = "http://localhost:9090"

QUERIES = {
    "cpu_percent": '100 * (1 - avg by (instance) (rate(node_cpu_seconds_total{mode="idle"}[2m])))',
    "memory_percent": '100 * (1 - node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)',
    "disk_percent": '100 * (1 - (node_filesystem_avail_bytes{mountpoint="/",fstype!~"tmpfs|overlay|squashfs"} / node_filesystem_size_bytes{mountpoint="/",fstype!~"tmpfs|overlay|squashfs"}))',
    "load1": "node_load1",
    "network_receive_bytes": 'rate(node_network_receive_bytes_total{device!~"lo|docker.*|veth.*"}[2m])',
    "network_transmit_bytes": 'rate(node_network_transmit_bytes_total{device!~"lo|docker.*|veth.*"}[2m])',
}

FIELDS = ["timestamp", "instance", *QUERIES.keys()]
OUTPUT.parent.mkdir(parents=True, exist_ok=True)

if not OUTPUT.exists():
    with OUTPUT.open("w", newline="") as f:
        csv.DictWriter(f, fieldnames=FIELDS).writeheader()

print(f"Collecte démarrée. Fichier : {OUTPUT}", flush=True)
print("Arrêt propre avec Ctrl+C.", flush=True)

try:
    while True:
        timestamp = datetime.now(timezone.utc).isoformat()
        rows = {}

        for metric, query in QUERIES.items():
            try:
                response = requests.get(
                    f"{PROMETHEUS}/api/v1/query",
                    params={"query": query},
                    timeout=10,
                )
                response.raise_for_status()
                payload = response.json()

                if payload.get("status") != "success":
                    continue

                for item in payload["data"]["result"]:
                    instance = item["metric"].get("instance")
                    if not instance:
                        continue
                    rows.setdefault(instance, {
                        "timestamp": timestamp,
                        "instance": instance,
                    })
                    rows[instance][metric] = float(item["value"][1])

            except (requests.RequestException, ValueError, KeyError) as exc:
                print(f"[AVERTISSEMENT] {metric}: {exc}", flush=True)

        if rows:
            with OUTPUT.open("a", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=FIELDS)
                writer.writerows(rows.values())

            print(
                f"[{timestamp}] {len(rows)} hôtes collectés",
                flush=True,
            )
        else:
            print("[AVERTISSEMENT] Aucune métrique collectée", flush=True)

        time.sleep(15)

except KeyboardInterrupt:
    print("\nCollecte arrêtée.", flush=True)
