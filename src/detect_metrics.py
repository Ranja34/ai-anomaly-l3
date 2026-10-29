import csv
from collections import defaultdict
from pathlib import Path
from statistics import median

BASE = Path(__file__).resolve().parent.parent
CSV_FILE = BASE / "data/prometheus/metrics.csv"

METRICS = {
    "cpu_percent": ("CPU", 15),
    "memory_percent": ("RAM", 10),
    "disk_percent": ("Disque", 5),
    "load1": ("Charge système", 2),
    "network_receive_bytes": ("Trafic entrant", 1000),
    "network_transmit_bytes": ("Trafic sortant", 1000),
}
MIN_HISTORY = 30
MAD_FACTOR = 6

def collect_anomalies():
    history = defaultdict(list)
    if not CSV_FILE.is_file():
        print(f"[METRICS] Fichier absent : {CSV_FILE}")
        return []

    with CSV_FILE.open(newline="", encoding="utf-8") as file:
        for row in csv.DictReader(file):
            host = row.get("instance", "inconnu")
            for metric in METRICS:
                try:
                    value = float(row[metric])
                    if value == value and abs(value) != float("inf"):
                        history[(host, metric)].append(
                            (row.get("timestamp", ""), value)
                        )
                except (ValueError, TypeError, KeyError):
                    continue

    incidents = []
    for (host, metric), points in sorted(history.items()):
        if len(points) < MIN_HISTORY:
            continue
        baseline = [value for _, value in points[:-1]]
        timestamp, current = points[-1]
        center = median(baseline)
        mad = median([abs(value - center) for value in baseline])
        threshold = max(MAD_FACTOR * 1.4826 * mad, METRICS[metric][1])

        if abs(current - center) > threshold:
            incidents.append({
                "severity": "WARNING",
                "host": host,
                "source": "prometheus_metrics",
                "timestamp": timestamp,
                "message": (
                    f"Anomalie {METRICS[metric][0]} : valeur={current:.3f}, "
                    f"médiane={center:.3f}, écart={current-center:+.3f}"
                ),
            })
    print(f"[METRICS] Anomalies candidates : {len(incidents)}")
    return incidents

def main():
    collect_anomalies()

if __name__ == "__main__":
    main()
