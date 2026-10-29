import json
import os
import re
import requests
from datetime import datetime, timedelta, timezone
from src.llm_client import ask_model

BASE_DIR = __import__("pathlib").Path(__file__).resolve().parent.parent
LOKI = "http://10.10.0.10:3100"
WINDOW_MINUTES = 5
LIMIT = 500
MAX_EVENTS_FOR_AI = 20

PATTERNS = {
    "CRITICAL": re.compile(
        r"\b(fatal|critical|panic|out of memory|oom-kill|no space left on device|segfault)\b",
        re.IGNORECASE,
    ),
    "ERROR": re.compile(
        r"\b(error|failed|failure|exception|connection refused|timed? ?out|authentication failure)\b",
        re.IGNORECASE,
    ),
}

IGNORE_PATTERNS = [
    re.compile(r"\bnode exited without error\b", re.IGNORECASE),
    re.compile(r"\bfailed to create source, skipping\b", re.IGNORECASE),
    re.compile(r"\bfailed to flush all queues during shutdown\b", re.IGNORECASE),
    re.compile(r"\bfinal error sending batch\b", re.IGNORECASE),
]


def collect_incidents():
    end = datetime.now(timezone.utc)
    start = end - timedelta(minutes=WINDOW_MINUTES)
    params = {
        "query": '{host=~".+"}',
        "start": str(int(start.timestamp() * 1_000_000_000)),
        "end": str(int(end.timestamp() * 1_000_000_000)),
        "limit": LIMIT,
        "direction": "backward",
    }

    response = requests.get(
        f"{LOKI}/loki/api/v1/query_range",
        params=params,
        timeout=15,
    )
    response.raise_for_status()
    payload = response.json()

    if payload.get("status") != "success":
        raise RuntimeError("Réponse Loki invalide.")

    incidents = []
    ignored = 0

    for stream in payload.get("data", {}).get("result", []):
        labels = stream.get("stream", {})
        host = labels.get("host", "inconnu")
        job = labels.get("job", "inconnu")

        for entry in stream.get("values", []):
            message = entry[1]

            if any(p.search(message) for p in IGNORE_PATTERNS):
                ignored += 1
                continue

            matched = [
                level for level, pattern in PATTERNS.items()
                if pattern.search(message)
            ]
            if not matched:
                continue

            incidents.append({
                "severity": "CRITICAL" if "CRITICAL" in matched else "ERROR",
                "host": host,
                "source": job,
                "timestamp_ns": entry[0],
                "message": message[:400],
            })

    return incidents, ignored


def diagnose_with_ai(incidents):
    prompt = f"""
Tu es l'Agent IA 1 d'un laboratoire de supervision système et réseau.
Analyse uniquement les événements fournis. Ils peuvent être incomplets
ou être de faux positifs : ne présente pas une hypothèse comme un fait.

Retourne uniquement un objet JSON valide avec les clés :
summary, incidents, recommended_checks, requires_human_review.

Pour chaque incident, donne : host, severity, probable_cause,
confidence (low, medium ou high), evidence et safe_next_step.
Ne propose aucune commande destructive, aucun changement automatique
et aucune action de résolution directe. L'Agent IA 2 traitera séparément
les actions autorisées.

Événements détectés :
{json.dumps(incidents, ensure_ascii=False)}
"""
    return ask_model(prompt)


def main():
    try:
        incidents, ignored = collect_incidents()
    except (requests.RequestException, ValueError, RuntimeError) as exc:
        print(f"[ERREUR] Collecte Loki impossible : {exc}")
        return

    print(f"Événements suspects : {len(incidents)}")
    print(f"Messages ignorés : {ignored}")

    if not incidents:
        print("Aucun événement suspect : aucun appel au modèle IA.")
        return

    selected = incidents[:MAX_EVENTS_FOR_AI]
    print(f"\nTransmission de {len(selected)} événement(s) à l'IA...")

    try:
        diagnosis = diagnose_with_ai(selected)
    except Exception as exc:
        print(f"[ERREUR] Diagnostic IA impossible : {exc}")
        return

    print("\n=== Diagnostic de l'Agent IA 1 ===")
    try:
        parsed = json.loads(diagnosis)
        print(json.dumps(parsed, ensure_ascii=False, indent=2))

        output = BASE_DIR / "data" / "agent1" / "latest_diagnosis.json"
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(parsed, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        print(f"Diagnostic enregistré : {output}")

    except json.JSONDecodeError:
        print("Réponse du modèle non conforme au JSON attendu :")
        print(diagnosis)


if __name__ == "__main__":
    main()
