import hashlib
import json
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
DIAGNOSIS = BASE / "data/agent1/latest_diagnosis.json"
PENDING = BASE / "data/agent2/pending"
STATE = BASE / "data/agent1/last_fingerprint.txt"
MAX_SIGNALS = 5

def main():
    PENDING.mkdir(parents=True, exist_ok=True)

    # Une proposition attend déjà l'humain : zéro nouvel appel IA.
    for path in PENDING.glob("*.json"):
        try:
            proposal = json.loads(path.read_text(encoding="utf-8"))
            if proposal.get("status") == "pending":
                print("[ÉCONOMIE] Proposition en attente : aucun appel IA.")
                return 0
        except (OSError, json.JSONDecodeError):
            continue

    from src.detect_logs import collect_incidents
    from src.detect_metrics import collect_anomalies

    try:
        logs, ignored = collect_incidents()
        print(f"[LOGS] Signaux={len(logs)}, ignorés={ignored}")
    except Exception as exc:
        print(f"[LOGS] Collecte indisponible : {exc}")
        logs = []

    try:
        metrics = collect_anomalies()
    except Exception as exc:
        print(f"[METRICS] Collecte indisponible : {exc}")
        metrics = []

    # Déduplication locale : un seul message par hôte/source/message.
    unique = {}
    for item in logs + metrics:
        key = (
            str(item.get("host", "")),
            str(item.get("source", "")),
            " ".join(str(item.get("message", "")).lower().split())
        )
        unique[key] = item

    signals = list(unique.values())[:MAX_SIGNALS]
    print(f"[PIPELINE] Signaux uniques retenus : {len(signals)}")

    if not signals:
        print("[ÉCONOMIE] Aucun signal : zéro appel IA.")
        return 0

    # Empêche de repayer pour les mêmes événements lors des cycles suivants.
    digest = hashlib.sha256(
        json.dumps(signals, sort_keys=True, ensure_ascii=False).encode()
    ).hexdigest()

    if STATE.exists() and STATE.read_text().strip() == digest:
        print("[ÉCONOMIE] Signaux identiques au cycle précédent : zéro appel IA.")
        return 0

    from src.detect_logs import diagnose_with_ai

    try:
        print("[AGENT 1] Diagnostic du petit lot de signaux...")
        raw = diagnose_with_ai(signals)
        data = json.loads(raw)
        if not isinstance(data, dict) or not isinstance(data.get("incidents"), list):
            raise ValueError("JSON du diagnostic invalide.")
    except Exception as exc:
        # Ne pas mémoriser le lot : il pourra être réessayé au cycle suivant.
        print(f"[AGENT 1] Échec temporaire, aucun playbook généré : {exc}")
        return 0

    if not data["incidents"]:
        STATE.write_text(digest)
        print("[AGENT 1] Aucun incident confirmé : pas d'appel à Agent 2.")
        return 0

    DIAGNOSIS.parent.mkdir(parents=True, exist_ok=True)
    DIAGNOSIS.write_text(
        json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    # Un seul appel Agent 2, uniquement après diagnostic non vide.
    try:
        from src.agent2_resolver import prepare_correction
        fingerprint = json.dumps(data, sort_keys=True, ensure_ascii=False)
        proposal = prepare_correction(fingerprint)
        proposal["diagnosis_fingerprint"] = hashlib.sha256(
            fingerprint.encode()
        ).hexdigest()

        proposal_file = PENDING / f"{proposal['id']}.json"
        proposal_file.write_text(
            json.dumps(proposal, ensure_ascii=False, indent=2),
            encoding="utf-8"
        )
        proposal_file.chmod(0o600)
        STATE.write_text(digest)
        print("[AGENT 2] Proposition créée. Validation humaine requise dans le navigateur.")
    except Exception as exc:
        print(f"[AGENT 2] Échec : {exc}. Aucune correction exécutée.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
