import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
PENDING_DIR = BASE_DIR / "data" / "agent2" / "pending"
AUDIT_FILE = BASE_DIR / "data" / "agent2" / "audit.jsonl"

ALLOWED_TARGETS = {
    "frappe-staging",
    "runner-devops",
    "lab",
}


def now():
    return datetime.now(timezone.utc).isoformat()


def propose_action(target, description, playbook, parameters=None):
    """Enregistre une proposition sans exécuter de commande."""
    if target not in ALLOWED_TARGETS:
        raise ValueError(f"Cible non autorisée : {target}")

    if not description.strip() or not playbook.strip():
        raise ValueError("Description et playbook sont obligatoires.")

    action_id = str(uuid.uuid4())
    action = {
        "id": action_id,
        "created_at": now(),
        "status": "pending",
        "target": target,
        "description": description,
        "playbook": playbook,
        "parameters": parameters or {},
    }

    PENDING_DIR.mkdir(parents=True, exist_ok=True)
    path = PENDING_DIR / f"{action_id}.json"
    path.write_text(json.dumps(action, ensure_ascii=False, indent=2))
    path.chmod(0o600)

    return action


def record_decision(action_id, approved, reviewer):
    """Enregistre une décision humaine ; n'exécute rien."""
    if not reviewer.strip():
        raise ValueError("L'identité du valideur est obligatoire.")

    path = PENDING_DIR / f"{action_id}.json"
    if not path.exists():
        raise FileNotFoundError("Proposition introuvable.")

    action = json.loads(path.read_text())
    if action["status"] != "pending":
        raise ValueError("Cette proposition a déjà été traitée.")

    action["status"] = "approved" if approved else "rejected"
    action["reviewer"] = reviewer
    action["decision_at"] = now()

    path.write_text(json.dumps(action, ensure_ascii=False, indent=2))
    path.chmod(0o600)

    AUDIT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with AUDIT_FILE.open("a", encoding="utf-8") as audit:
        audit.write(json.dumps({
            "id": action_id,
            "target": action["target"],
            "status": action["status"],
            "reviewer": reviewer,
            "decision_at": action["decision_at"],
        }, ensure_ascii=False) + "\n")

    return action


if __name__ == "__main__":
    print("Registre Agent IA 2 prêt.")
    print("Ce module enregistre les propositions et décisions, sans exécuter de commandes.")
