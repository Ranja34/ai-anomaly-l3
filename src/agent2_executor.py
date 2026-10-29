
import hashlib
import json
import subprocess
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
PENDING_DIR = BASE_DIR / "data" / "agent2" / "pending"
INVENTORY = BASE_DIR / "ansible" / "inventory.ini"
PLAYBOOK_DIR = (BASE_DIR / "ansible" / "playbooks").resolve()
AUDIT_FILE = BASE_DIR / "data" / "agent2" / "audit.jsonl"
SSH_KEY = Path.home() / ".ssh" / "id_ed25519_ansible"
ALLOWED_HOSTS = {"frappe-staging", "runner-devops", "lab"}


def execute_approved_action(action_id, expected_digest):
    if not action_id or any(c not in "0123456789abcdef-" for c in action_id.lower()):
        raise ValueError("Identifiant de proposition invalide.")

    path = PENDING_DIR / f"{action_id}.json"
    if not path.is_file():
        raise FileNotFoundError("Proposition introuvable.")

    action = json.loads(path.read_text(encoding="utf-8"))

    # L'interface marque la proposition executing après approbation.
    if action.get("status") != "executing":
        raise PermissionError("La proposition n'est pas approuvée pour exécution.")

    playbook = (BASE_DIR / action.get("playbook", "")).resolve()
    if not playbook.is_relative_to(PLAYBOOK_DIR):
        raise PermissionError("Playbook hors du répertoire autorisé.")

    if not playbook.is_file() or playbook.suffix not in {".yml", ".yaml"}:
        raise ValueError("Playbook YAML invalide.")

    current_digest = hashlib.sha256(playbook.read_bytes()).hexdigest()
    if not expected_digest or current_digest != expected_digest:
        raise PermissionError("Le playbook a changé depuis l'approbation.")

    target = action.get("target")
    if target not in ALLOWED_HOSTS:
        raise PermissionError("Cible non autorisée.")

    if not INVENTORY.is_file() or not SSH_KEY.is_file():
        raise FileNotFoundError("Inventaire ou clé SSH introuvable.")

    base_command = [
        "/usr/bin/ansible-playbook",
        "-i", str(INVENTORY),
        str(playbook),
        "--private-key", str(SSH_KEY),
        "-e", 'ansible_ssh_common_args="-o IdentitiesOnly=yes"',
        "-e", "ansible_become=true",
    ]

    try:
        syntax = subprocess.run(
            base_command + ["--syntax-check"],
            cwd=BASE_DIR,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        if syntax.returncode != 0:
            raise RuntimeError(
                "Échec du contrôle de syntaxe :\n"
                + syntax.stdout[-3000:] + "\n" + syntax.stderr[-3000:]
            )

        result = subprocess.run(
            base_command + ["--limit", target],
            cwd=BASE_DIR,
            capture_output=True,
            text=True,
            timeout=600,
            check=False,
        )

        event = {
            "action_id": action_id,
            "status": "executed" if result.returncode == 0 else "failed",
            "returncode": result.returncode,
            "stdout": result.stdout[-10000:],
            "stderr": result.stderr[-5000:],
        }

    except subprocess.TimeoutExpired as exc:
        event = {
            "action_id": action_id,
            "status": "failed",
            "returncode": -1,
            "stdout": str(exc.stdout or "")[-3000:],
            "stderr": "Délai dépassé pendant l'exécution Ansible.",
        }

    AUDIT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with AUDIT_FILE.open("a", encoding="utf-8") as file:
        file.write(json.dumps(event, ensure_ascii=False) + "\n")

    if event["status"] != "executed":
        raise RuntimeError(
            f"Échec Ansible :\n{event['stderr']}\n{event['stdout']}"
        )

    return event
