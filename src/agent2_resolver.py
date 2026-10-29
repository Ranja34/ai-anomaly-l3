
import json
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path

from src.llm_client import ask_model

BASE_DIR = Path(__file__).resolve().parent.parent
PENDING_DIR = BASE_DIR / "data" / "agent2" / "pending"
PLAYBOOK_DIR = (BASE_DIR / "ansible" / "playbooks").resolve()
INVENTORY = BASE_DIR / "ansible" / "inventory.ini"
SSH_KEY = Path.home() / ".ssh" / "id_ed25519_ansible"

ALLOWED_HOSTS = {"frappe-staging", "runner-devops"}

# Modules Ansible autorisés pour les réparations du laboratoire.
ALLOWED_MODULES = {
    "ansible.builtin.systemd",
    "ansible.builtin.service",
    "ansible.builtin.command",
    "ansible.builtin.apt",
    "ansible.builtin.file",
}


def prepare_correction(diagnosis_json: str) -> dict:
    """Génère et valide un playbook de réparation à partir du diagnostic."""

    diagnosis = json.loads(diagnosis_json)

    prompt = f"""
Tu es l'Agent IA 2 d'un laboratoire Linux Ubuntu.
Tu dois générer un playbook Ansible de réparation adapté au diagnostic.

DIAGNOSTIC :
{json.dumps(diagnosis, ensure_ascii=False)}

Machines autorisées :
- frappe-staging
- runner-devops

Retourne UNIQUEMENT un objet JSON valide avec :
host, title, diagnosis, rationale, risk, playbook_yaml, verification.

Règles obligatoires :
- Choisis uniquement une machine explicitement concernée par le diagnostic.
- Si la machine concernée n'est pas identifiable, refuse la réparation.
- playbook_yaml doit être un playbook YAML complet.
- Le champ hosts doit être exactement le nom de la machine choisie.
- Utilise become: true si des privilèges administrateur sont nécessaires.
- Utilise les modules Ansible intégrés, pas de shell arbitraire.
- Modules permis : ansible.builtin.systemd,
  ansible.builtin.service, ansible.builtin.command,
  ansible.builtin.apt et ansible.builtin.file.
- Ne supprime aucune donnée et ne désactive aucun mécanisme de sécurité.
- Ne réinstalle pas un système ou un service sans preuve.
- N'invente pas de cause si les preuves sont insuffisantes.
- Privilégie une correction ciblée, puis une tâche de vérification.
- Si aucune réparation fiable n'est possible, indique-le dans title
  et propose un diagnostic en lecture seule.
- Réponds en JSON, sans Markdown ni bloc de code.
"""

    raw = ask_model(prompt)
    proposal = json.loads(raw)

    host = proposal.get("host")
    yaml_text = proposal.get("playbook_yaml", "").strip()

    if host not in ALLOWED_HOSTS:
        raise ValueError("Cible absente ou non autorisée.")

    if not yaml_text:
        raise ValueError("L'Agent 2 n'a généré aucun playbook.")

    # Chaque play doit cibler exclusivement la machine retenue.
    try:
        import yaml
        plays = yaml.safe_load(yaml_text)
    except Exception as exc:
        raise ValueError(f"YAML invalide : {exc}") from exc

    if not isinstance(plays, list) or not plays:
        raise ValueError("Le playbook doit contenir une liste de plays.")

    for play in plays:
        if not isinstance(play, dict):
            raise ValueError("Structure de play invalide.")

        if play.get("hosts") != host:
            raise ValueError("La cible YAML ne correspond pas à la cible validée.")

        tasks = play.get("tasks", [])
        if not isinstance(tasks, list) or not tasks:
            raise ValueError("Le playbook doit contenir des tâches.")

        for task in tasks:
            if not isinstance(task, dict):
                raise ValueError("Structure de tâche invalide.")

            modules = [
                key for key in task
                if key.startswith("ansible.builtin.")
            ]
            if len(modules) != 1 or modules[0] not in ALLOWED_MODULES:
                raise ValueError(
                    f"Module Ansible non autorisé ou ambigu : {modules}"
                )

    PLAYBOOK_DIR.mkdir(parents=True, exist_ok=True)
    PENDING_DIR.mkdir(parents=True, exist_ok=True)

    proposal_id = str(uuid.uuid4())
    playbook_path = PLAYBOOK_DIR / f"proposal_{proposal_id}.yml"
    playbook_path.write_text(yaml_text + "\n", encoding="utf-8")
    playbook_path.chmod(0o600)

    # Vérification syntaxique réelle avec Ansible.
    command = [
        "/usr/bin/ansible-playbook",
        "-i", str(INVENTORY),
        str(playbook_path),
        "--syntax-check",
        "--private-key", str(SSH_KEY),
        "-e", 'ansible_ssh_common_args="-o IdentitiesOnly=yes"',
        "-e", "ansible_become=true",
    ]

    check = subprocess.run(
        command,
        cwd=BASE_DIR,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )

    if check.returncode != 0:
        playbook_path.unlink(missing_ok=True)
        raise ValueError(
            "Le contrôle de syntaxe Ansible a échoué :\n"
            + check.stdout[-2000:]
            + "\n"
            + check.stderr[-2000:]
        )

    record = {
        "id": proposal_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "status": "pending",
        "target": host,
        "description": proposal.get(
            "title", "Playbook généré par Agent 2"
        ),
        "diagnosis": proposal.get("diagnosis", ""),
        "rationale": proposal.get("rationale", ""),
        "risk": proposal.get("risk", "non évalué"),
        "verification": proposal.get("verification", ""),
        "playbook": f"ansible/playbooks/{playbook_path.name}",
    }

    record_path = PENDING_DIR / f"{proposal_id}.json"
    record_path.write_text(
        json.dumps(record, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    record_path.chmod(0o600)

    return record


if __name__ == "__main__":
    print("Agent 2 : génération dynamique de playbooks activée.")

