import hashlib
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from src.agent2_executor import execute_approved_action
from flask import Flask, abort, redirect, render_template_string, request, url_for
app = Flask(__name__)
BASE = Path(__file__).resolve().parent
PENDING = BASE / "data" / "agent2" / "pending"
PLAYBOOKS = (BASE / "ansible" / "playbooks").resolve()
INVENTORY = BASE / "ansible" / "inventory.ini"
AUDIT = BASE / "data" / "agent2" / "audit.jsonl"
TARGETS = {"frappe-staging", "runner-devops", "lab"}

HTML = """
<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Agent IA 2 — Validation des corrections</title>
<style>
body{font:16px Arial;max-width:1000px;margin:30px auto;padding:0 16px;background:#f3f5f7;color:#202733}
article{background:white;padding:20px;margin:16px 0;border-radius:10px;overflow-wrap:anywhere}
pre{background:#171b22;color:#e8edf2;padding:14px;overflow:auto;white-space:pre-wrap}
button{padding:10px 16px;margin:8px 8px 0 0;cursor:pointer}
.approve{background:#176b3a;color:white;border:0}
.reject{background:#9d2525;color:white;border:0}
small{color:#555}
</style>
</head>
<body>
<h1>Agent IA 2 — Corrections à valider</h1>
<p>Chaque proposition doit être examinée avant exécution sur le laboratoire.</p>
{% if message %}<article>{{ message }}</article>{% endif %}
{% if not actions %}<article>Aucune correction en attente.</article>{% endif %}
{% for a in actions %}
<article>
<h2>{{ a.description }}</h2>
<p><b>Machine :</b> {{ a.target }} | <b>Statut :</b> {{ a.status }}</p>
<p><b>Diagnostic :</b> {{ a.diagnosis or 'Non renseigné' }}</p>
<p><b>Justification :</b> {{ a.rationale or 'Non renseignée' }}</p>
<p><b>Risque annoncé :</b> {{ a.risk or 'Non évalué' }}</p>
<p><b>Vérification prévue :</b> {{ a.verification or 'Non renseignée' }}</p>
<p><b>Playbook proposé :</b> {{ a.playbook_name }}</p>
<details><summary>Examiner le playbook complet</summary><pre>{{ a.playbook_text }}</pre></details>
{% if a.status == 'pending' %}
<form method="post" action="{{ url_for('decision', action_id=a.id) }}">
<input type="hidden" name="digest" value="{{ a.digest }}">
<button class="approve" name="decision" value="approve">Accepter et exécuter</button>
<button class="reject" name="decision" value="reject">Refuser</button>
</form>
<small>L’acceptation lance le playbook affiché sur la cible indiquée.</small>
{% else %}
<p><b>Résultat :</b> {{ a.result or 'Aucun résultat enregistré' }}</p>
{% endif %}
</article>
{% endfor %}
</body></html>
"""


def load_actions():
    actions = []
    if not PENDING.exists():
        return actions

    for path in sorted(PENDING.glob("*.json"), reverse=True):
        try:
            a = json.loads(path.read_text(encoding="utf-8"))
            action_id = a.get("id", "")
            if not re.fullmatch(r"[0-9a-fA-F-]{36}", action_id):
                continue
            if path.name != f"{action_id}.json":
                continue

            rel = Path(a.get("playbook", ""))
            pb = (BASE / rel).resolve()
            if not pb.is_relative_to(PLAYBOOKS) or not pb.is_file():
                pb_text = "ERREUR : playbook absent ou hors du répertoire autorisé."
                digest = ""
                pb_name = str(rel)
            else:
                pb_text = pb.read_text(encoding="utf-8")
                digest = hashlib.sha256(pb_text.encode()).hexdigest()
                pb_name = pb.name

            a["playbook_text"] = pb_text
            a["playbook_name"] = pb_name
            a["digest"] = digest
            actions.append(a)
        except (OSError, ValueError, json.JSONDecodeError):
            continue
    return actions


def audit(event):
    AUDIT.parent.mkdir(parents=True, exist_ok=True)
    with AUDIT.open("a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")


@app.get("/")
def index():
    return render_template_string(
        HTML, actions=load_actions(), message=request.args.get("message", "")
    )


@app.post("/decision/<action_id>")
def decision(action_id):
    if not re.fullmatch(r"[0-9a-fA-F-]{36}", action_id):
        abort(400)

    path = PENDING / f"{action_id}.json"
    if not path.is_file():
        abort(404)

    action = json.loads(path.read_text(encoding="utf-8"))
    if action.get("status") != "pending":
        return redirect(url_for("index", message="Cette proposition a déjà été traitée."))

    if request.form.get("decision") == "reject":
        action["status"] = "rejected"
        action["decision_at"] = datetime.now(timezone.utc).isoformat()
        action["reviewer"] = "utilisateur de l'interface"
        path.write_text(json.dumps(action, ensure_ascii=False, indent=2))
        audit({"id": action_id, "event": "rejected", "at": action["decision_at"]})
        return redirect(url_for("index", message="Correction refusée."))

    if request.form.get("decision") != "approve":
        abort(400)

    rel = Path(action.get("playbook", ""))
    playbook = (BASE / rel).resolve()
    if not playbook.is_relative_to(PLAYBOOKS) or not playbook.is_file():
        abort(400, "Playbook invalide.")

    current_digest = hashlib.sha256(playbook.read_bytes()).hexdigest()
    if not request.form.get("digest") or current_digest != request.form["digest"]:
        return redirect(url_for("index", message="Le playbook a changé. Examinez la version actuelle avant de valider."))

    target = action.get("target")
    if target not in TARGETS:
        abort(400, "Cible non autorisée.")
    if not INVENTORY.is_file():
        return redirect(url_for("index", message="Inventaire Ansible introuvable."))

    # Marquer avant exécution pour éviter une seconde soumission concurrente.
    action["status"] = "executing"
    action["decision_at"] = datetime.now(timezone.utc).isoformat()
    action["reviewer"] = "utilisateur de l'interface"
    path.write_text(json.dumps(action, ensure_ascii=False, indent=2))

    
    
    try:
        event = execute_approved_action(action_id, current_digest)
        action["status"] = event["status"]
        action["result"] = (
            f"Code retour : {event['returncode']}\n"
            f"{event['stdout']}\n{event['stderr']}"
        )
    except Exception as exc:
        action["status"] = "failed"
        action["result"] = str(exc)


    action["finished_at"] = datetime.now(timezone.utc).isoformat()
    path.write_text(json.dumps(action, ensure_ascii=False, indent=2))
    audit({
        "id": action_id,
        "event": action["status"],
        "target": target,
        "at": action["finished_at"],
        "result": action.get("result", "")[-2000:],
    })
    return redirect(url_for("index", message=f"Traitement terminé : {action['status']}"))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
