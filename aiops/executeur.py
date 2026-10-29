"""Exécution des corrections approuvées (playbook Ansible ou script bash) sur les machines."""
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from aiops import config
from aiops.validation import CorrectionRefusee

ANSIBLE_DIR = config.RACINE / "ansible"


def _ansible_playbook():
    return shutil.which("ansible-playbook") or "/usr/bin/ansible-playbook"


def _env():
    return {**os.environ, "ANSIBLE_CONFIG": str(ANSIBLE_DIR / "ansible.cfg"),
            "ANSIBLE_NOCOLOR": "1", "ANSIBLE_FORCE_COLOR": "0"}


def verifier_syntaxe(type_, machine, contenu):
    """Contrôle de syntaxe sans rien exécuter. Lève CorrectionRefusee si invalide."""
    if type_ == "script":
        p = subprocess.run(["bash", "-n"], input=contenu, capture_output=True, text=True, timeout=10)
        if p.returncode != 0:
            raise CorrectionRefusee(f"syntaxe bash invalide : {p.stderr.strip()[:200]}")
        return
    with tempfile.TemporaryDirectory() as dossier:
        fichier = Path(dossier) / "correction.yml"
        fichier.write_text(contenu, encoding="utf-8")
        cmd = [_ansible_playbook(), "--syntax-check", "-i", str(ANSIBLE_DIR / "inventory.ini"),
               "-l", machine, str(fichier)]
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=30, env=_env(), cwd=str(ANSIBLE_DIR))
        except FileNotFoundError:
            raise RuntimeError("ansible-playbook est introuvable sur cette machine")
    if p.returncode != 0:
        raise CorrectionRefusee(f"syntaxe Ansible invalide : {(p.stdout + p.stderr).strip()[:300]}")


def executer(type_, machine, contenu, sudo, timeout=180):
    """Exécute la correction. Retourne {ok, code, sortie}."""
    try:
        if type_ == "playbook":
            with tempfile.TemporaryDirectory() as dossier:
                fichier = Path(dossier) / "correction.yml"
                fichier.write_text(contenu, encoding="utf-8")
                cmd = [_ansible_playbook(), "-i", str(ANSIBLE_DIR / "inventory.ini"), "-l", machine,
                       "-e", json.dumps({"ansible_become": bool(sudo)}), str(fichier)]
                p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                                   env=_env(), cwd=str(ANSIBLE_DIR))
        else:
            hote = config.ADRESSES.get(machine)
            if not hote:
                return {"ok": False, "code": None, "sortie": f"machine inconnue : {machine}"}
            cmd = ["ssh", "-i", config.SSH_CLE, "-o", "BatchMode=yes", "-o", "ConnectTimeout=8",
                   "-o", "IdentitiesOnly=yes", f"{config.SSH_USER}@{hote}",
                   "sudo -n bash -s" if sudo else "bash -s"]
            p = subprocess.run(cmd, input=contenu, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"ok": False, "code": None, "sortie": f"délai dépassé ({timeout} s)"}
    except FileNotFoundError as e:
        return {"ok": False, "code": None, "sortie": f"programme introuvable : {e.filename}"}
    return {"ok": p.returncode == 0, "code": p.returncode, "sortie": (p.stdout + p.stderr).strip()}
