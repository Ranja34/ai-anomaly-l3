"""Exécution de commandes d'enquête sur les machines via SSH (lecture seule, vérifiée par aiops.lecture)."""
import subprocess

from aiops import config, lecture
from aiops.securite import masquer_secrets


def executer(machine, commande, sudo=False, timeout=25):
    """Exécute une commande d'enquête. Lève CommandeRefusee si elle modifierait le système."""
    lecture.valider(commande)
    hote = config.ADRESSES.get(machine)
    if not hote:
        return {"ok": False, "code": None, "sortie": f"machine inconnue : {machine}", "injoignable": False}
    cmd = ["ssh", "-i", config.SSH_CLE, "-o", "BatchMode=yes", "-o", "ConnectTimeout=8",
           "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=yes",
           f"{config.SSH_USER}@{hote}", "sudo -n bash -s" if sudo else "bash -s"]
    try:
        p = subprocess.run(cmd, input=commande.strip() + "\n", capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"ok": False, "code": None, "sortie": "délai dépassé", "injoignable": True}
    except FileNotFoundError:
        return {"ok": False, "code": None, "sortie": "programme ssh introuvable", "injoignable": False}
    sortie = masquer_secrets((p.stdout + p.stderr).strip())
    return {"ok": p.returncode == 0, "code": p.returncode, "sortie": sortie, "injoignable": p.returncode == 255}
