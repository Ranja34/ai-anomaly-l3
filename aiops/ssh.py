"""Exécution de commandes sur les machines via SSH (après validation par la liste blanche)."""
import subprocess

from aiops import config
from aiops.securite import masquer_secrets, valider


def executer(machine, commande, timeout=20):
    """Exécute une commande d'investigation en lecture seule. Lève CommandeRefusee si non autorisée."""
    valider(commande)
    hote = config.ADRESSES.get(machine)
    if not hote:
        return {"ok": False, "code": None, "sortie": f"machine inconnue : {machine}", "injoignable": False}
    cmd = ["ssh", "-i", config.SSH_CLE, "-o", "BatchMode=yes", "-o", "ConnectTimeout=8",
           "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=yes",
           f"{config.SSH_USER}@{hote}", commande.strip()]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"ok": False, "code": None, "sortie": "délai dépassé", "injoignable": True}
    except FileNotFoundError:
        return {"ok": False, "code": None, "sortie": "programme ssh introuvable", "injoignable": False}
    sortie = masquer_secrets((p.stdout + p.stderr).strip())
    return {"ok": p.returncode == 0, "code": p.returncode, "sortie": sortie,
            "injoignable": p.returncode == 255}
