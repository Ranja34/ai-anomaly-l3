"""Réglages centraux du projet."""
import os
from pathlib import Path

from dotenv import load_dotenv

RACINE = Path(__file__).resolve().parent.parent
load_dotenv(RACINE / ".env")

DB_PATH = Path(os.getenv("AIOPS_DB", RACINE / "data" / "aiops.db"))
FUSEAU = os.getenv("AIOPS_FUSEAU", "Indian/Antananarivo")

PROMETHEUS_URL = os.getenv("PROMETHEUS_URL", "http://10.10.0.10:9090").rstrip("/")
# Correspondance adresse IP -> nom de machine
MACHINES = {
    cle.strip(): valeur.strip()
    for cle, valeur in (
        p.split("=", 1)
        for p in os.getenv("AIOPS_MACHINES", "10.10.0.10=frappe-staging,10.10.0.20=runner-devops").split(",")
        if "=" in p
    )
}

# Accès SSH pour l'investigation et les corrections
ADRESSES = {nom: ip for ip, nom in MACHINES.items()}
SSH_CLE = os.path.expanduser(os.getenv("SSH_CLE", "~/.ssh/id_ed25519_ansible"))
SSH_USER = os.getenv("SSH_USER", "ranja")
