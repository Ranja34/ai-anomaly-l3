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

LOKI_URL = os.getenv("LOKI_URL", "http://10.10.0.10:3100").rstrip("/")


# ---- Inventaire des machines : source unique (inventaire.yml), sinon réglages historiques du laboratoire ----
import yaml

INVENTAIRE_FICHIER = Path(os.getenv("AIOPS_INVENTAIRE", str(RACINE / "inventaire.yml")))
OS_VALIDES = ("linux", "windows")
MODES_VALIDES = ("approbation", "observation")


def _charger_inventaire():
    if not INVENTAIRE_FICHIER.exists():
        return {nom: {"nom": nom, "ip": ip, "os": "linux", "ssh": True, "mode": "approbation",
                      "port_metriques": 9100} for nom, ip in ADRESSES.items()}
    donnees = yaml.safe_load(INVENTAIRE_FICHIER.read_text(encoding="utf-8")) or {}
    inventaire = {}
    for i, m in enumerate(donnees.get("machines") or [], 1):
        if not isinstance(m, dict) or not m.get("nom") or not m.get("ip"):
            raise ValueError(f"inventaire : machine n°{i} invalide (nom et ip obligatoires)")
        systeme = str(m.get("os", "linux")).lower()
        mode = str(m.get("mode", "approbation")).lower()
        if systeme not in OS_VALIDES:
            raise ValueError(f"inventaire : système inconnu pour {m['nom']} ({systeme})")
        if mode not in MODES_VALIDES:
            raise ValueError(f"inventaire : mode inconnu pour {m['nom']} ({mode})")
        nom = str(m["nom"])
        if nom in inventaire:
            raise ValueError(f"inventaire : machine en double ({nom})")
        inventaire[nom] = {"nom": nom, "ip": str(m["ip"]), "os": systeme, "mode": mode,
                           "ssh": bool(m.get("ssh", systeme == "linux")),
                           "port_metriques": int(m.get("port_metriques", 9100 if systeme == "linux" else 9182))}
    if not inventaire:
        raise ValueError("inventaire vide")
    return inventaire


INVENTAIRE = _charger_inventaire()
MACHINES = {m["ip"]: nom for nom, m in INVENTAIRE.items()}
ADRESSES = {nom: m["ip"] for nom, m in INVENTAIRE.items()}


def os_de(machine):
    return INVENTAIRE.get(machine, {}).get("os", "linux")


def mode_de(machine):
    return INVENTAIRE.get(machine, {}).get("mode", "approbation")


def ssh_actif(machine):
    return bool(INVENTAIRE.get(machine, {}).get("ssh", True))


def machines_ssh():
    return sorted(n for n, m in INVENTAIRE.items() if m["ssh"])


def machines_actionnables():
    """Machines sur lesquelles l'IA peut proposer des corrections : accès SSH et mode approbation."""
    return sorted(n for n, m in INVENTAIRE.items() if m["ssh"] and m["mode"] == "approbation")
