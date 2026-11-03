"""Test chronométré : provoque une vraie panne (Node Exporter arrêté sur runner-devops) et mesure chaque phase.
Rien n'est approuvé automatiquement : la décision se prend dans l'interface web."""
import os
import subprocess
import time
from datetime import datetime, timezone

from aiops import db

SSH = ["ssh", "-i", os.path.expanduser("~/.ssh/id_ed25519_ansible"), "-o", "BatchMode=yes", "ranja@10.10.0.20"]


def _t(iso):
    return datetime.fromisoformat(iso)


def _attendre(condition, delai):
    fin = time.time() + delai
    while time.time() < fin:
        resultat = condition()
        if resultat:
            return resultat
        time.sleep(1)
    return None


def main():
    db.init_db()
    t0 = datetime.now(timezone.utc).replace(microsecond=0)
    subprocess.run(SSH + ["sudo systemctl stop prometheus-node-exporter"], check=False)
    print("Panne provoquée (Node Exporter arrêté sur runner-devops)", flush=True)
    try:
        def incident_ouvert():
            for i in db.lister_incidents(limite=10):
                if i["source"] == "up" and i["machine"] == "runner-devops" and _t(i["cree_le"]) >= t0:
                    return i["id"]

        iid = _attendre(incident_ouvert, 180)
        if not iid:
            print("Aucun incident ouvert en 3 minutes")
            return
        print(f"Incident {iid} ouvert ; attente de la proposition de l'IA...", flush=True)
        if not _attendre(lambda: db.get_incident(iid)["statut"] in ("attente_approbation", "resolu", "echec_escalade"), 240):
            print("Pas de proposition en 4 minutes")
            return
        print(">>> CORRECTION PRÊTE : ouvre http://10.10.0.10:5000 et clique « Approuver » (4 minutes max)", flush=True)
        _attendre(lambda: db.get_incident(iid)["statut"] in ("resolu", "echec_escalade", "nouvelle_tentative"), 240)

        inc = db.get_incident(iid)
        ev = {}
        for e in inc["evenements"]:
            ev.setdefault(e["type"], []).append(_t(e["horodatage"]))
        print("=" * 64)
        print("Statut final :", inc["statut"])
        print(f"Panne -> incident ouvert           : {(_t(inc['cree_le']) - t0).total_seconds():5.0f} s")
        if "proposition" in ev:
            print(f"Incident -> correction proposée    : {(ev['proposition'][-1] - _t(inc['cree_le'])).total_seconds():5.0f} s")
            print(f"Panne -> correction proposée       : {(ev['proposition'][-1] - t0).total_seconds():5.0f} s")
        if "decision" in ev and "execution" in ev:
            print(f"Approbation -> exécution terminée  : {(ev['execution'][-1] - ev['decision'][0]).total_seconds():5.0f} s")
        if "decision" in ev and "resolu" in ev:
            print(f"Approbation -> problème résolu     : {(ev['resolu'][-1] - ev['decision'][0]).total_seconds():5.0f} s")
        print("Chronologie (secondes après la panne) :")
        for e in inc["evenements"]:
            print(f"  +{(_t(e['horodatage']) - t0).total_seconds():4.0f} s  [{e['type']}] {e['message'][:84]}")
        with db.connexion() as c:
            n, tok = c.execute("SELECT COUNT(*), COALESCE(SUM(tokens), 0) FROM appels_ia WHERE objet LIKE ?",
                               (f"%{iid}%",)).fetchone()
        print(f"Appels IA pour cet incident : {n} | tokens : {tok}")
        print("=" * 64)
    finally:
        subprocess.run(SSH + ["sudo systemctl start prometheus-node-exporter"], check=False)
        print("(Node Exporter remis en marche par sécurité)")


if __name__ == "__main__":
    main()
