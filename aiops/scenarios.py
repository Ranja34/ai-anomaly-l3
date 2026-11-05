"""Scénarios de démonstration : provoque une vraie panne, chronomètre la détection et la résolution, puis nettoie.
Rien n'est approuvé automatiquement : la décision se prend dans l'interface web."""
import argparse
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone

from aiops import config, db

VM2 = "runner-devops"
RACINE = config.RACINE


@dataclass
class Scenario:
    nom: str
    titre: str
    machine: str      # machine où l'incident est attendu
    source: str       # type d'incident attendu
    motif: str        # fragment attendu dans l'empreinte de l'incident
    injection: list   # [(cible, sudo, script)] ; cible = nom de machine ou "local"
    nettoyage: list
    delai_detection: int = 240
    detection: str = ""


NGINX_INJECTION = """systemctl is-active nginx > /tmp/aiops_demo_nginx_etat 2>&1 || true
printf 'server {\\n    listen 8099;\\n    directive_invalide_demo on;\\n}\\n' > /etc/nginx/conf.d/demo-panne.conf
systemctl restart nginx || true
"""
NGINX_NETTOYAGE = """rm -f /etc/nginx/conf.d/demo-panne.conf
if [ "$(cat /tmp/aiops_demo_nginx_etat 2>/dev/null)" = "active" ]; then systemctl restart nginx || true; else systemctl stop nginx || true; fi
systemctl reset-failed nginx 2>/dev/null || true
rm -f /tmp/aiops_demo_nginx_etat
"""
DISQUE_INJECTION = """set -e
mkdir -p /srv/demo-disque
if ! mountpoint -q /srv/demo-disque; then
  fallocate -l 300M /var/tmp/demo-disque.img
  mkfs.ext4 -q -F -m 0 /var/tmp/demo-disque.img
  mount -o loop /var/tmp/demo-disque.img /srv/demo-disque
fi
fallocate -l 270M /srv/demo-disque/journal_applicatif_enorme.log
"""
DISQUE_NETTOYAGE = """umount /srv/demo-disque 2>/dev/null || umount -l /srv/demo-disque 2>/dev/null || true
rm -f /var/tmp/demo-disque.img
rmdir /srv/demo-disque 2>/dev/null || true
"""
CPU_INJECTION = "for i in 1 2; do setsid -f timeout 900 yes > /dev/null 2>&1 < /dev/null; done\n"
CPU_NETTOYAGE = "pkill -x yes || true\n"
RESEAU_INJECTION = "modprobe sch_netem\ntc qdisc replace dev ens37 root netem delay 300ms\n"
RESEAU_NETTOYAGE = "tc qdisc del dev ens37 root 2>/dev/null || true\n"
SSH_ALIAS = "ip addr add 10.10.0.99/24 dev ens37 2>/dev/null || true\n"
SSH_ATTAQUE = (f"cd {RACINE} && setsid -f scripts/attaque_ssh_continue.sh 10.10.0.20 600 10.10.0.99 "
               "> /dev/null 2>&1 < /dev/null\n")
SSH_ARRET = "pkill -f attaque_ssh_continue.sh || true\n"
SSH_ALIAS_RETRAIT = "ip addr del 10.10.0.99/24 dev ens37 2>/dev/null || true\n"
SSH_UFW_NETTOYAGE = """for i in $(seq 1 10); do
  n=$(ufw status numbered | grep -F '10.10.0.99' | head -n 1 | sed -E 's/^\\[ *([0-9]+)\\].*/\\1/')
  [ -z "$n" ] && break
  ufw --force delete "$n" > /dev/null
done
"""

SCENARIOS = {s.nom: s for s in [
    Scenario("noeud", "Node Exporter arrêté (cible de supervision injoignable)", VM2, "up", ":9100",
             [(VM2, True, "systemctl stop prometheus-node-exporter\n")],
             [(VM2, True, "systemctl start prometheus-node-exporter\n")], 150, "environ 40 s"),
    Scenario("service", "Service nginx en échec (configuration cassée)", VM2, "service", "nginx.service",
             [(VM2, True, NGINX_INJECTION)], [(VM2, True, NGINX_NETTOYAGE)], 180, "environ 40 s"),
    Scenario("disque", "Disque presque plein (gros fichier journal sur /srv/demo-disque)", VM2, "disque",
             "/srv/demo-disque", [(VM2, True, DISQUE_INJECTION)], [(VM2, True, DISQUE_NETTOYAGE)], 150,
             "environ 20 s"),
    Scenario("cpu", "Processeur saturé (deux processus « yes »)", VM2, "cpu", "cpu:",
             [(VM2, True, CPU_INJECTION)], [(VM2, True, CPU_NETTOYAGE)], 240, "environ 90 s"),
    Scenario("reseau", "Latence réseau élevée (300 ms ajoutées sur ens37)", VM2, "reseau", "reseau:latence",
             [(VM2, True, RESEAU_INJECTION)], [(VM2, True, RESEAU_NETTOYAGE)], 240, "environ 60 s"),
    Scenario("ssh", "Attaque SSH continue depuis 10.10.0.99", VM2, "securite", ":ssh:",
             [("local", True, SSH_ALIAS), ("local", False, SSH_ATTAQUE)],
             [("local", False, SSH_ARRET), ("local", True, SSH_ALIAS_RETRAIT), (VM2, True, SSH_UFW_NETTOYAGE)],
             240, "environ 40 s"),
]}


def _t(iso):
    return datetime.fromisoformat(iso)


def _executer(cible, sudo, script, timeout=90):
    if cible == "local":
        cmd = ["sudo", "bash", "-s"] if sudo else ["bash", "-s"]
    else:
        cmd = ["ssh", "-i", config.SSH_CLE, "-o", "BatchMode=yes", "-o", "ConnectTimeout=8",
               "-o", "IdentitiesOnly=yes", f"{config.SSH_USER}@{config.ADRESSES[cible]}",
               "sudo -n bash -s" if sudo else "bash -s"]
    try:
        p = subprocess.run(cmd, input=script, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return 124, "délai dépassé"
    return p.returncode, (p.stdout + p.stderr).strip()


def _correspond(sc, inc):
    return inc["source"] == sc.source and inc["machine"] == sc.machine and sc.motif in inc["empreinte"]


def _trouver(sc, t0):
    for inc in db.lister_incidents(limite=40):
        if _correspond(sc, inc) and _t(inc["cree_le"]) >= t0:
            return inc["id"]
    return None


def _preparer(sc):
    """False si un incident identique est encore actif ; supprime ceux (refusés ou échoués) qui bloqueraient."""
    incidents = [i for i in db.lister_incidents(limite=300) if _correspond(sc, i)]
    actifs = [i for i in incidents if i["statut"] not in db.STATUTS_FINAUX]
    if actifs:
        print(f"Un incident identique est encore actif ({actifs[0]['id']}) : termine-le ou supprime-le d'abord.")
        return False
    bloquants = [i for i in incidents if i["statut"] in ("echec_escalade", "refuse")]
    for inc in bloquants:
        db.supprimer_incident(inc["id"])
    if bloquants:
        print(f"{len(bloquants)} ancien(s) incident(s) identique(s) supprimé(s) de l'historique (ils bloquaient la réouverture).")
    return True


def _attendre(condition, delai):
    fin = time.time() + delai
    while time.time() < fin:
        resultat = condition()
        if resultat:
            return resultat
        time.sleep(1)
    return None


def _nettoyer(sc):
    for cible, sudo, script in sc.nettoyage:
        code, sortie = _executer(cible, sudo, script)
        if code != 0:
            print(f"  (nettoyage partiel sur {cible} : {sortie[-160:]})")
    print("Panne retirée.")


def _rapport(iid, t0):
    inc = db.get_incident(iid)
    ev = {}
    for e in inc["evenements"]:
        ev.setdefault(e["type"], []).append(e)
    cree = _t(inc["cree_le"])
    propositions = [_t(e["horodatage"]) for e in ev.get("proposition", []) if e["message"].startswith("Correction proposée")]
    decisions = [_t(e["horodatage"]) for e in ev.get("decision", [])]
    resolus = [_t(e["horodatage"]) for e in ev.get("resolu", [])]
    print("=" * 66)
    print("Statut final :", inc["statut"], "| tentatives :", inc["tentatives"])
    print(f"Panne -> incident ouvert           : {(cree - t0).total_seconds():5.0f} s")
    if propositions:
        print(f"Incident -> 1re correction proposée : {(propositions[0] - cree).total_seconds():5.0f} s")
    if decisions and resolus:
        print(f"1re approbation -> résolu          : {(resolus[-1] - decisions[0]).total_seconds():5.0f} s")
    if resolus:
        print(f"Panne -> résolu (décision incluse) : {(resolus[-1] - t0).total_seconds():5.0f} s")
    print("Chronologie (secondes après la panne) :")
    for e in inc["evenements"]:
        print(f"  +{(_t(e['horodatage']) - t0).total_seconds():4.0f} s  [{e['type']}] {e['message'][:84]}")
    with db.connexion() as c:
        n, tok = c.execute("SELECT COUNT(*), COALESCE(SUM(tokens), 0) FROM appels_ia WHERE objet LIKE ?",
                           (f"%{iid}%",)).fetchone()
    print(f"Appels IA pour cet incident : {n} | tokens : {tok}")
    print("=" * 66)


def lancer(sc):
    db.init_db()
    battement = db.get_etat("battement")
    if not battement or (datetime.now(timezone.utc) - _t(battement["mis_a_jour_le"])).total_seconds() > 120:
        print("L'orchestrateur ne répond pas : vérifie « systemctl is-active aiops-orchestrateur ».")
        return
    if not _preparer(sc):
        return
    print(f"Scénario : {sc.titre}", flush=True)
    t0 = datetime.now(timezone.utc).replace(microsecond=0)
    try:
        for cible, sudo, script in sc.injection:
            code, sortie = _executer(cible, sudo, script)
            if code != 0:
                print(f"Échec de l'injection sur {cible} : {sortie[-300:]}")
                return
        print(f"Panne provoquée. Détection attendue : {sc.detection}.", flush=True)
        iid = _attendre(lambda: _trouver(sc, t0), sc.delai_detection)
        if not iid:
            print("Aucun incident correspondant détecté dans le délai prévu.")
            return
        print(f"Incident {iid} détecté (+{(datetime.now(timezone.utc) - t0).total_seconds():.0f} s) ; "
              "attente de la correction de l'IA...", flush=True)
        notifie, fin = 0, time.time() + 900
        while time.time() < fin:
            inc = db.get_incident(iid)
            if inc["statut"] in db.STATUTS_FINAUX:
                break
            if inc["statut"] == "attente_approbation" and inc["tentatives"] > notifie:
                notifie = inc["tentatives"]
                print(f">>> CORRECTION {notifie} PRÊTE : ouvre http://10.10.0.10:5000 puis « Approuver » (ou « Refuser »)",
                      flush=True)
            time.sleep(1)
        _rapport(iid, t0)
    finally:
        print("Nettoyage...", flush=True)
        _nettoyer(sc)


def main():
    parser = argparse.ArgumentParser(description="Scénarios de démonstration")
    parser.add_argument("scenario", nargs="?", choices=sorted(SCENARIOS))
    parser.add_argument("--liste", action="store_true", help="afficher les scénarios disponibles")
    args = parser.parse_args()
    if args.liste or not args.scenario:
        for sc in SCENARIOS.values():
            print(f"  {sc.nom:<8} {sc.titre}  (détection : {sc.detection})")
        return
    lancer(SCENARIOS[args.scenario])


if __name__ == "__main__":
    main()
