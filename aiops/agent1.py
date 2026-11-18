"""Agent 1 : enquête libre en lecture seule (commandes écrites par l'IA, en plusieurs tours) puis diagnostic."""
import argparse
import json
import os

from aiops import config, db, llm, ssh
from aiops.securite import CommandeRefusee
from aiops.temps import formater_local

GRAVITES = ("faible", "moyenne", "haute", "critique")


def _max_tours():
    return int(os.getenv("AGENT1_MAX_TOURS", "4"))


def _systeme(maxi):
    machines = ", ".join(sorted(config.ADRESSES))
    return f"""Tu es un ingénieur système, réseau et sécurité Linux chargé du DIAGNOSTIC d'incidents dans un laboratoire de deux machines Ubuntu 22.04 : {machines}.
Contexte : ufw actif ; nginx et docker installés ; fail2ban sur frappe-staging ; Prometheus, Loki et Grafana sur frappe-staging ; les journaux d'authentification sont dans journalctl (unité ssh) et dans /var/log/auth.log.
Tu réponds UNIQUEMENT par un objet JSON valide, en français, sans texte autour. Tu ne proposes aucune correction ici : seulement le diagnostic, appuyé sur des preuves.

Pour enquêter, écris toi-même des commandes shell en LECTURE SEULE (au plus 4 par tour, {maxi} tours au total) :
{{"action": "commandes", "raison": "ce que tu cherches", "commandes": [{{"machine": "...", "commande": "...", "sudo": false}}]}}
Règles : pipes, grep, awk, sort, head, tail autorisés ; aucune modification (pas de rm, systemctl restart, ufw allow, kill, apt install...) ; aucune redirection vers un fichier ; n'écris pas « sudo » dans la commande : mets "sudo": true si la lecture l'exige (auth.log, ufw status, iptables -L, lastb, fail2ban-client status) ; une seule ligne par commande.

Dès que tu as assez de preuves :
{{"action": "conclure", "resume": "2 phrases claires", "gravite": "faible|moyenne|haute|critique", "cause_probable": "...", "confiance": "faible|moyenne|haute", "preuves": ["fait observé 1", "fait observé 2"], "service_concerne": "nom du service ou null", "machine": "machine concernée", "verification_recommandee": "comment vérifier que c'est réglé"}}
Ne conclus jamais que « les logs ne sont pas disponibles » sans avoir essayé journalctl ET une lecture avec sudo. Si l'incident est un faux positif ou ne demande aucune action, dis-le dans le résumé."""


def _commandes_standard(inc):
    """Premier passage sans IA : commandes adaptées au type d'incident. Retourne (machine, commande, sudo)."""
    machine, source = inc["machine"], inc["source"]
    nom = inc["empreinte"].rsplit(":", 1)[-1]
    if source == "up":
        liste = [("systemctl status prometheus-node-exporter --no-pager", False),
                 ("systemctl is-active prometheus-node-exporter", False),
                 ("journalctl -u prometheus-node-exporter -n 30 --no-pager", False),
                 ("ss -tln", False), ("uptime", False), ("free -m", False), ("df -h", False)]
    elif source == "cpu":
        liste = [("uptime", False), ("ps aux --sort=-%cpu | head -n 15", False), ("free -m", False),
                 ("journalctl -n 30 -p warning --no-pager", False)]
    elif source == "ram":
        liste = [("free -m", False), ("ps aux --sort=-%mem | head -n 15", False),
                 ("journalctl -k -n 30 -p warning --no-pager", False), ("uptime", False)]
    elif source == "disque":
        liste = [("df -h", False), ("du -x -h --max-depth=1 /var 2>/dev/null | sort -h | tail -n 10", False),
                 ("df -i", False), ("journalctl -n 30 -p warning --no-pager", False)]
    elif source == "service":
        liste = [(f"systemctl status {nom} --no-pager", False), (f"journalctl -u {nom} -n 40 --no-pager", False),
                 ("systemctl list-units --failed --no-pager", False)]
    elif source == "securite" and ":sudo:" in inc["empreinte"]:
        liste = [('journalctl -n 150 --no-pager | grep -E "sudo" | tail -n 25', False),
                 ("last -n 15", False), ("who", False)]
    elif source == "securite":
        liste = [('journalctl -n 150 --no-pager | grep -E "Failed password|Invalid user" | tail -n 25', False),
                 ("ss -tn | grep ':22 '", False), ("lastb -n 15", True),
                 ("ufw status verbose", True), ("fail2ban-client status", True)]
    elif source == "reseau":
        liste = [("ip -br a", False), ("ip route", False), ("ip -s link", False), ("ss -s", False),
                 ("ufw status verbose", True)]
        autres = [ip for ip, n in config.MACHINES.items() if n != machine]
        if autres:
            liste.append((f"ping -c 3 {autres[0]}", False))
    elif source == "logs":
        liste = [('journalctl -p err -n 60 --no-pager --since "30 min ago"', False),
                 ("journalctl -k -n 40 --no-pager", False), ("df -h", False), ("free -m", False)]
    else:
        liste = [("uptime", False), ("df -h", False), ("free -m", False),
                 ("systemctl list-units --failed --no-pager", False)]
    return [(machine, c, s) for c, s in liste]


def _tronquer(texte, commande, lignes=40, caracteres=2500):
    morceaux = (texte or "").splitlines()
    if len(morceaux) > lignes:
        morceaux = morceaux[-lignes:] if commande.startswith("journalctl") else morceaux[:lignes]
    resultat = "\n".join(morceaux)
    return resultat[:caracteres] + ("\n[...tronqué]" if len(resultat) > caracteres else "")


def _executer_liste(commandes):
    """Exécute des (machine, commande[, sudo]). Une machine injoignable n'est interrogée qu'une fois."""
    preuves, injoignables = [], set()
    for element in commandes:
        machine, commande = element[0], element[1]
        sudo = bool(element[2]) if len(element) > 2 else False
        if machine in injoignables:
            continue
        try:
            res = ssh.executer(machine, commande, sudo)
        except CommandeRefusee as e:
            preuves.append({"machine": machine, "commande": commande, "code": None,
                            "sortie": f"COMMANDE REFUSÉE : {e}"})
            continue
        if res["injoignable"]:
            injoignables.add(machine)
            res["sortie"] = f"Connexion SSH impossible : {res['sortie'] or 'machine injoignable'}"
        preuves.append({"machine": machine, "commande": commande, "code": res["code"],
                        "sortie": _tronquer(res["sortie"], commande)})
    return preuves


def _budget(preuves, max_total=6000):
    """Limite la taille envoyée à l'IA : les anciennes sorties sont raccourcies."""
    if sum(len(p["sortie"]) for p in preuves) <= max_total:
        return preuves
    n = len(preuves)
    return [{**p, "sortie": p["sortie"][:400] if i < n - 6 else p["sortie"]} for i, p in enumerate(preuves)]


def _diagnostic_mock(inc):
    m = inc["machine"]
    if inc["source"] == "up":
        return {"action": "conclure", "gravite": "haute", "machine": m, "confiance": "haute",
                "resume": f"Le service prometheus-node-exporter est arrêté sur {m} : Prometheus ne reçoit plus ses métriques.",
                "cause_probable": "Arrêt du service prometheus-node-exporter (volontaire ou crash).",
                "preuves": ["Le service est inactif d'après systemctl", "Le port 9100 n'est plus en écoute"],
                "service_concerne": "prometheus-node-exporter",
                "verification_recommandee": "Vérifier que la cible 9100 repasse à l'état up dans Prometheus."}
    return {"action": "conclure", "gravite": inc["gravite"], "machine": m, "confiance": "moyenne",
            "resume": f"{inc['titre']} (diagnostic simulé en mode mock).",
            "cause_probable": "À déterminer (mode mock).", "preuves": ["Données simulées"],
            "service_concerne": None, "verification_recommandee": "Contrôler la métrique concernée."}


def _gravite_finale(proposee, mesuree):
    """La gravité n'est jamais abaissée en dessous de celle mesurée par le détecteur."""
    if proposee not in GRAVITES:
        return mesuree
    return max(proposee, mesuree, key=GRAVITES.index)


def _normaliser(rep, inc):
    if not rep.get("resume") or not rep.get("cause_probable"):
        raise llm.LLMErreur("Diagnostic IA incomplet")
    machine = rep.get("machine") if rep.get("machine") in config.ADRESSES else inc["machine"]
    preuves = rep.get("preuves") if isinstance(rep.get("preuves"), list) else []
    return {
        "resume": str(rep["resume"]),
        "gravite": _gravite_finale(rep.get("gravite"), inc["gravite"]),
        "cause_probable": str(rep["cause_probable"]),
        "confiance": rep.get("confiance") or "moyenne",
        "preuves": [str(p) for p in preuves][:6],
        "service_concerne": rep.get("service_concerne"),
        "machine": machine,
        "verification_recommandee": str(rep.get("verification_recommandee") or ""),
    }


def _boucle_ia(inc, preuves):
    maxi = _max_tours()
    forcer = False
    for tour in range(1, maxi + 1):
        dernier = forcer or tour == maxi
        message = {"incident": {"titre": inc["titre"], "machine": inc["machine"], "type": inc["source"],
                                "gravite_initiale": inc["gravite"]},
                   "preuves": _budget(preuves), "tour": f"{tour}/{maxi}"}
        if dernier:
            message["consigne"] = "Tu dois conclure maintenant (action = conclure)."
        rep = llm.demander_json(_systeme(maxi), json.dumps(message, ensure_ascii=False),
                                objet=f"diagnostic {inc['id']} t{tour}", reponse_mock=_diagnostic_mock(inc))
        if rep.get("action") in ("commandes", "enqueter") and not dernier:
            demandes = []
            for c in (rep.get("commandes") or [])[:4]:
                if isinstance(c, dict) and c.get("commande"):
                    machine = c.get("machine") if c.get("machine") in config.ADRESSES else inc["machine"]
                    commande, sudo = str(c["commande"]).strip(), bool(c.get("sudo"))
                    if commande.startswith("sudo "):
                        commande, sudo = commande[5:].lstrip(), True
                    demandes.append((machine, commande, sudo))
            if not demandes:
                forcer = True
                continue
            nouvelles = _executer_liste(demandes)
            preuves = preuves + nouvelles
            liste = " ; ".join(d[1] for d in demandes)[:300]
            db.ajouter_evenement(inc["id"], "enquete",
                                 f"Enquête complémentaire (tour {tour}/{maxi}) : {rep.get('raison', '')} "
                                 f"| commandes : {liste}", {"preuves": nouvelles})
            continue
        return _normaliser(rep, inc)
    raise llm.LLMErreur("Le diagnostic n'a pas abouti")


def diagnostiquer(incident_id):
    """Enquête + diagnostic. Retourne le diagnostic, ou None si l'IA n'a pas pu répondre."""
    inc = db.get_incident(incident_id)
    if not inc:
        raise ValueError(f"Incident introuvable : {incident_id}")
    machine = inc["machine"]
    db.changer_statut(incident_id, "diagnostic_en_cours",
                      f"Enquête en lecture seule lancée sur {machine}", "enquete")

    preuves = _executer_liste(_commandes_standard(inc))
    db.ajouter_evenement(incident_id, "enquete",
                         f"{len(preuves)} commandes en lecture seule exécutées sur {machine}",
                         {"preuves": preuves})
    try:
        diag = _boucle_ia(inc, preuves)
    except llm.QuotaDepasse as e:
        db.changer_statut(incident_id, "ouvert", f"Diagnostic IA reporté : {e}", "erreur")
        return None
    except llm.LLMErreur as e:
        if db.compter_evenements(incident_id, "erreur_ia") >= 1:
            db.changer_statut(incident_id, "echec_escalade",
                              f"Diagnostic IA impossible après un nouvel essai : {e}. Intervention humaine requise.",
                              "erreur_ia")
        else:
            db.changer_statut(incident_id, "ouvert",
                              f"Réponse IA inutilisable ({e}). Nouvel essai plus tard.", "erreur_ia")
        return None

    db.mettre_a_jour_incident(incident_id, resume=diag["resume"], cause_probable=diag["cause_probable"],
                              gravite=diag["gravite"])
    db.changer_statut(incident_id, "diagnostique", f"Diagnostic IA : {diag['resume']}", "diagnostic", diag)
    return diag


def main():
    parser = argparse.ArgumentParser(description="Agent 1 : enquête et diagnostic")
    groupe = parser.add_mutually_exclusive_group(required=True)
    groupe.add_argument("--incident", help="identifiant de l'incident")
    groupe.add_argument("--prochain", action="store_true", help="plus ancien incident ouvert")
    args = parser.parse_args()

    db.init_db()
    incident_id = args.incident
    if args.prochain:
        ouverts = db.lister_incidents(statut="ouvert")
        if not ouverts:
            print("Aucun incident ouvert à diagnostiquer.")
            return
        incident_id = ouverts[-1]["id"]

    print(f"Diagnostic de l'incident {incident_id}...")
    diag = diagnostiquer(incident_id)
    inc = db.get_incident(incident_id)
    print(f"\nStatut : {inc['statut']}")
    if diag:
        print(json.dumps(diag, ensure_ascii=False, indent=2))
    print("\nChronologie :")
    for e in inc["evenements"]:
        print(f"  {formater_local(e['horodatage'], False)}  [{e['type']}]  {e['message'][:160]}")
    print(f"\nAppels IA aujourd'hui : {db.nombre_appels_ia_aujourdhui()}")


if __name__ == "__main__":
    main()
