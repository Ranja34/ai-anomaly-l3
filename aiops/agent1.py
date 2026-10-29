"""Agent 1 : enquête en lecture seule (SSH) puis diagnostic par l'IA."""
import argparse
import json
import os

from aiops import config, db, llm, ssh
from aiops.securite import SPECS, CommandeRefusee
from aiops.temps import formater_local

MAX_ENQUETES = int(os.getenv("AGENT1_MAX_ENQUETES", "1"))
GRAVITES = ("faible", "moyenne", "haute", "critique")

COMMANDES_STANDARD = {
    "up": ["systemctl status prometheus-node-exporter --no-pager",
           "systemctl is-active prometheus-node-exporter",
           "journalctl -u prometheus-node-exporter -n 30 --no-pager",
           "ss -tln", "uptime", "free -m", "df -h"],
    "cpu": ["uptime", "ps aux --sort=-%cpu", "free -m", "journalctl -n 30 -p warning --no-pager"],
    "ram": ["free -m", "ps aux --sort=-%mem", "journalctl -k -n 30 -p warning --no-pager", "uptime"],
    "disque": ["df -h", "du -x -h --max-depth=1 /var", "journalctl -n 30 -p warning --no-pager"],
}

SYSTEME = f"""Tu es un ingénieur système et réseau Linux chargé du DIAGNOSTIC d'incidents dans un petit laboratoire de deux machines.
Tu réponds UNIQUEMENT par un objet JSON valide, en français, sans texte autour.
Tu ne proposes aucune correction ici : seulement le diagnostic. Appuie-toi uniquement sur les preuves fournies.

Si les preuves suffisent :
{{"action": "conclure", "resume": "2 phrases claires", "gravite": "faible|moyenne|haute|critique",
 "cause_probable": "...", "confiance": "faible|moyenne|haute", "preuves": ["fait observé 1", "fait observé 2"],
 "service_concerne": "nom du service ou null", "machine": "machine concernée",
 "verification_recommandee": "comment vérifier que le problème est réglé"}}

Si elles ne suffisent pas, tu peux demander au plus 2 commandes de lecture seule supplémentaires :
{{"action": "enqueter", "commandes": [{{"machine": "...", "commande": "..."}}], "raison": "..."}}
Une commande = un seul programme avec ses options, sans pipe, sans redirection, sans guillemets, sans sudo.
Programmes autorisés : {", ".join(sorted(SPECS))}."""


def _tronquer(texte, commande, lignes=40, caracteres=2500):
    morceaux = (texte or "").splitlines()
    if len(morceaux) > lignes:
        morceaux = morceaux[-lignes:] if commande.startswith("journalctl") else morceaux[:lignes]
    resultat = "\n".join(morceaux)
    return resultat[:caracteres] + ("\n[...tronqué]" if len(resultat) > caracteres else "")


def _executer_liste(commandes):
    preuves, injoignables = [], set()
    for machine, commande in commandes:
        if machine in injoignables:
            continue
        try:
            res = ssh.executer(machine, commande)
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
    for tour in range(MAX_ENQUETES + 1):
        dernier = tour == MAX_ENQUETES
        message = {
            "incident": {"titre": inc["titre"], "machine": inc["machine"], "type": inc["source"],
                         "gravite_initiale": inc["gravite"]},
            "preuves": preuves,
        }
        if dernier:
            message["consigne"] = "Tu dois conclure maintenant (action = conclure)."
        rep = llm.demander_json(SYSTEME, json.dumps(message, ensure_ascii=False),
                                objet=f"diagnostic {inc['id']}", reponse_mock=_diagnostic_mock(inc))
        if rep.get("action") == "enqueter" and not dernier:
            demandes = [(c.get("machine") or inc["machine"], c.get("commande", ""))
                        for c in (rep.get("commandes") or [])[:2] if isinstance(c, dict)]
            nouvelles = _executer_liste(demandes)
            preuves = preuves + nouvelles
            db.ajouter_evenement(inc["id"], "enquete",
                                 f"Enquête complémentaire demandée par l'IA : {rep.get('raison', '')}",
                                 {"preuves": nouvelles})
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

    commandes = [(machine, c) for c in COMMANDES_STANDARD.get(inc["source"], ["uptime", "df -h", "free -m"])]
    preuves = _executer_liste(commandes)
    db.ajouter_evenement(incident_id, "enquete",
                         f"{len(preuves)} commandes en lecture seule exécutées sur {machine}",
                         {"preuves": preuves})
    try:
        diag = _boucle_ia(inc, preuves)
    except llm.QuotaDepasse as e:
        db.changer_statut(incident_id, "ouvert", f"Diagnostic IA reporté : {e}", "erreur")
        return None
    except llm.LLMErreur as e:
        db.changer_statut(incident_id, "echec_escalade",
                          f"Diagnostic IA impossible : {e}. Intervention humaine requise.", "erreur")
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
        print(f"  {formater_local(e['horodatage'], False)}  [{e['type']}]  {e['message'][:140]}")
    print(f"\nAppels IA aujourd'hui : {db.nombre_appels_ia_aujourdhui()}")


if __name__ == "__main__":
    main()
