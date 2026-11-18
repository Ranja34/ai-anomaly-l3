"""Agent 2 : écrit la correction, la soumet à approbation, l'exécute, vérifie, recommence si besoin."""
import argparse
import hashlib
import json
import os
import time

import requests

from aiops import config, db, detecteurs, executeur, llm
from aiops.securite import masquer_secrets
from aiops.temps import formater_local
from aiops import validation
from aiops.validation import CorrectionRefusee, valider_correction

DELAIS_VERIFICATION = {"up": 90, "disque": 60, "cpu": 180, "ram": 180,
                       "service": 90, "reseau": 120, "securite": 180, "logs": 180}
RISQUES = ("faible", "moyen", "eleve")


def _max_tentatives():
    return int(os.getenv("AGENT2_MAX_TENTATIVES", "3"))


def _regles_mode():
    if validation.mode() == "strict":
        return ("Interdit : redémarrer ou éteindre la machine, rm récursif, formater, toucher aux comptes, aux clés SSH, "
                "au pare-feu, au service ssh, télécharger du code (curl, wget).")
    return ("Tu peux agir sur les services, le pare-feu (ufw, iptables), la configuration SSH, les paquets, les "
            "utilisateurs et télécharger si l'incident l'exige. Interdits absolus : éteindre la machine (shutdown, "
            "poweroff), rm récursif sur un dossier système, formater un disque, bloquer SSH (port 22) ou le réseau "
            "10.10.0.0/24, arrêter les services prometheus, loki, alloy, node-exporter ou aiops.")


def _systeme():
    machines = ", ".join(sorted(config.ADRESSES))
    interdits = _regles_mode()
    return f"""Tu es un ingénieur système Linux (Ubuntu 22.04) chargé de CORRIGER un incident dans un laboratoire de deux machines : {machines}.
Tu écris toi-même la correction : soit un playbook Ansible, soit un script bash, selon ce qui est le plus simple et le plus sûr.
Tu réponds UNIQUEMENT par un objet JSON valide, en français, sans texte autour :
{{"type": "playbook" ou "script", "machine": "...", "contenu": "...", "sudo_requis": true ou false, "resume_action": "une phrase", "justification": "pourquoi cette correction traite la cause", "risque": "faible|moyen|eleve"}}

Règles :
- Correction minimale, ciblée sur la cause du diagnostic, idempotente.
- Playbook : un seul play avec exactement « hosts: <machine> », « gather_facts: false » et une liste de tâches. N'écris PAS « become » : indique sudo_requis=true si des privilèges administrateur sont nécessaires (services systemd, apt, fichiers système).
- Script : commence par #!/bin/bash et set -eu, affiche ce qu'il fait, n'utilise PAS sudo (le programme l'ajoute si sudo_requis=true).
- sudo_requis=true uniquement si c'est nécessaire.
- {interdits}
- Si des tentatives précédentes ont échoué, analyse pourquoi (sortie et vérification fournies) et propose une approche DIFFÉRENTE.
- Le contenu est du texte brut (YAML ou bash) ; les retours à la ligne sont écrits \\n dans le JSON."""


def _preuves(inc):
    resultat = []
    for e in inc["evenements"]:
        if e["type"] == "enquete" and e.get("details"):
            try:
                for p in json.loads(e["details"]).get("preuves", []):
                    resultat.append({"commande": p.get("commande"), "sortie": (p.get("sortie") or "")[:800]})
            except ValueError:
                continue
    return resultat[-10:]


def _diagnostic(inc):
    for e in reversed(inc["evenements"]):
        if e["type"] == "diagnostic" and e.get("details"):
            try:
                return json.loads(e["details"])
            except ValueError:
                break
    return {"resume": inc.get("resume"), "cause_probable": inc.get("cause_probable")}


def _contexte(inc, tentative, erreur):
    precedentes = [{"tentative": p["tentative"], "type": p["type"], "contenu": p["contenu"],
                    "statut": p["statut"], "code_retour": p["code_retour"],
                    "sortie": (p["sortie"] or "")[-1200:]}
                   for p in inc["propositions"] if p["statut"] in ("executee", "echec")]
    contexte = {"incident": {"titre": inc["titre"], "machine": inc["machine"], "type": inc["source"]},
                "diagnostic": _diagnostic(inc), "preuves": _preuves(inc),
                "tentative": tentative, "tentatives_precedentes": precedentes}
    if erreur:
        contexte["erreur_de_ta_proposition_precedente"] = erreur
    return json.dumps(contexte, ensure_ascii=False)


def _mock(inc):
    m = inc["machine"]
    if inc["source"] == "up":
        contenu = (f"- name: Rétablir prometheus-node-exporter\n  hosts: {m}\n  gather_facts: false\n  tasks:\n"
                   "    - name: Démarrer et activer le service\n      ansible.builtin.systemd:\n"
                   "        name: prometheus-node-exporter\n        state: started\n        enabled: true\n")
        return {"type": "playbook", "machine": m, "contenu": contenu, "sudo_requis": True, "risque": "faible",
                "resume_action": "Démarrer prometheus-node-exporter et l'activer au démarrage",
                "justification": "Le service est arrêté : le démarrer rétablit l'export des métriques."}
    return {"type": "script", "machine": m, "sudo_requis": False, "risque": "faible",
            "contenu": "#!/bin/bash\nset -eu\necho 'Simulation (mode mock) : aucune action réelle'\n",
            "resume_action": "Simulation (mode mock)", "justification": "Mode mock."}


def _normaliser(rep, inc):
    type_, contenu = rep.get("type"), rep.get("contenu")
    if type_ not in ("playbook", "script") or not isinstance(contenu, str) or not contenu.strip():
        raise CorrectionRefusee("réponse IA incomplète (type ou contenu manquant)")
    return {
        "type": type_, "contenu": contenu,
        "machine": rep.get("machine") if rep.get("machine") in config.ADRESSES else inc["machine"],
        "sudo_requis": bool(rep.get("sudo_requis")),
        "risque": rep.get("risque") if rep.get("risque") in RISQUES else "moyen",
        "resume_action": str(rep.get("resume_action") or "Correction proposée")[:300],
        "justification": str(rep.get("justification") or "")[:600],
    }


def _escalader(incident_id, message):
    db.changer_statut(incident_id, "echec_escalade", f"{message} Intervention humaine requise.", "escalade")


def proposer(incident_id):
    """L'IA écrit une correction. Retourne l'identifiant de la proposition, ou None."""
    inc = db.get_incident(incident_id)
    if not inc:
        raise ValueError(f"Incident introuvable : {incident_id}")
    if inc["statut"] not in ("diagnostique", "nouvelle_tentative"):
        raise ValueError(f"Statut inattendu pour proposer une correction : {inc['statut']}")
    maxi = _max_tentatives()
    tentative = inc["tentatives"] + 1
    if tentative > maxi:
        _escalader(incident_id, f"{maxi} tentatives épuisées sans résolution.")
        return None

    precedent = inc["statut"]
    db.changer_statut(incident_id, "redaction_correction",
                      f"L'IA rédige une correction (tentative {tentative}/{maxi})", "proposition")
    erreur, prop = None, None
    for _ in range(2):
        try:
            rep = llm.demander_json(_systeme(), _contexte(inc, tentative, erreur),
                                    objet=f"correction {incident_id} t{tentative}", reponse_mock=_mock(inc))
            prop = _normaliser(rep, inc)
            valider_correction(prop["type"], prop["machine"], prop["contenu"])
            executeur.verifier_syntaxe(prop["type"], prop["machine"], prop["contenu"])
            break
        except CorrectionRefusee as e:
            erreur, prop = str(e), None
            db.ajouter_evenement(incident_id, "securite", f"Correction rejetée automatiquement : {erreur}")
        except llm.QuotaDepasse as e:
            db.changer_statut(incident_id, precedent, f"Rédaction de la correction reportée : {e}", "erreur")
            return None
        except llm.LLMErreur as e:
            _escalader(incident_id, f"Rédaction de la correction impossible : {e}.")
            return None
        except RuntimeError as e:
            _escalader(incident_id, f"Erreur de configuration : {e}.")
            return None
    if prop is None:
        _escalader(incident_id, f"Aucune correction acceptable après contrôle ({erreur}).")
        return None

    proposition_id = db.creer_proposition(incident_id, tentative, prop["machine"], prop["type"], prop["contenu"],
                                          prop["sudo_requis"], prop["justification"], prop["risque"])
    db.mettre_a_jour_incident(incident_id, tentatives=tentative)
    db.changer_statut(incident_id, "attente_approbation",
                      f"Correction proposée (tentative {tentative}/{maxi}) : {prop['resume_action']}",
                      "proposition", {"proposition_id": proposition_id, "type": prop["type"],
                                      "sudo_requis": prop["sudo_requis"], "risque": prop["risque"]})
    return proposition_id


def refuser(proposition_id):
    prop = db.get_proposition(proposition_id)
    if not prop:
        raise ValueError(f"Proposition introuvable : {proposition_id}")
    if not db.decider_proposition(proposition_id, "refusee"):
        raise ValueError("Cette proposition n'est plus en attente")
    db.changer_statut(prop["incident_id"], "refuse", "Correction refusée par l'administrateur", "decision")


def _verifier(inc, timeout_s, pas_s=5):
    fin = time.monotonic() + timeout_s
    while True:
        try:
            if inc["source"] == "up":
                instance = inc["empreinte"].split(":", 1)[1]
                res = detecteurs._requete(f'up{{instance="{instance}"}}')
                ok = bool(res) and float(res[0]["value"][1]) == 1
                detail = (f"la cible {instance} est de nouveau up dans Prometheus" if ok
                          else f"la cible {instance} est toujours injoignable")
            else:
                presentes = {a.empreinte for a in detecteurs.collecter_anomalies()}
                ok = inc["empreinte"] not in presentes
                detail = "la métrique est repassée sous le seuil" if ok else "la métrique dépasse encore le seuil"
        except (requests.RequestException, RuntimeError, ValueError, KeyError, IndexError) as e:
            ok, detail = False, f"vérification impossible ({type(e).__name__})"
        if ok or time.monotonic() >= fin:
            return ok, detail
        time.sleep(pas_s)


def approuver(proposition_id):
    """Enregistre l'approbation. L'exécution est ensuite prise en charge par executer_approuvee()."""
    prop = db.get_proposition(proposition_id)
    if not prop:
        raise ValueError(f"Proposition introuvable : {proposition_id}")
    if not db.decider_proposition(proposition_id, "approuvee"):
        raise ValueError("Cette proposition n'est plus en attente")
    droits = "avec privilèges administrateur (sudo)" if prop["sudo_requis"] else "sans privilèges administrateur"
    empreinte = hashlib.sha256(prop["contenu"].encode("utf-8")).hexdigest()[:12]
    db.changer_statut(prop["incident_id"], "approuve",
                      f"Correction approuvée par l'administrateur, {droits}", "decision",
                      {"proposition_id": proposition_id, "empreinte_contenu": empreinte})


def executer_approuvee(proposition_id):
    """Exécute une correction approuvée puis vérifie le rétablissement.
    Retourne 'resolu', 'nouvelle_tentative' ou 'echec_escalade'."""
    prop = db.get_proposition(proposition_id)
    if not prop:
        raise ValueError(f"Proposition introuvable : {proposition_id}")
    if not db.demarrer_execution(proposition_id):
        raise ValueError("Cette proposition n'est pas approuvée ou est déjà en cours d'exécution")

    iid, machine, sudo = prop["incident_id"], prop["machine"], bool(prop["sudo_requis"])
    db.changer_statut(iid, "execution", f"Exécution du {prop['type']} sur {machine}", "execution")
    try:
        res = executeur.executer(prop["type"], machine, prop["contenu"], sudo)
    except Exception as e:  # une erreur inattendue ne doit pas bloquer l'incident
        res = {"ok": False, "code": None, "sortie": f"erreur inattendue : {type(e).__name__}: {e}"}
    sortie = masquer_secrets(res["sortie"])[-6000:]
    db.mettre_a_jour_proposition(proposition_id, statut="executee" if res["ok"] else "echec",
                                 code_retour=res["code"], sortie=sortie)
    db.ajouter_evenement(iid, "execution",
                         f"Exécution {'réussie' if res['ok'] else 'en échec'} (code de retour : {res['code']})",
                         {"sortie": sortie[-1500:]})

    inc = db.get_incident(iid)
    db.changer_statut(iid, "verification", "Vérification du rétablissement en cours", "verification")
    delai = DELAIS_VERIFICATION.get(inc["source"], 60) if res["ok"] else 10
    ok, detail = _verifier(inc, delai)
    if ok:
        db.changer_statut(iid, "resolu", f"Problème résolu : {detail}", "resolu")
        return "resolu"

    db.mettre_a_jour_proposition(proposition_id, sortie=(sortie + f"\n[Vérification] {detail}")[-6000:])
    maxi = _max_tentatives()
    if inc["tentatives"] >= maxi:
        db.changer_statut(iid, "echec_escalade",
                          f"Le problème persiste après {maxi} tentatives ({detail}). Intervention humaine requise.",
                          "escalade")
        return "echec_escalade"
    db.changer_statut(iid, "nouvelle_tentative",
                      f"Le problème persiste ({detail}). Nouvelle analyse en cours "
                      f"(tentative {inc['tentatives'] + 1}/{maxi})", "echec")
    return "nouvelle_tentative"


def approuver_et_executer(proposition_id):
    """Utilisé par la ligne de commande et les tests : décision puis exécution."""
    approuver(proposition_id)
    return executer_approuvee(proposition_id)


# ---------- Utilisation en ligne de commande (la future interface web utilisera les mêmes fonctions) ----------

def _afficher(prop, maxi):
    ligne = "=" * 64
    print(f"\n{ligne}\nCORRECTION PROPOSÉE (tentative {prop['tentative']}/{maxi})")
    print(f"Machine : {prop['machine']} | Type : {prop['type']} | Risque : {prop['risque']}")
    print("Privilèges administrateur (sudo) :", "OUI" if prop["sudo_requis"] else "non")
    print(f"Justification : {prop['justification']}\n{'-' * 64}\n{prop['contenu']}\n{ligne}")


def traiter_interactif(incident_id):
    while True:
        statut = db.get_incident(incident_id)["statut"]
        if statut in db.STATUTS_FINAUX:
            return statut
        proposition_id = proposer(incident_id)
        if not proposition_id:
            return db.get_incident(incident_id)["statut"]
        _afficher(db.get_proposition(proposition_id), _max_tentatives())
        if input("Approuver cette correction ? [o/N] ").strip().lower() not in ("o", "oui", "y", "yes"):
            refuser(proposition_id)
            return "refuse"
        print("Exécution et vérification en cours (jusqu'à 90 s)...")
        if approuver_et_executer(proposition_id) != "nouvelle_tentative":
            return db.get_incident(incident_id)["statut"]
        print("Le problème persiste : nouvelle tentative...")


def main():
    parser = argparse.ArgumentParser(description="Agent 2 : correction")
    groupe = parser.add_mutually_exclusive_group(required=True)
    groupe.add_argument("--incident", help="identifiant de l'incident diagnostiqué")
    groupe.add_argument("--prochain", action="store_true", help="plus ancien incident diagnostiqué")
    args = parser.parse_args()

    db.init_db()
    incident_id = args.incident
    if args.prochain:
        candidats = db.lister_incidents(statut="diagnostique")
        if not candidats:
            print("Aucun incident diagnostiqué en attente de correction.")
            return
        incident_id = candidats[-1]["id"]

    statut = traiter_interactif(incident_id)
    print(f"\nRésultat final : {statut}\n\nChronologie :")
    for e in db.get_incident(incident_id)["evenements"]:
        print(f"  {formater_local(e['horodatage'], False)}  [{e['type']}]  {e['message'][:150]}")
    print(f"\nAppels IA aujourd'hui : {db.nombre_appels_ia_aujourdhui()}")


if __name__ == "__main__":
    main()
