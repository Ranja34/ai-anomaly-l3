"""Banc d'essai du moteur IA : vitesse et qualité sur des prompts réalistes.
N'exécute rien sur les machines et ne modifie pas le moteur actif de l'interface."""
import argparse
import json
import statistics
import time

from aiops import agent1, agent2, db, executeur, llm
from aiops.temps import maintenant_utc
from aiops.validation import CorrectionRefusee, valider_correction

SORTIE_SSH = "\n".join(
    f"Nov 03 10:{15 + i // 6:02d}:{(i * 10) % 60:02d} runner-devops sshd[{2000 + i}]: "
    f"Invalid user intrus{i} from 10.10.0.99 port {40000 + i}" for i in range(25))
PREUVES = [
    {"machine": "runner-devops", "code": 0, "sortie": SORTIE_SSH,
     "commande": "journalctl -n 150 --no-pager | grep -E 'Failed password|Invalid user' | tail -n 25"},
    {"machine": "runner-devops", "commande": "ufw status verbose", "code": 0,
     "sortie": "Status: active\nLogging: on (low)\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n\n"
               "To                         Action      From\n--                         ------      ----\n"
               "22/tcp                     ALLOW IN    Anywhere\n9100/tcp                   ALLOW IN    10.10.0.10"},
    {"machine": "runner-devops", "commande": "fail2ban-client status", "code": 127,
     "sortie": "bash: fail2ban-client: command not found"},
    {"machine": "runner-devops", "commande": "ss -tn | grep ':22 '", "code": 0,
     "sortie": "ESTAB 0 0 10.10.0.20:22 10.10.0.10:51234"},
]
INCIDENT = {
    "id": "banc", "titre": "Tentatives de connexion SSH suspectes sur runner-devops", "machine": "runner-devops",
    "source": "securite", "gravite": "haute", "empreinte": "securite:ssh:runner-devops",
    "evenements": [{"type": "mesure", "message": "20 échecs d'authentification SSH sur runner-devops en 2m (seuil : 10)."}],
}
DIAGNOSTIC = {"resume": "Attaque par force brute SSH depuis 10.10.0.99 ; aucune connexion réussie.",
              "cause_probable": "Tentatives répétées sur le port 22 depuis 10.10.0.99, fail2ban absent.",
              "preuves": ["25 lignes « Invalid user » depuis 10.10.0.99", "fail2ban n'est pas installé",
                          "Le port 22 est ouvert à tous"], "service_concerne": "ssh"}


def _essai_diagnostic():
    message = {"incident": {"titre": INCIDENT["titre"], "machine": INCIDENT["machine"], "type": INCIDENT["source"],
                            "gravite_initiale": INCIDENT["gravite"], "description": agent1._description(INCIDENT)},
               "preuves": PREUVES, "tour": "2/2", "consigne": "Tu dois conclure maintenant (action = conclure)."}
    rep = llm.demander_json(agent1._systeme(2), json.dumps(message, ensure_ascii=False), objet="banc diagnostic")
    if rep.get("action") != "conclure":
        raise llm.LLMErreur("n'a pas conclu (action inattendue)")
    diag = agent1._normaliser(rep, INCIDENT)
    return "cite 10.10.0.99" if "10.10.0.99" in json.dumps(diag, ensure_ascii=False) else "n'identifie pas l'attaquant"


def _essai_correction():
    inc = dict(INCIDENT)
    inc["propositions"] = []
    inc["evenements"] = INCIDENT["evenements"] + [
        {"type": "enquete", "message": "enquête", "details": json.dumps({"preuves": PREUVES})},
        {"type": "diagnostic", "message": "diagnostic", "details": json.dumps(DIAGNOSTIC)}]
    rep = llm.demander_json(agent2._systeme(), agent2._contexte(inc, 1, None), objet="banc correction")
    prop = agent2._normaliser(rep, inc)
    valider_correction(prop["type"], prop["machine"], prop["contenu"])
    executeur.verifier_syntaxe(prop["type"], prop["machine"], prop["contenu"])
    cible = "bloque 10.10.0.99" if "10.10.0.99" in prop["contenu"] else "ne vise pas l'attaquant"
    return f"{prop['type']}, sudo {'oui' if prop['sudo_requis'] else 'non'}, {cible}"


def _mesurer(nom, essai, n):
    durees, valides = [], 0
    for i in range(n):
        debut = time.monotonic()
        try:
            note, etat = essai(), "valide "
            valides += 1
        except (llm.LLMErreur, CorrectionRefusee, RuntimeError) as e:
            note, etat = f"ÉCHEC : {e}", "ÉCHEC  "
        durees.append(time.monotonic() - debut)
        print(f"  {nom} #{i + 1} : {durees[-1]:5.1f} s | {etat}| {str(note)[:100]}", flush=True)
    return valides, durees


def main():
    parser = argparse.ArgumentParser(description="Banc d'essai du moteur IA")
    parser.add_argument("--moteur", choices=llm.MOTEURS, default="ollama")
    parser.add_argument("--n", type=int, default=3, help="nombre d'essais par type de prompt")
    args = parser.parse_args()

    db.init_db()
    llm.moteur_choisi = lambda: args.moteur  # n'affecte que ce processus
    r = llm._reglages()
    print(f"Moteur : {r['fournisseur']} · modèle : {r['modele']}")
    debut_iso = maintenant_utc()
    if args.moteur == "ollama":
        t = time.monotonic()
        try:
            llm.demander_json("Tu réponds uniquement en JSON.", '{"ok": true}', "banc chauffe")
        except llm.LLMErreur as e:
            print("  Le moteur ne répond pas :", e)
            return
        print(f"  Chauffe (chargement du modèle) : {time.monotonic() - t:.1f} s")

    resultats = {}
    for nom, essai in (("diagnostic", _essai_diagnostic), ("correction", _essai_correction)):
        resultats[nom] = _mesurer(nom, essai, args.n)
    print("Résumé :")
    for nom, (valides, durees) in resultats.items():
        print(f"  {nom:<11} {valides}/{args.n} valides · durée médiane {statistics.median(durees):.1f} s")
    with db.connexion() as c:
        n, t = c.execute("SELECT COUNT(*), COALESCE(SUM(tokens), 0) FROM appels_ia WHERE horodatage >= ? "
                         "AND objet LIKE 'banc%' AND succes = 1", (debut_iso,)).fetchone()
    print(f"  Tokens : {t} sur {n} appels réussis")


if __name__ == "__main__":
    main()
