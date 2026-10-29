"""Orchestrateur : service permanent qui détecte, diagnostique, propose, exécute les corrections approuvées et vérifie."""
import os
import signal
import time
import traceback

import requests

from aiops import agent1, agent2, db, detecteurs, llm
from aiops.temps import formater_local, maintenant_utc

STATUTS_A_SURVEILLER = ("diagnostique", "attente_approbation", "nouvelle_tentative")


def journal(message):
    print(f"[{formater_local(maintenant_utc(), avec_date=False)}] {message}", flush=True)


class Orchestrateur:
    def __init__(self, detecteur=None):
        self.detecteur = detecteur or detecteurs.Detecteur()
        self.pause_ia_s = int(os.getenv("IA_PAUSE_QUOTA_S", "600"))
        self.pause_ia_jusqua = 0.0
        self.erreurs = {}
        self.arret = False

    # ----- Reprise après un arrêt brutal ou un redémarrage -----
    def reprise(self):
        maxi = agent2._max_tentatives()
        for inc in db.lister_incidents(limite=500):
            statut, iid = inc["statut"], inc["id"]
            if statut == "diagnostic_en_cours":
                db.changer_statut(iid, "ouvert", "Reprise après redémarrage du service : diagnostic à refaire", "info")
            elif statut == "redaction_correction":
                retour = "nouvelle_tentative" if inc["tentatives"] else "diagnostique"
                db.changer_statut(iid, retour, "Reprise après redémarrage du service : rédaction à refaire", "info")
            elif statut in ("execution", "verification"):
                for p in db.propositions_par_statut("en_cours"):
                    if p["incident_id"] == iid:
                        db.mettre_a_jour_proposition(
                            p["id"], statut="echec", sortie="Exécution interrompue par un redémarrage du service")
                if inc["tentatives"] >= maxi:
                    db.changer_statut(iid, "echec_escalade",
                                      "Exécution interrompue par un redémarrage du service. "
                                      "Intervention humaine requise.", "escalade")
                else:
                    db.changer_statut(iid, "nouvelle_tentative",
                                      "Exécution interrompue par un redémarrage du service : nouvelle analyse", "info")

    # ----- Un passage complet -----
    def cycle(self):
        db.set_etat("battement", maintenant_utc())
        detection_ok = True
        try:
            for iid in self.detecteur.cycle():
                journal(f"Incident {iid} ouvert : {db.get_incident(iid)['titre']}")
            db.set_etat("prometheus", "ok")
        except (requests.RequestException, RuntimeError) as e:
            detection_ok = False
            db.set_etat("prometheus", "injoignable")
            journal(f"Prometheus injoignable ou réponse invalide : {e}")
        if detection_ok:
            self._cloturer_obsoletes()
        self._traiter()

    def _cloturer_obsoletes(self):
        """Un problème qui a disparu avant la fin du traitement est clos automatiquement."""
        presentes = self.detecteur.presentes
        if presentes is None:
            return
        for statut in STATUTS_A_SURVEILLER:
            for inc in db.lister_incidents(statut=statut):
                if inc["empreinte"] not in presentes:
                    db.annuler_propositions_en_attente(inc["id"])
                    db.changer_statut(inc["id"], "resolu",
                                      "Le problème a disparu avant la fin du traitement "
                                      "(rétablissement hors procédure)", "resolu")
                    journal(f"Incident {inc['id']} clos : le problème a disparu de lui-même")

    def _traiter(self):
        # 1. Exécuter les corrections approuvées (ne consomme aucun appel IA)
        for prop in db.propositions_par_statut("approuvee"):
            journal(f"Exécution de la correction {prop['id']} (incident {prop['incident_id']}) sur {prop['machine']}")
            resultat = self._securise(prop["incident_id"], lambda p=prop: agent2.executer_approuvee(p["id"]))
            if resultat:
                journal(f"Incident {prop['incident_id']} : {resultat}")

        # 2. Étapes qui utilisent l'IA (suspendues si le quota est atteint)
        if time.monotonic() < self.pause_ia_jusqua:
            return
        for inc in reversed(db.lister_incidents(statut="ouvert")):
            if not self._etape_ia(inc["id"], agent1.diagnostiquer, "Diagnostic"):
                return
        for statut in ("diagnostique", "nouvelle_tentative"):
            for inc in reversed(db.lister_incidents(statut=statut)):
                if not self._etape_ia(inc["id"], agent2.proposer, "Rédaction de la correction"):
                    return

    def _etape_ia(self, incident_id, fonction, nom):
        avant = db.get_incident(incident_id)["statut"]
        journal(f"{nom} : incident {incident_id}")
        self._securise(incident_id, lambda: fonction(incident_id))
        apres = db.get_incident(incident_id)["statut"]
        if apres == avant:  # l'IA n'a pas pu répondre : on suspend les appels
            self.pause_ia_jusqua = time.monotonic() + self.pause_ia_s
            journal(f"IA indisponible ou quota atteint : appels suspendus pendant {self.pause_ia_s // 60} min")
            return False
        journal(f"Incident {incident_id} : {avant} -> {apres}")
        return True

    def _securise(self, incident_id, fonction):
        try:
            return fonction()
        except Exception as e:  # une erreur sur un incident ne doit jamais arrêter le service
            n = self.erreurs[incident_id] = self.erreurs.get(incident_id, 0) + 1
            journal(f"Erreur interne sur l'incident {incident_id} ({n}/3) : {type(e).__name__}: {e}")
            traceback.print_exc()
            if n >= 3:
                db.changer_statut(incident_id, "echec_escalade",
                                  f"Erreur interne répétée ({type(e).__name__}). Intervention humaine requise.",
                                  "escalade")
            return None


def main():
    db.init_db()
    orchestrateur = Orchestrateur()
    for signal_arret in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signal_arret, lambda *_: setattr(orchestrateur, "arret", True))

    r = llm._reglages()
    journal(f"Orchestrateur démarré (moteur IA : {r['fournisseur']}, modèle : {r['modele']}, "
            f"quota : {r['max_appels_jour']} appels/jour)")
    orchestrateur.reprise()
    intervalle = orchestrateur.detecteur.r["intervalle"]
    while not orchestrateur.arret:
        debut = time.monotonic()
        try:
            orchestrateur.cycle()
        except Exception as e:
            journal(f"Erreur inattendue dans le cycle : {type(e).__name__}: {e}")
            traceback.print_exc()
        while not orchestrateur.arret and time.monotonic() - debut < intervalle:
            time.sleep(1)
    journal("Orchestrateur arrêté proprement")


if __name__ == "__main__":
    main()
