import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from aiops import agent1, agent2, db, llm, orchestrateur
from aiops.detecteurs import Anomalie, Detecteur

ANOMALIE = Anomalie("up:10.10.0.20:9100", "runner-devops", "up", "haute",
                    "Cible de supervision injoignable sur runner-devops", "détail", 60)
OK = {"ok": True, "code": 0, "sortie": "ok", "injoignable": False}


class TestOrchestrateur(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        db.DB_PATH = Path(self.tmp.name) / "t.db"
        db.init_db()
        env = mock.patch.dict(os.environ, {"LLM_PROVIDER": "mock", "AGENT2_MAX_TENTATIVES": "3"})
        env.start()
        self.addCleanup(env.stop)
        self.anomalies = [ANOMALIE]
        detecteur = Detecteur(collecteur=lambda: self.anomalies, reglages={"intervalle": 30, "cooldown_s": 600})
        self.o = orchestrateur.Orchestrateur(detecteur)
        for cible, nom, kw in [(agent1.ssh, "executer", {"return_value": OK}),
                               (agent2.executeur, "verifier_syntaxe", {}),
                               (agent2.executeur, "executer", {"return_value": {"ok": True, "code": 0, "sortie": "ok"}}),
                               (agent2, "_verifier", {"return_value": (True, "la cible est up")})]:
            p = mock.patch.object(cible, nom, **kw)
            p.start()
            self.addCleanup(p.stop)

    def _incident(self):
        return db.lister_incidents()[0]

    def test_parcours_complet_automatique(self):
        self.o.cycle()
        self.assertEqual(db.lister_incidents(), [])
        self.o.cycle()
        incident = self._incident()
        self.assertEqual(incident["statut"], "attente_approbation")
        proposition_id = db.get_incident(incident["id"])["propositions"][0]["id"]
        agent2.approuver(proposition_id)
        self.o.cycle()
        self.assertEqual(db.get_incident(incident["id"])["statut"], "resolu")

    def test_disparition_pendant_l_attente(self):
        self.o.cycle()
        self.o.cycle()
        incident = self._incident()
        self.anomalies = []
        self.o.cycle()
        detail = db.get_incident(incident["id"])
        self.assertEqual(detail["statut"], "resolu")
        self.assertEqual(detail["propositions"][0]["statut"], "annulee")

    def test_pause_si_quota(self):
        with mock.patch.object(agent1.llm, "demander_json", side_effect=llm.QuotaDepasse("limite")) as appel:
            self.o.cycle()
            self.o.cycle()
            self.o.cycle()
        self.assertEqual(appel.call_count, 1)
        self.assertEqual(self._incident()["statut"], "ouvert")

    def test_reprise_apres_arret_brutal(self):
        iid = db.creer_incident("Test", "runner-devops", "up", "haute", "up:10.10.0.10:9100")
        db.changer_statut(iid, "diagnostique")
        pid = db.creer_proposition(iid, 1, "runner-devops", "script", "#!/bin/bash\n", False, "j", "faible")
        db.mettre_a_jour_incident(iid, tentatives=1)
        db.decider_proposition(pid, "approuvee")
        db.demarrer_execution(pid)
        db.changer_statut(iid, "execution")
        self.o.reprise()
        self.assertEqual(db.get_incident(iid)["statut"], "nouvelle_tentative")
        self.assertEqual(db.get_proposition(pid)["statut"], "echec")


if __name__ == "__main__":
    unittest.main()
