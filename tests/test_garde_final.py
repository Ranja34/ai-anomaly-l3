import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from aiops import agent2, db
from aiops.detecteurs import Detecteur
from aiops.orchestrateur import Orchestrateur


class TestGardeFinal(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        db.DB_PATH = Path(self.tmp.name) / "t.db"
        db.init_db()
        self.iid = db.creer_incident("Cible injoignable", "runner-devops", "up", "haute", "up:10.10.0.20:9100")
        env = mock.patch.dict(os.environ, {"LLM_PROVIDER": "mock"})
        env.start()
        self.addCleanup(env.stop)

    def test_un_incident_termine_ne_peut_pas_etre_rouvert(self):
        db.changer_statut(self.iid, "resolu", "ok", "resolu")
        self.assertFalse(db.changer_statut(self.iid, "attente_approbation", "ne doit pas passer", "info"))
        incident = db.get_incident(self.iid)
        self.assertEqual(incident["statut"], "resolu")
        self.assertNotIn("ne doit pas passer", str(incident["evenements"]))
        self.assertTrue(db.changer_statut(self.iid, "ouvert", "relance", "info", forcer=True))

    def test_pas_de_correction_pour_un_incident_resolu_pendant_l_appel_ia(self):
        db.changer_statut(self.iid, "diagnostique")

        def appel_ia_pendant_lequel_le_probleme_disparait(*args, **kwargs):
            db.changer_statut(self.iid, "resolu", "disparu", "resolu")
            return agent2._mock(db.get_incident(self.iid))

        with mock.patch.object(agent2.executeur, "verifier_syntaxe"), \
             mock.patch.object(agent2.llm, "demander_json", side_effect=appel_ia_pendant_lequel_le_probleme_disparait):
            self.assertIsNone(agent2.proposer(self.iid))
        self.assertEqual(db.get_incident(self.iid)["propositions"], [])

    def test_la_detection_laisse_un_battement(self):
        o = Orchestrateur(Detecteur(collecteur=lambda: [], reglages={"intervalle": 10}))
        o.detecter()
        self.assertIsNotNone(db.get_etat("battement"))
        self.assertEqual(db.get_etat("prometheus")["valeur"], "ok")


if __name__ == "__main__":
    unittest.main()
