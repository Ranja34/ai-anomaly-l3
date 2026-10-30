import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from aiops import db, llm
from aiops.detecteurs import Anomalie, Detecteur

ANOMALIE = Anomalie("up:10.10.0.20:9100", "runner-devops", "up", "haute", "Cible injoignable", "détail", 60)


class TestEconomieIA(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        db.DB_PATH = Path(self.tmp.name) / "t.db"
        db.init_db()

    def test_limite_horaire(self):
        env = {"LLM_PROVIDER": "groq", "GROQ_API_KEY": "x", "LLM_MAX_APPELS_HEURE": "2", "LLM_INTERVALLE_MIN_S": "0"}
        with mock.patch.dict(os.environ, env):
            for _ in range(2):
                db.enregistrer_appel_ia("groq", "m", "x", True)
            with mock.patch.object(llm.requests, "post", side_effect=AssertionError("appel interdit")):
                with self.assertRaises(llm.QuotaDepasse):
                    llm.demander_json("s", "u")

    def test_pause_longue_apres_escalade(self):
        detecteur = Detecteur(collecteur=lambda: [ANOMALIE],
                              reglages={"intervalle": 30, "cooldown_s": 0, "cooldown_escalade_s": 3600})
        detecteur.cycle()
        incident_id = detecteur.cycle()[0]
        db.changer_statut(incident_id, "echec_escalade", "Échec", "escalade")
        self.assertEqual(detecteur.cycle(), [])
        self.assertEqual(len(db.lister_incidents()), 1)


if __name__ == "__main__":
    unittest.main()
