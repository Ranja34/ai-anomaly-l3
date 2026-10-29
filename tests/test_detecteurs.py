import tempfile
import unittest
from pathlib import Path

from aiops import db
from aiops.detecteurs import Anomalie, Detecteur

ANOMALIE = Anomalie("up:10.10.0.20:9100", "runner-devops", "up", "haute",
                    "Cible de supervision injoignable sur runner-devops", "détail", 60)


class TestDetecteur(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        db.DB_PATH = Path(self.tmp.name) / "t.db"
        db.init_db()
        self.etat = {"anomalies": [ANOMALIE]}
        self.detecteur = Detecteur(collecteur=lambda: self.etat["anomalies"],
                                   reglages={"intervalle": 30, "cooldown_s": 600})

    def tearDown(self):
        self.tmp.cleanup()

    def test_confirmation_puis_pas_de_doublon(self):
        self.assertEqual(self.detecteur.cycle(), [])
        self.assertEqual(len(self.detecteur.cycle()), 1)
        self.assertEqual(self.detecteur.cycle(), [])
        self.assertEqual(len(db.lister_incidents()), 1)

    def test_anomalie_breve_ignoree(self):
        self.detecteur.cycle()
        self.etat["anomalies"] = []
        self.detecteur.cycle()
        self.etat["anomalies"] = [ANOMALIE]
        self.assertEqual(self.detecteur.cycle(), [])
        self.assertEqual(db.lister_incidents(), [])

    def test_retablissement_spontane(self):
        self.detecteur.cycle()
        incident_id = self.detecteur.cycle()[0]
        self.etat["anomalies"] = []
        self.detecteur.cycle()
        self.assertEqual(db.get_incident(incident_id)["statut"], "resolu")

    def test_pause_apres_refus(self):
        self.detecteur.cycle()
        incident_id = self.detecteur.cycle()[0]
        db.changer_statut(incident_id, "refuse", "Refusé par l'administrateur", "decision")
        self.assertEqual(self.detecteur.cycle(), [])
        self.assertEqual(len(db.lister_incidents()), 1)


if __name__ == "__main__":
    unittest.main()
