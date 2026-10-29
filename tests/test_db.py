import tempfile
import unittest
from pathlib import Path

from aiops import db

EMPREINTE = "up:10.10.0.20:9100"


class TestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        db.DB_PATH = Path(self.tmp.name) / "test.db"
        db.init_db()

    def tearDown(self):
        self.tmp.cleanup()

    def _incident(self):
        return db.creer_incident("Node Exporter arrêté", "runner-devops", "up", "haute", EMPREINTE)

    def test_creation_et_deduplication(self):
        incident_id = self._incident()
        self.assertEqual(db.incident_actif_par_empreinte(EMPREINTE)["id"], incident_id)
        self.assertIsNone(db.incident_actif_par_empreinte("autre"))

    def test_chronologie(self):
        incident_id = self._incident()
        db.changer_statut(incident_id, "diagnostic", "Diagnostic en cours", "diagnostic")
        self.assertEqual(len(db.get_incident(incident_id)["evenements"]), 2)

    def test_suppression_protegee(self):
        incident_id = self._incident()
        self.assertFalse(db.supprimer_incident(incident_id))
        db.changer_statut(incident_id, "resolu", "Service rétabli", "resolu")
        self.assertTrue(db.supprimer_incident(incident_id))
        self.assertIsNone(db.get_incident(incident_id))

    def test_quota_survit_a_la_suppression(self):
        incident_id = self._incident()
        db.enregistrer_appel_ia("groq", "modele-test", incident_id, True)
        db.changer_statut(incident_id, "resolu", "ok", "resolu")
        self.assertEqual(db.supprimer_historique(), 1)
        self.assertEqual(db.nombre_appels_ia_aujourdhui(), 1)


if __name__ == "__main__":
    unittest.main()
