import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from aiops import config, db, scenarios


class TestScenarios(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        db.DB_PATH = Path(self.tmp.name) / "t.db"
        db.init_db()

    def test_catalogue(self):
        self.assertEqual(set(scenarios.SCENARIOS), {"noeud", "service", "disque", "cpu", "reseau", "ssh"})
        for sc in scenarios.SCENARIOS.values():
            self.assertTrue(sc.injection and sc.nettoyage, sc.nom)
            self.assertIn(sc.machine, config.ADRESSES)

    def test_reconnaissance_de_l_incident_attendu(self):
        sc = scenarios.SCENARIOS["disque"]
        db.creer_incident("Disque /", "runner-devops", "disque", "moyenne", "disque:10.10.0.20:9100:/")
        voulu = db.creer_incident("Disque démo", "runner-devops", "disque", "moyenne",
                                  "disque:10.10.0.20:9100:/srv/demo-disque")
        t0 = datetime.now(timezone.utc) - timedelta(seconds=5)
        self.assertEqual(scenarios._trouver(sc, t0), voulu)

    def test_preparation(self):
        sc = scenarios.SCENARIOS["service"]
        empreinte = "service:10.10.0.20:9100:nginx.service"
        ancien = db.creer_incident("Service nginx", "runner-devops", "service", "haute", empreinte)
        db.changer_statut(ancien, "echec_escalade", "Échec", "escalade")
        self.assertTrue(scenarios._preparer(sc))
        self.assertIsNone(db.get_incident(ancien))
        db.creer_incident("Service nginx", "runner-devops", "service", "haute", empreinte)
        self.assertFalse(scenarios._preparer(sc))


if __name__ == "__main__":
    unittest.main()
