import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from aiops import agent1, db, llm

OK = {"ok": True, "code": 0, "sortie": "inactive", "injoignable": False}


class TestAgent1(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        db.DB_PATH = Path(self.tmp.name) / "t.db"
        db.init_db()
        self.id = db.creer_incident("Cible injoignable", "runner-devops", "up", "haute", "up:10.10.0.20:9100")
        self.env = mock.patch.dict(os.environ, {"LLM_PROVIDER": "mock"})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()

    def test_diagnostic_en_mode_mock(self):
        with mock.patch.object(agent1.ssh, "executer", return_value=OK):
            diag = agent1.diagnostiquer(self.id)
        inc = db.get_incident(self.id)
        self.assertEqual(inc["statut"], "diagnostique")
        self.assertTrue(inc["resume"])
        self.assertEqual(diag["service_concerne"], "prometheus-node-exporter")
        types = [e["type"] for e in inc["evenements"]]
        self.assertIn("enquete", types)
        self.assertIn("diagnostic", types)

    def test_machine_injoignable_arrete_les_commandes(self):
        panne = {"ok": False, "code": 255, "sortie": "timeout", "injoignable": True}
        with mock.patch.object(agent1.ssh, "executer", return_value=panne) as m:
            agent1.diagnostiquer(self.id)
        self.assertEqual(m.call_count, 1)

    def test_commande_refusee_signalee(self):
        preuves = agent1._executer_liste([("runner-devops", "rm -rf /")])
        self.assertIn("REFUSÉE", preuves[0]["sortie"])

    def test_quota_laisse_incident_ouvert(self):
        with mock.patch.object(agent1.ssh, "executer", return_value=OK), \
             mock.patch.object(agent1.llm, "demander_json", side_effect=llm.QuotaDepasse("limite")):
            self.assertIsNone(agent1.diagnostiquer(self.id))
        self.assertEqual(db.get_incident(self.id)["statut"], "ouvert")


if __name__ == "__main__":
    unittest.main()
