import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from aiops import agent1, db, llm

OK = {"ok": True, "code": 0, "sortie": "inactive", "injoignable": False}
CONCLUSION = {"action": "conclure", "resume": "Résumé", "gravite": "faible", "cause_probable": "Cause",
              "confiance": "haute", "preuves": ["p"], "service_concerne": None, "machine": "runner-devops",
              "verification_recommandee": "v"}


class Base(unittest.TestCase):
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


class TestAgent1(Base):
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


class TestEnqueteLibre(Base):
    def test_enquete_libre_en_deux_tours_avec_sudo(self):
        tours = [{"action": "commandes", "raison": "chercher les tentatives",
                  "commandes": [{"machine": "runner-devops", "commande": "journalctl -u ssh -n 5 --no-pager",
                                 "sudo": True}]}, CONCLUSION]
        with mock.patch.object(agent1.ssh, "executer", return_value=OK) as ssh_mock, \
             mock.patch.object(agent1.llm, "demander_json", side_effect=tours) as ia:
            agent1.diagnostiquer(self.id)
        self.assertEqual(ia.call_count, 2)
        self.assertEqual(db.get_incident(self.id)["statut"], "diagnostique")
        lectures_sudo = [c for c in ssh_mock.call_args_list
                         if c.args[1].startswith("journalctl -u ssh") and c.args[2] is True]
        self.assertEqual(len(lectures_sudo), 1)

    def test_commande_dangereuse_de_l_ia_jamais_executee(self):
        tours = [{"action": "commandes", "raison": "x",
                  "commandes": [{"machine": "runner-devops", "commande": "rm -rf /tmp/x", "sudo": False}]},
                 CONCLUSION]
        faux = SimpleNamespace(returncode=0, stdout="ok", stderr="")
        with mock.patch.object(agent1.ssh.subprocess, "run", return_value=faux) as run, \
             mock.patch.object(agent1.llm, "demander_json", side_effect=tours):
            agent1.diagnostiquer(self.id)
        self.assertEqual(run.call_count, 7)  # les 7 commandes standard d'un incident « up », rien d'autre
        self.assertIn("REFUSÉE", str(db.get_incident(self.id)["evenements"]))


if __name__ == "__main__":
    unittest.main()
