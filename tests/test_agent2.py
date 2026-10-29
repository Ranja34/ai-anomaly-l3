import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from aiops import agent2, db


class TestAgent2(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        db.DB_PATH = Path(self.tmp.name) / "t.db"
        db.init_db()
        self.id = db.creer_incident("Cible injoignable", "runner-devops", "up", "haute", "up:10.10.0.20:9100")
        db.changer_statut(self.id, "diagnostique")
        env = mock.patch.dict(os.environ, {"LLM_PROVIDER": "mock", "AGENT2_MAX_TENTATIVES": "3"})
        env.start()
        self.addCleanup(env.stop)
        for cible, kw in [("verifier_syntaxe", {}),
                          ("executer", {"return_value": {"ok": True, "code": 0, "sortie": "ok"}})]:
            p = mock.patch.object(agent2.executeur, cible, **kw)
            p.start()
            self.addCleanup(p.stop)
        self.addCleanup(self.tmp.cleanup)

    def _statut(self):
        return db.get_incident(self.id)["statut"]

    def test_proposition_en_attente(self):
        pid = agent2.proposer(self.id)
        prop = db.get_proposition(pid)
        self.assertEqual((prop["statut"], prop["type"], prop["sudo_requis"]), ("en_attente", "playbook", 1))
        self.assertEqual(self._statut(), "attente_approbation")
        self.assertEqual(db.get_incident(self.id)["tentatives"], 1)

    def test_succes(self):
        pid = agent2.proposer(self.id)
        with mock.patch.object(agent2, "_verifier", return_value=(True, "la cible est up")):
            self.assertEqual(agent2.approuver_et_executer(pid), "resolu")
        self.assertEqual(self._statut(), "resolu")

    def test_echec_puis_escalade_apres_3_tentatives(self):
        with mock.patch.object(agent2, "_verifier", return_value=(False, "toujours injoignable")):
            for attendu in ("nouvelle_tentative", "nouvelle_tentative", "echec_escalade"):
                pid = agent2.proposer(self.id)
                self.assertEqual(agent2.approuver_et_executer(pid), attendu)
        self.assertEqual(self._statut(), "echec_escalade")

    def test_refus(self):
        pid = agent2.proposer(self.id)
        agent2.refuser(pid)
        self.assertEqual(self._statut(), "refuse")
        self.assertEqual(db.get_proposition(pid)["statut"], "refusee")

    def test_double_approbation_impossible(self):
        pid = agent2.proposer(self.id)
        with mock.patch.object(agent2, "_verifier", return_value=(True, "ok")):
            agent2.approuver_et_executer(pid)
            with self.assertRaises(ValueError):
                agent2.approuver_et_executer(pid)

    def test_correction_dangereuse_rejetee(self):
        dangereux = {"type": "script", "machine": "runner-devops", "sudo_requis": True,
                     "contenu": "#!/bin/bash\nrm -rf /var\n"}
        with mock.patch.object(agent2.llm, "demander_json", return_value=dangereux) as appel:
            self.assertIsNone(agent2.proposer(self.id))
        self.assertEqual(appel.call_count, 2)
        self.assertEqual(self._statut(), "echec_escalade")


if __name__ == "__main__":
    unittest.main()
