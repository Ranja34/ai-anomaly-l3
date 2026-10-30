import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from aiops import agent1, agent2, db, llm

OK = {"ok": True, "code": 0, "sortie": "ok", "injoignable": False}


class Rep400:
    status_code = 400

    def __init__(self, generation):
        self._corps = {"error": {"message": "Tool choice is none, but model called a tool",
                                 "type": "invalid_request_error", "code": "tool_use_failed",
                                 "failed_generation": generation}}
        self.text = json.dumps(self._corps)

    def json(self):
        return self._corps


class Rep200:
    status_code = 200
    text = ""

    def json(self):
        return {"choices": [{"message": {"content": '{"ok": true}'}, "finish_reason": "stop"}]}


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        db.DB_PATH = Path(self.tmp.name) / "t.db"
        db.init_db()
        env = mock.patch.dict(os.environ, {
            "LLM_PROVIDER": "groq", "GROQ_API_KEY": "cle-de-test", "LLM_INTERVALLE_MIN_S": "0",
            "LLM_TENTATIVES": "2", "LLM_MAX_APPELS_JOUR": "100", "LLM_MAX_APPELS_HEURE": "100"})
        env.start()
        self.addCleanup(env.stop)
        sleep = mock.patch("aiops.llm.time.sleep")
        sleep.start()
        self.addCleanup(sleep.stop)


class TestAppelOutil(Base):
    def test_recuperation_de_la_reponse(self):
        generation = json.dumps({"name": "assistant", "arguments": {"action": "conclure", "resume": "ok"}})
        with mock.patch.object(llm.requests, "post", return_value=Rep400(generation)) as post:
            self.assertEqual(llm.demander_json("s", "u"), {"action": "conclure", "resume": "ok"})
        self.assertEqual(post.call_count, 1)

    def test_nouvel_essai_si_irrecuperable(self):
        with mock.patch.object(llm.requests, "post", side_effect=[Rep400("n'importe quoi"), Rep200()]) as post:
            self.assertEqual(llm.demander_json("s", "u"), {"ok": True})
        self.assertEqual(post.call_count, 2)

    def test_la_consigne_est_envoyee(self):
        with mock.patch.object(llm.requests, "post", return_value=Rep200()) as post:
            llm.demander_json("système", "u")
        self.assertIn("N'appelle aucun outil", post.call_args.kwargs["json"]["messages"][0]["content"])


class TestErreursIA(Base):
    def setUp(self):
        super().setUp()
        self.id = db.creer_incident("Cible injoignable", "runner-devops", "up", "haute", "up:10.10.0.20:9100")

    def test_agent1_deux_echecs_puis_escalade(self):
        with mock.patch.object(agent1.ssh, "executer", return_value=OK), \
             mock.patch.object(agent1.llm, "demander_json", side_effect=llm.LLMErreur("panne")):
            self.assertIsNone(agent1.diagnostiquer(self.id))
            self.assertEqual(db.get_incident(self.id)["statut"], "ouvert")
            self.assertIsNone(agent1.diagnostiquer(self.id))
        self.assertEqual(db.get_incident(self.id)["statut"], "echec_escalade")

    def test_agent2_deux_echecs_puis_escalade(self):
        db.changer_statut(self.id, "diagnostique")
        with mock.patch.object(agent2.executeur, "verifier_syntaxe"), \
             mock.patch.object(agent2.llm, "demander_json", side_effect=llm.LLMErreur("panne")):
            self.assertIsNone(agent2.proposer(self.id))
            self.assertEqual(db.get_incident(self.id)["statut"], "diagnostique")
            self.assertIsNone(agent2.proposer(self.id))
        self.assertEqual(db.get_incident(self.id)["statut"], "echec_escalade")


if __name__ == "__main__":
    unittest.main()
