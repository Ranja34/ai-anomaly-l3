import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from aiops import db, llm


class Rep200:
    status_code = 200
    text = ""
    headers = {}

    def json(self):
        return {"choices": [{"message": {"content": '{"ok": true}'}, "finish_reason": "stop"}],
                "usage": {"total_tokens": 1234}}


class TestJetons(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        db.DB_PATH = Path(self.tmp.name) / "t.db"
        db.init_db()
        env = mock.patch.dict(os.environ, {
            "LLM_PROVIDER": "groq", "GROQ_API_KEY": "cle-de-test", "LLM_INTERVALLE_MIN_S": "0",
            "LLM_MAX_TOKENS": "2000", "LLM_MAX_APPELS_JOUR": "100", "LLM_MAX_APPELS_HEURE": "100"})
        env.start()
        self.addCleanup(env.stop)
        patcher = mock.patch("aiops.llm.time.sleep")
        self.sleep = patcher.start()
        self.addCleanup(patcher.stop)

    def _limites(self, reste):
        db.set_etat("limites_ia", json.dumps({"x-ratelimit-limit-tokens": "8000",
                                              "x-ratelimit-remaining-tokens": str(reste)}))

    def test_attente_si_peu_de_jetons_disponibles(self):
        self._limites(1000)
        with mock.patch.object(llm.requests, "post", return_value=Rep200()):
            llm.demander_json("s", "u")
        attentes = [c.args[0] for c in self.sleep.call_args_list]
        self.assertTrue(any(6 < a < 10 for a in attentes), attentes)

    def test_pas_d_attente_si_jetons_suffisants(self):
        self._limites(8000)
        with mock.patch.object(llm.requests, "post", return_value=Rep200()):
            llm.demander_json("s", "u")
        self.assertEqual(self.sleep.call_args_list, [])

    def test_tokens_enregistres(self):
        with mock.patch.object(llm.requests, "post", return_value=Rep200()):
            llm.demander_json("s", "u")
        self.assertEqual(db.tokens_ia_aujourdhui(), 1234)


if __name__ == "__main__":
    unittest.main()
