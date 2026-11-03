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
        return {"choices": [{"message": {"content": '{"ok": true}'}, "finish_reason": "stop"}]}


class TestQuotaParFournisseur(unittest.TestCase):
    ENV = {"LLM_PROVIDER": "groq", "GROQ_API_KEY": "x", "LLM_INTERVALLE_MIN_S": "0",
           "LLM_MAX_APPELS_HEURE": "2", "LLM_MAX_APPELS_JOUR": "2"}

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        db.DB_PATH = Path(self.tmp.name) / "t.db"
        db.init_db()

    def test_les_appels_ollama_ne_consomment_pas_le_quota_groq(self):
        with mock.patch.dict(os.environ, self.ENV), mock.patch("aiops.llm.time.sleep"):
            for _ in range(5):
                db.enregistrer_appel_ia("ollama", "m", "x", True)
            with mock.patch.object(llm.requests, "post", return_value=Rep200()):
                self.assertEqual(llm.demander_json("s", "u"), {"ok": True})

    def test_les_appels_groq_comptent_toujours(self):
        with mock.patch.dict(os.environ, self.ENV), mock.patch("aiops.llm.time.sleep"):
            for _ in range(2):
                db.enregistrer_appel_ia("groq", "m", "x", True)
            with mock.patch.object(llm.requests, "post", side_effect=AssertionError("appel interdit")):
                with self.assertRaises(llm.QuotaDepasse):
                    llm.demander_json("s", "u")


if __name__ == "__main__":
    unittest.main()
