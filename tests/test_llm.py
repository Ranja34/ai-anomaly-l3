import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from aiops import db, llm


class Rep:
    def __init__(self, code=200, contenu='{"ok": true}', fin="stop"):
        self.status_code = code
        self.text = contenu
        self._contenu = contenu
        self._fin = fin

    def json(self):
        return {"choices": [{"message": {"content": self._contenu}, "finish_reason": self._fin}]}


class TestLLM(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        db.DB_PATH = Path(self.tmp.name) / "t.db"
        db.init_db()
        self.env = mock.patch.dict(os.environ, {
            "LLM_PROVIDER": "groq", "GROQ_API_KEY": "cle-de-test",
            "LLM_INTERVALLE_MIN_S": "0", "LLM_MAX_APPELS_JOUR": "3", "LLM_TENTATIVES": "2"})
        self.env.start()
        self.sleep = mock.patch("aiops.llm.time.sleep")
        self.sleep.start()

    def tearDown(self):
        self.sleep.stop()
        self.env.stop()
        self.tmp.cleanup()

    def test_extraire_json(self):
        self.assertEqual(llm.extraire_json('```json\n{"a": 1}\n```'), {"a": 1})
        self.assertEqual(llm.extraire_json('Voici : {"a": 1} merci'), {"a": 1})
        with self.assertRaises(llm.LLMErreur):
            llm.extraire_json('{"a": 1, "b": ')

    def test_mock_ne_consomme_rien(self):
        with mock.patch.dict(os.environ, {"LLM_PROVIDER": "mock"}), \
             mock.patch.object(llm.requests, "post", side_effect=AssertionError("appel réseau interdit")):
            self.assertEqual(llm.demander_json("s", "u", reponse_mock={"x": 1}), {"x": 1})
        self.assertEqual(db.nombre_appels_ia_aujourdhui(), 0)

    def test_succes_compte_un_appel(self):
        with mock.patch.object(llm.requests, "post", return_value=Rep()):
            self.assertEqual(llm.demander_json("s", "u"), {"ok": True})
        self.assertEqual(db.nombre_appels_ia_aujourdhui(), 1)

    def test_reessai_apres_erreur_500(self):
        with mock.patch.object(llm.requests, "post", side_effect=[Rep(500, "erreur"), Rep()]) as post:
            self.assertEqual(llm.demander_json("s", "u"), {"ok": True})
        self.assertEqual(post.call_count, 2)
        self.assertEqual(db.nombre_appels_ia_aujourdhui(), 2)

    def test_429_arrete_immediatement(self):
        with mock.patch.object(llm.requests, "post", return_value=Rep(429, "limite")) as post:
            with self.assertRaises(llm.QuotaDepasse):
                llm.demander_json("s", "u")
        self.assertEqual(post.call_count, 1)

    def test_quota_local_bloque_avant_tout_appel(self):
        for _ in range(3):
            db.enregistrer_appel_ia("groq", "m", "x", True)
        with mock.patch.object(llm.requests, "post", side_effect=AssertionError("interdit")):
            with self.assertRaises(llm.QuotaDepasse):
                llm.demander_json("s", "u")

    def test_reponse_tronquee_sans_reessai(self):
        with mock.patch.object(llm.requests, "post", return_value=Rep(fin="length")) as post:
            with self.assertRaises(llm.LLMErreur):
                llm.demander_json("s", "u")
        self.assertEqual(post.call_count, 1)


if __name__ == "__main__":
    unittest.main()
