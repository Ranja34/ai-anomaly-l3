import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from aiops import db, llm, web


class Rep200:
    status_code = 200
    text = ""
    headers = {}

    def json(self):
        return {"choices": [{"message": {"content": '{"ok": true}'}, "finish_reason": "stop"}]}


class TestMoteur(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        db.DB_PATH = Path(self.tmp.name) / "t.db"
        db.init_db()

    def test_le_choix_de_l_interface_prime_sur_l_env(self):
        with mock.patch.dict(os.environ, {"LLM_PROVIDER": "groq"}):
            self.assertEqual(llm.moteur_choisi(), "groq")
            db.set_etat("moteur_ia", "ollama")
            self.assertEqual(llm.moteur_choisi(), "ollama")
            db.set_etat("moteur_ia", "n'importe quoi")
            self.assertEqual(llm.moteur_choisi(), "groq")

    def test_reglages_ollama(self):
        env = {"LLM_PROVIDER": "groq", "OLLAMA_MODEL": "qwen2.5:3b", "OLLAMA_URL": "http://10.10.0.50:11434/v1/"}
        with mock.patch.dict(os.environ, env):
            db.set_etat("moteur_ia", "ollama")
            r = llm._reglages()
        self.assertEqual((r["fournisseur"], r["modele"], r["cle"]), ("ollama", "qwen2.5:3b", ""))
        self.assertEqual(r["url"], "http://10.10.0.50:11434/v1")
        self.assertEqual(r["intervalle_min"], 0.0)
        self.assertTrue(r["mode_json"])
        self.assertGreater(r["max_appels_jour"], 10 ** 6)

    def test_ollama_sans_cle_ni_quota(self):
        env = {"LLM_PROVIDER": "groq", "GROQ_API_KEY": "cle-groq", "LLM_MAX_APPELS_JOUR": "5"}
        with mock.patch.dict(os.environ, env), mock.patch("aiops.llm.time.sleep"):
            db.set_etat("moteur_ia", "ollama")
            for _ in range(500):
                db.enregistrer_appel_ia("ollama", "m", "x", True)
            with mock.patch.object(llm.requests, "post", return_value=Rep200()) as post:
                self.assertEqual(llm.demander_json("s", "u"), {"ok": True})
        self.assertTrue(post.call_args.args[0].endswith("/chat/completions"))
        self.assertNotIn("Authorization", post.call_args.kwargs["headers"])
        corps = post.call_args.kwargs["json"]
        self.assertEqual(corps["response_format"], {"type": "json_object"})
        self.assertNotIn("reasoning_effort", corps)


class TestMoteurWeb(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        db.DB_PATH = Path(self.tmp.name) / "t.db"
        db.init_db()
        self.c = web.app.test_client()

    def test_changer_de_moteur(self):
        r = self.c.post("/api/moteur", json={"moteur": "ollama"})
        self.assertEqual(r.status_code, 200)
        etat = self.c.get("/api/etat").get_json()
        self.assertEqual(etat["moteur"], "ollama")
        self.assertIsNone(etat["max_jour"])
        self.assertEqual(self.c.post("/api/moteur", json={"moteur": "inconnu"}).status_code, 400)

    def test_tester_le_moteur_en_simulation(self):
        self.c.post("/api/moteur", json={"moteur": "mock"})
        r = self.c.post("/api/moteur/tester", json={})
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.get_json()["ok"])


if __name__ == "__main__":
    unittest.main()
