import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from aiops import agent1, db, llm

OK = {"ok": True, "code": 0, "sortie": "ok", "injoignable": False}
CONCLUSION = {"action": "conclure", "resume": "Résumé", "gravite": "faible", "cause_probable": "Cause",
              "machine": "runner-devops"}


class Rep429:
    status_code = 429

    def __init__(self, retry_after=None, message="Rate limit reached: please try again in 3s"):
        self.headers = {"retry-after": retry_after} if retry_after else {}
        self.text = message
        self._corps = {"error": {"message": message, "code": "rate_limit_exceeded"}}

    def json(self):
        return self._corps


class Rep200:
    status_code = 200
    text = ""
    headers = {"x-ratelimit-remaining-tokens": "5000", "content-type": "application/json"}

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
        patcher = mock.patch("aiops.llm.time.sleep")
        self.sleep = patcher.start()
        self.addCleanup(patcher.stop)


class TestLimites429(Base):
    def test_attente_conseillee_puis_succes(self):
        with mock.patch.object(llm.requests, "post", side_effect=[Rep429("3"), Rep200()]) as post:
            self.assertEqual(llm.demander_json("s", "u"), {"ok": True})
        self.assertEqual(post.call_count, 2)
        self.sleep.assert_any_call(4.0)

    def test_attente_trop_longue_abandonne(self):
        with mock.patch.object(llm.requests, "post", return_value=Rep429("300")) as post:
            with self.assertRaises(llm.QuotaDepasse) as ctx:
                llm.demander_json("s", "u")
        self.assertEqual(post.call_count, 1)
        self.assertIn("Rate limit", str(ctx.exception))

    def test_sans_delai_indique_abandonne(self):
        with mock.patch.object(llm.requests, "post", return_value=Rep429()) as post:
            with self.assertRaises(llm.QuotaDepasse):
                llm.demander_json("s", "u")
        self.assertEqual(post.call_count, 1)

    def test_limites_memorisees(self):
        with mock.patch.object(llm.requests, "post", return_value=Rep200()):
            llm.demander_json("s", "u")
        self.assertIn("x-ratelimit-remaining-tokens", db.get_etat("limites_ia")["valeur"])


class TestSudoNormalise(Base):
    def test_sudo_en_debut_de_commande_active_l_option(self):
        db.creer_incident("Test", "runner-devops", "securite", "haute", "securite:ssh:runner-devops")
        inc = db.get_incident(db.lister_incidents()[0]["id"])
        tours = [{"action": "commandes", "raison": "x",
                  "commandes": [{"machine": "runner-devops", "commande": "sudo ufw status", "sudo": False}]},
                 CONCLUSION]
        with mock.patch.object(agent1.ssh, "executer", return_value=OK) as ssh_mock, \
             mock.patch.object(agent1.llm, "demander_json", side_effect=tours):
            agent1._boucle_ia(inc, [])
        self.assertEqual(ssh_mock.call_args_list[0].args, ("runner-devops", "ufw status", True))


if __name__ == "__main__":
    unittest.main()
