import tempfile
import unittest
from pathlib import Path

from aiops import db, web


class TestWeb(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        db.DB_PATH = Path(self.tmp.name) / "t.db"
        db.init_db()
        self.c = web.app.test_client()

    def _incident(self, statut="ouvert", source="up"):
        iid = db.creer_incident("Cible injoignable", "runner-devops", source, "haute", f"{source}:x:{statut}")
        if statut != "ouvert":
            db.changer_statut(iid, statut)
        return iid

    def _proposition(self):
        iid = self._incident("attente_approbation")
        return iid, db.creer_proposition(iid, 1, "runner-devops", "script", "#!/bin/bash\n", False, "j", "faible")

    def test_etat_et_page(self):
        etat = self.c.get("/api/etat").get_json()
        self.assertFalse(etat["orchestrateur_ok"])
        self.assertIn("runner-devops", etat["machines"])
        self.assertEqual(self.c.get("/").status_code, 200)

    def test_signalement_et_liste(self):
        r = self.c.post("/api/incidents/signaler", json={
            "description": "Le site web ne répond plus", "machine": "runner-devops", "gravite": "haute"})
        self.assertEqual(r.status_code, 200)
        iid = r.get_json()["id"]
        self.assertEqual(self.c.get("/api/incidents").get_json()[0]["source"], "manuel")
        detail = self.c.get(f"/api/incidents/{iid}").get_json()
        self.assertIn("Le site web", detail["evenements"][-1]["message"])

    def test_signalement_invalide(self):
        self.assertEqual(self.c.post("/api/incidents/signaler", json={"description": "x", "machine": "runner-devops"}).status_code, 400)
        self.assertEqual(self.c.post("/api/incidents/signaler", json={"description": "problème réel", "machine": "inconnue"}).status_code, 400)

    def test_approuver_une_seule_fois(self):
        iid, pid = self._proposition()
        self.assertEqual(self.c.post(f"/api/propositions/{pid}/approuver").status_code, 200)
        self.assertEqual(db.get_incident(iid)["statut"], "approuve")
        self.assertEqual(self.c.post(f"/api/propositions/{pid}/approuver").status_code, 409)

    def test_refuser(self):
        iid, pid = self._proposition()
        self.assertEqual(self.c.post(f"/api/propositions/{pid}/refuser").status_code, 200)
        self.assertEqual(db.get_incident(iid)["statut"], "refuse")

    def test_detail_expose_la_proposition_en_attente(self):
        iid, pid = self._proposition()
        detail = self.c.get(f"/api/incidents/{iid}").get_json()
        self.assertEqual(detail["proposition_attente"]["id"], pid)
        self.assertTrue(detail["a_decision"])

    def test_suppression_protegee(self):
        iid = self._incident()
        self.assertEqual(self.c.delete(f"/api/incidents/{iid}").status_code, 409)
        db.changer_statut(iid, "resolu", "ok", "resolu")
        self.assertEqual(self.c.delete(f"/api/incidents/{iid}").status_code, 200)

    def test_vider_l_historique(self):
        for i in range(2):
            iid = db.creer_incident("T", "runner-devops", "up", "haute", f"up:{i}")
            db.changer_statut(iid, "resolu", "ok", "resolu")
        actif = self._incident()
        r = self.c.post("/api/historique/supprimer", json={"tout": True}).get_json()
        self.assertEqual(r["supprimes"], 2)
        self.assertEqual([i["id"] for i in self.c.get("/api/incidents").get_json()], [actif])

    def test_verification_manuelle(self):
        a = self._incident("verification_manuelle", "manuel")
        self.assertEqual(self.c.post(f"/api/incidents/{a}/confirmer").status_code, 200)
        self.assertEqual(db.get_incident(a)["statut"], "resolu")
        b = db.creer_incident("T2", "runner-devops", "manuel", "haute", "manuel:b")
        db.changer_statut(b, "verification_manuelle")
        self.assertEqual(self.c.post(f"/api/incidents/{b}/infirmer").status_code, 200)
        self.assertEqual(db.get_incident(b)["statut"], "nouvelle_tentative")

    def test_relancer(self):
        iid = self._incident("echec_escalade")
        self.assertEqual(self.c.post(f"/api/incidents/{iid}/relancer").status_code, 200)
        self.assertEqual(db.get_incident(iid)["statut"], "ouvert")


if __name__ == "__main__":
    unittest.main()
