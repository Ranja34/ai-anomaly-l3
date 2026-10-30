import tempfile
import unittest
from pathlib import Path
from unittest import mock

from aiops import agent2, db
from aiops.detecteurs import Detecteur
from aiops.orchestrateur import Orchestrateur


class TestIncidentManuel(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        db.DB_PATH = Path(self.tmp.name) / "t.db"
        db.init_db()
        self.iid = db.creer_incident("Site HS", "runner-devops", "manuel", "haute", "manuel:abc12345")

    def test_jamais_clos_comme_disparu_par_le_detecteur(self):
        Detecteur(collecteur=lambda: [], reglages={"intervalle": 30}).cycle()
        self.assertEqual(db.get_incident(self.iid)["statut"], "ouvert")

    def test_jamais_clos_comme_disparu_par_l_orchestrateur(self):
        o = Orchestrateur(Detecteur(collecteur=lambda: [], reglages={"intervalle": 30}))
        o.detecteur.presentes = set()
        db.changer_statut(self.iid, "attente_approbation")
        o._cloturer_obsoletes()
        self.assertEqual(db.get_incident(self.iid)["statut"], "attente_approbation")

    def test_confirmation_manuelle_apres_execution(self):
        db.changer_statut(self.iid, "attente_approbation")
        pid = db.creer_proposition(self.iid, 1, "runner-devops", "script", "#!/bin/bash\n", False, "j", "faible")
        db.mettre_a_jour_incident(self.iid, tentatives=1)
        agent2.approuver(pid)
        with mock.patch.object(agent2.executeur, "executer", return_value={"ok": True, "code": 0, "sortie": "ok"}), \
             mock.patch.object(agent2, "_verifier", side_effect=AssertionError("pas de vérification automatique")):
            self.assertEqual(agent2.executer_approuvee(pid), "verification_manuelle")
        self.assertEqual(db.get_incident(self.iid)["statut"], "verification_manuelle")
        self.assertEqual(db.get_proposition(pid)["statut"], "executee")


if __name__ == "__main__":
    unittest.main()
