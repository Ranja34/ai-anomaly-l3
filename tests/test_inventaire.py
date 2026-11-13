import tempfile
import unittest
from pathlib import Path
from unittest import mock

from aiops import agent1, agent2, config, db, orchestrateur, web
from aiops.detecteurs import Detecteur

SRV = {"nom": "srv-test", "ip": "192.0.2.50", "os": "windows", "ssh": False, "mode": "observation",
       "port_metriques": 9182}


class TestChargement(unittest.TestCase):
    def _charger(self, texte):
        with tempfile.TemporaryDirectory() as d:
            fichier = Path(d) / "inv.yml"
            fichier.write_text(texte, encoding="utf-8")
            with mock.patch.object(config, "INVENTAIRE_FICHIER", fichier):
                return config._charger_inventaire()

    def test_sans_fichier_on_retrouve_le_laboratoire(self):
        with mock.patch.object(config, "INVENTAIRE_FICHIER", Path("/nonexistent/inv.yml")):
            inv = config._charger_inventaire()
        self.assertEqual(sorted(inv), ["frappe-staging", "runner-devops"])
        self.assertEqual((inv["runner-devops"]["mode"], inv["runner-devops"]["ssh"]), ("approbation", True))

    def test_valeurs_par_defaut_selon_le_systeme(self):
        inv = self._charger("machines:\n  - nom: a\n    ip: 10.0.0.1\n"
                            "  - nom: w\n    ip: 10.0.0.2\n    os: windows\n    mode: observation\n")
        self.assertEqual((inv["a"]["ssh"], inv["a"]["port_metriques"]), (True, 9100))
        self.assertEqual((inv["w"]["ssh"], inv["w"]["port_metriques"], inv["w"]["mode"]), (False, 9182, "observation"))

    def test_inventaire_invalide(self):
        for texte in ["machines:\n  - nom: a\n    ip: 1.1.1.1\n    os: macos\n",
                      "machines:\n  - nom: a\n    ip: 1.1.1.1\n    mode: auto\n",
                      "machines:\n  - nom: a\n    ip: 1.1.1.1\n  - nom: a\n    ip: 1.1.1.2\n",
                      "machines:\n  - nom: a\n", "machines: []\n"]:
            with self.assertRaises(ValueError, msg=texte):
                self._charger(texte)

    def test_aides(self):
        with mock.patch.dict(config.INVENTAIRE, {"srv-test": SRV}):
            self.assertEqual(config.mode_de("srv-test"), "observation")
            self.assertFalse(config.ssh_actif("srv-test"))
            self.assertNotIn("srv-test", config.machines_actionnables())
            self.assertNotIn("srv-test", config.machines_ssh())
        self.assertTrue(config.ssh_actif("machine-inconnue"))


class TestObservation(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        db.DB_PATH = Path(self.tmp.name) / "t.db"
        db.init_db()
        for p in (mock.patch.dict(config.INVENTAIRE, {"srv-test": SRV}),
                  mock.patch.dict(config.ADRESSES, {"srv-test": "192.0.2.50"}),
                  mock.patch.dict("os.environ", {"LLM_PROVIDER": "mock"})):
            p.start()
            self.addCleanup(p.stop)
        self.iid = db.creer_incident("Machine injoignable", "srv-test", "sonde", "haute", "sonde:srv-test:toutes")

    def test_l_agent_2_refuse_une_machine_en_observation(self):
        db.changer_statut(self.iid, "diagnostique")
        with self.assertRaises(ValueError):
            agent2.proposer(self.iid)

    def test_l_orchestrateur_ne_demande_aucune_correction(self):
        db.changer_statut(self.iid, "diagnostique")
        o = orchestrateur.Orchestrateur(Detecteur(collecteur=lambda: [], reglages={"intervalle": 10}))
        with mock.patch.object(agent2, "proposer", side_effect=AssertionError("interdit")):
            o._traiter_ia()
        self.assertEqual(db.get_incident(self.iid)["statut"], "diagnostique")

    def test_diagnostic_sans_ssh_utilise_les_sondes(self):
        with mock.patch.object(agent1.ssh, "executer", side_effect=AssertionError("pas de SSH")), \
             mock.patch("aiops.sondes.charger", return_value=[]), \
             mock.patch("aiops.detecteurs._sonde_ping", return_value=(100.0, None)):
            diag = agent1.diagnostiquer(self.iid)
        incident = db.get_incident(self.iid)
        self.assertIsNotNone(diag)
        self.assertEqual(incident["statut"], "diagnostique")
        self.assertIn("Pas d'accès SSH", str(incident["evenements"]))

    def test_l_ia_ne_peut_pas_cibler_une_machine_en_observation(self):
        rep = {"type": "script", "contenu": "#!/bin/bash\n", "machine": "srv-test"}
        self.assertEqual(agent2._normaliser(rep, {"machine": "runner-devops"})["machine"], "runner-devops")

    def test_libelle_dans_l_interface(self):
        db.changer_statut(self.iid, "diagnostique")
        liste = web.app.test_client().get("/api/incidents").get_json()
        self.assertIn("observation", liste[0]["statut_libelle"])


if __name__ == "__main__":
    unittest.main()
