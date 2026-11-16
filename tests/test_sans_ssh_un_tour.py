import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from aiops import agent1, config, db

SRV = {"nom": "srv-test", "ip": "192.0.2.50", "os": "windows", "ssh": False, "mode": "observation",
       "port_metriques": 9182}


class TestUnSeulTour(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        db.DB_PATH = Path(self.tmp.name) / "t.db"
        db.init_db()
        for p in (mock.patch.dict(config.INVENTAIRE, {"srv-test": SRV}),
                  mock.patch.dict(config.ADRESSES, {"srv-test": "192.0.2.50"})):
            p.start()
            self.addCleanup(p.stop)
        self.iid = db.creer_incident("Machine injoignable", "srv-test", "sonde", "haute", "sonde:srv-test:toutes")

    def test_une_machine_sans_ssh_doit_conclure_des_le_premier_tour(self):
        conclusion = {"action": "conclure", "resume": "R", "gravite": "haute", "cause_probable": "C",
                      "machine": "srv-test"}
        with mock.patch("aiops.sondes.charger", return_value=[]), \
             mock.patch("aiops.detecteurs._sonde_ping", return_value=(100.0, None)), \
             mock.patch.object(agent1.llm, "demander_json", return_value=conclusion) as ia:
            agent1.diagnostiquer(self.iid)
        self.assertEqual(ia.call_count, 1)
        self.assertIn("conclure maintenant", json.loads(ia.call_args.args[1])["consigne"])


if __name__ == "__main__":
    unittest.main()
