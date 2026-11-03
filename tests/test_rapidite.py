import json
import os
import unittest
from unittest import mock

from aiops import agent1, banc_essai, detecteurs


class TestRapidite(unittest.TestCase):
    def test_compacter_garde_le_debut_et_la_fin(self):
        texte = "DEBUT" + "x" * 2000 + "FIN"
        court = agent1._compacter(texte, 600)
        self.assertLess(len(court), 620)
        self.assertTrue(court.startswith("DEBUT") and court.endswith("FIN"))

    def test_l_attaquant_reste_visible_apres_compactage(self):
        reduit = agent1._budget(banc_essai.PREUVES)
        self.assertIn("10.10.0.99", json.dumps(reduit))
        self.assertLess(sum(len(p["sortie"]) for p in reduit), 3600)

    def test_cible_injoignable_sur_deux_releves(self):
        requetes = []

        def fausse(requete):
            requetes.append(requete)
            if "max_over_time(up" in requete:
                return [{"metric": {"instance": "10.10.0.20:9100"}, "value": [0, "0"]}]
            return []

        with mock.patch.dict(os.environ, {"CONFIRM_UP_S": "10", "UP_FENETRE": "30s"}), \
             mock.patch.object(detecteurs, "_requete", side_effect=fausse), \
             mock.patch.object(detecteurs, "_sonde_ping", return_value=(0.0, 0.5)), \
             mock.patch.object(detecteurs, "_requete_loki", return_value=[]):
            anomalies = detecteurs.collecter_anomalies()
        self.assertTrue(any("[30s]" in q for q in requetes))
        self.assertEqual([(a.source, a.confirmation_s) for a in anomalies], [("up", 10)])


if __name__ == "__main__":
    unittest.main()
