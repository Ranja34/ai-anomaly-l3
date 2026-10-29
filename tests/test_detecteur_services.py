import unittest
from unittest import mock

from aiops import detecteurs

SERIE = [{"metric": {"instance": "10.10.0.20:9100", "name": "nginx.service"}, "value": [0, "1"]}]


def fausse_requete(requete):
    return SERIE if "node_systemd_unit_state" in requete else []


class TestDetecteurServices(unittest.TestCase):
    def test_service_en_echec_detecte(self):
        with mock.patch.object(detecteurs, "_requete", side_effect=fausse_requete):
            anomalies = detecteurs.collecter_anomalies()
        self.assertEqual(len(anomalies), 1)
        a = anomalies[0]
        self.assertEqual((a.source, a.machine), ("service", "runner-devops"))
        self.assertEqual(a.empreinte, "service:10.10.0.20:9100:nginx.service")

    def test_service_ignore(self):
        r = {**detecteurs._reglages(), "services_ignores": {"nginx.service"}}
        with mock.patch.object(detecteurs, "_requete", side_effect=fausse_requete):
            self.assertEqual(detecteurs.collecter_anomalies(r), [])


if __name__ == "__main__":
    unittest.main()
