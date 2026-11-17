import unittest
from unittest import mock

import requests

from aiops import agent1, config, detecteurs

INST = "192.0.2.50:9182"
SRV = {"nom": "srv-test", "ip": "192.0.2.50", "os": "windows", "ssh": False, "mode": "observation",
       "port_metriques": 9182, "services": ["spooler", "dnscache"]}


def serie(valeur, instance=INST, **etiquettes):
    return [{"metric": {"instance": instance, **etiquettes}, "value": [0, str(valeur)]}]


def fausse(resultats):
    def f(requete):
        for cle, valeur in resultats.items():
            if cle in requete:
                return valeur
        return []
    return f


class Base(unittest.TestCase):
    def setUp(self):
        for p in (mock.patch.dict(config.INVENTAIRE, {"srv-test": SRV}),
                  mock.patch.dict(config.ADRESSES, {"srv-test": "192.0.2.50"}),
                  mock.patch.dict(config.MACHINES, {"192.0.2.50": "srv-test"})):
            p.start()
            self.addCleanup(p.stop)

    def detecter(self, resultats):
        with mock.patch.object(detecteurs, "_requete", side_effect=fausse(resultats)):
            return detecteurs._anomalies_windows(detecteurs._reglages())


class TestDetectionWindows(Base):
    def test_rien_a_signaler(self):
        self.assertEqual(self.detecter({"windows_cpu_time_total": serie(20),
                                        "windows_memory_available_bytes": serie(60),
                                        "windows_logical_disk_free_bytes": serie(40, volume="C:")}), [])

    def test_processeur(self):
        res = self.detecter({"windows_cpu_time_total": serie(97)})
        self.assertEqual([(a.source, a.empreinte, a.machine) for a in res], [("cpu", f"win:cpu:{INST}", "srv-test")])

    def test_memoire(self):
        self.assertEqual([a.source for a in self.detecter({"windows_memory_available_bytes": serie(96)})], ["ram"])
        self.assertEqual(self.detecter({"windows_memory_available_bytes": serie(94)}), [])

    def test_disques_valeurs_invalides_ignorees(self):
        res = self.detecter({"windows_logical_disk_free_bytes":
                             serie(93, volume="C:") + serie(50, volume="D:") + serie("NaN", volume="E:")
                             + serie("+Inf", volume="F:")})
        self.assertEqual([a.empreinte for a in res], [f"win:disque:{INST}:C:"])

    def test_service_arrete(self):
        res = self.detecter({"windows_service_state": serie(0, name="spooler", state="running")})
        self.assertEqual([(a.source, a.empreinte) for a in res], [("service", f"win:service:{INST}:spooler")])

    def test_cible_inconnue_ignoree(self):
        self.assertEqual(self.detecter({"windows_cpu_time_total": serie(99, instance="203.0.113.9:9182")}), [])

    def test_erreur_prometheus_ne_bloque_rien(self):
        with mock.patch.object(detecteurs, "_requete", side_effect=requests.ConnectionError("hors service")):
            self.assertEqual(detecteurs._anomalies_windows(detecteurs._reglages()), [])


class TestSansWindows(unittest.TestCase):
    def test_aucune_requete_sans_machine_windows(self):
        with mock.patch.object(detecteurs, "_requete", side_effect=AssertionError("interdit")):
            self.assertEqual(detecteurs._anomalies_windows(detecteurs._reglages()), [])


class TestPreuvesWindows(Base):
    RESULTATS = {"windows_cpu_time_total": serie(42), "windows_memory_available_bytes": serie(61),
                 "windows_logical_disk_free_bytes": serie(55, volume="C:"),
                 "windows_service_state": serie(1, name="dnscache", state="running")
                 + serie(0, name="spooler", state="running")}

    def test_mesures(self):
        with mock.patch.object(detecteurs, "_requete", side_effect=fausse(self.RESULTATS)):
            mesures = dict(detecteurs.mesures_windows("srv-test"))
        self.assertEqual(mesures["processeur utilisé"], "42 %")
        self.assertIn("C: 55 %", mesures["disques utilisés"])
        self.assertIn("spooler : ARRÊTÉ", mesures["services surveillés"])

    def test_les_preuves_sans_ssh_contiennent_les_mesures(self):
        with mock.patch.object(detecteurs, "_requete", side_effect=fausse(self.RESULTATS)), \
             mock.patch("aiops.sondes.charger", return_value=[]), \
             mock.patch.object(detecteurs, "_sonde_ping", return_value=(0.0, 1.0)):
            preuves = agent1._preuves_sans_ssh({"machine": "srv-test"})
        commandes = [p["commande"] for p in preuves]
        self.assertTrue(any("mesure Prometheus : processeur" in c for c in commandes))
        self.assertTrue(any("mesure Prometheus : services surveillés" in c for c in commandes))


if __name__ == "__main__":
    unittest.main()
