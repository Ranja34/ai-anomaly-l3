import unittest
from unittest import mock

from aiops import detecteurs

IP = "10.10.0.20"


def serie(valeur, **etiquettes):
    return [{"metric": {"instance": f"{IP}:9100", **etiquettes}, "value": [0, str(valeur)]}]


class TestDetecteurReseau(unittest.TestCase):
    def _collecter(self, requetes=None, ping=(0.0, 0.5)):
        def fausse(requete):
            for cle, valeur in (requetes or {}).items():
                if cle in requete:
                    return valeur
            return []
        with mock.patch.object(detecteurs, "_requete", side_effect=fausse), \
             mock.patch.object(detecteurs, "_sonde_ping", return_value=ping), \
             mock.patch.object(detecteurs.socket, "gethostname", return_value="frappe-staging"):
            return [a.empreinte for a in detecteurs.collecter_anomalies()]

    def test_rien_a_signaler(self):
        self.assertEqual(self._collecter(), [])

    def test_interface_inactive(self):
        res = self._collecter({"node_network_up": serie(0, device="ens37")})
        self.assertEqual(res, [f"reseau:interface:{IP}:9100:ens37"])

    def test_erreurs_de_paquets(self):
        res = self._collecter({"node_network_receive_errs_total": serie(12.5, device="ens37")})
        self.assertEqual(res, [f"reseau:erreurs:{IP}:9100:ens37"])

    def test_retransmissions_tcp(self):
        res = self._collecter({"node_netstat_Tcp_RetransSegs": serie(8)})
        self.assertEqual(res, [f"reseau:retrans:{IP}:9100"])

    def test_perte_de_ping_partielle(self):
        self.assertEqual(self._collecter(ping=(40.0, 0.5)), [f"reseau:perte:{IP}"])

    def test_perte_totale_laissee_au_detecteur_up(self):
        self.assertEqual(self._collecter(ping=(100.0, None)), [])

    def test_latence_elevee(self):
        self.assertEqual(self._collecter(ping=(0.0, 250.0)), [f"reseau:latence:{IP}"])


if __name__ == "__main__":
    unittest.main()
