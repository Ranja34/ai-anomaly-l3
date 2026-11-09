import os
import socket
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest import mock

import yaml

from aiops import agent1, config, detecteurs, lecture, sondes
from aiops.sondes import Sonde


class Gestionnaire(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200 if self.path == "/ok" else 503)
        self.end_headers()

    def log_message(self, *args):
        pass


def port_ferme():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class TestSondes(unittest.TestCase):
    def setUp(self):
        self.serveur = HTTPServer(("127.0.0.1", 0), Gestionnaire)
        self.port = self.serveur.server_address[1]
        threading.Thread(target=self.serveur.serve_forever, daemon=True).start()
        self.addCleanup(self.serveur.server_close)
        self.addCleanup(self.serveur.shutdown)
        adresses = mock.patch.dict(config.ADRESSES, {"local": "127.0.0.1"})
        adresses.start()
        self.addCleanup(adresses.stop)

    def test_tcp_ouvert_et_ferme(self):
        self.assertTrue(sondes.executer(Sonde("local", "tcp", self.port))[0])
        ok, detail, _ = sondes.executer(Sonde("local", "tcp", port_ferme(), timeout=1))
        self.assertFalse(ok)
        self.assertIn("refusée", detail)

    def test_http(self):
        self.assertTrue(sondes.executer(Sonde("local", "http", self.port, "/ok"))[0])
        self.assertFalse(sondes.executer(Sonde("local", "http", self.port, "/panne"))[0])
        self.assertTrue(sondes.executer(Sonde("local", "http", self.port, "/panne", statuts=(503,)))[0])
        self.assertFalse(sondes.executer(Sonde("local", "http", port_ferme(), "/ok", timeout=1))[0])

    def test_executer_toutes_en_parallele(self):
        liste = [Sonde("local", "tcp", self.port), Sonde("local", "tcp", port_ferme(), timeout=1)]
        self.assertEqual([r[1] for r in sondes.executer_toutes(liste)], [True, False])


class TestConfiguration(unittest.TestCase):
    def _charger(self, texte):
        with tempfile.TemporaryDirectory() as d:
            fichier = Path(d) / "s.yml"
            fichier.write_text(texte, encoding="utf-8")
            with mock.patch.dict(os.environ, {"SONDES_FICHIER": str(fichier)}):
                return sondes.charger()

    def test_chargement(self):
        liste = self._charger("sondes:\n  - machine: runner-devops\n    type: http\n    port: 80\n    chemin: /x\n"
                              "  - machine: frappe-staging\n    type: tcp\n    port: 22\n")
        self.assertEqual([(s.machine, s.type, s.port, s.chemin) for s in liste],
                         [("runner-devops", "http", 80, "/x"), ("frappe-staging", "tcp", 22, "/")])

    def test_fichier_invalide(self):
        with self.assertRaises(ValueError):
            self._charger("sondes:\n  - machine: inconnue\n    type: tcp\n    port: 22\n")
        with self.assertRaises(ValueError):
            self._charger("sondes:\n  - machine: runner-devops\n    type: tcp\n    port: abc\n")

    def test_fichier_absent(self):
        self.assertEqual(sondes.charger(), [])

    def test_yaml_genere_est_relisible(self):
        donnees = yaml.safe_load(sondes._yaml([("runner-devops", 80), ("runner-devops", 22)]))["sondes"]
        self.assertEqual([(d["type"], d["port"]) for d in donnees], [("http", 80), ("tcp", 22)])


S22 = Sonde("runner-devops", "tcp", 22)
S80 = Sonde("runner-devops", "http", 80)
S9090 = Sonde("frappe-staging", "http", 9090, "/-/ready")


class TestDetectionSondes(unittest.TestCase):
    def _anomalies(self, *resultats):
        res = [(s, ok, "détail", 1.0) for s, ok in resultats]
        with mock.patch.object(sondes, "charger", return_value=[r[0] for r in res]), \
             mock.patch.object(sondes, "executer_toutes", return_value=res), \
             mock.patch.object(detecteurs.socket, "gethostname", return_value="frappe-staging"):
            return detecteurs._anomalies_sondes({"conf_sonde_s": 20})

    def test_tout_va_bien(self):
        self.assertEqual(self._anomalies((S22, True), (S80, True), (S9090, True)), [])

    def test_une_sonde_en_echec(self):
        res = self._anomalies((S22, True), (S80, False), (S9090, True))
        self.assertEqual([(a.empreinte, a.source, a.machine) for a in res],
                         [("sonde:runner-devops:http:80", "sonde", "runner-devops")])

    def test_toutes_les_sondes_d_une_machine_en_echec_donnent_un_seul_incident(self):
        res = self._anomalies((S22, False), (S80, False), (S9090, True))
        self.assertEqual([a.empreinte for a in res], ["sonde:runner-devops:toutes"])

    def test_une_machine_deja_en_echec_n_ouvre_pas_d_incident_de_sonde(self):
        def fausse(requete):
            if "node_systemd_unit_state" in requete:
                return [{"metric": {"instance": "10.10.0.20:9100", "name": "nginx.service"}, "value": [0, "1"]}]
            return []

        sonde = detecteurs.Anomalie("sonde:runner-devops:http:80", "runner-devops", "sonde", "haute", "t", "d", 20)
        with mock.patch.object(detecteurs, "_requete", side_effect=fausse), \
             mock.patch.object(detecteurs, "_sonde_ping", return_value=(0.0, 0.5)), \
             mock.patch.object(detecteurs, "_requete_loki", return_value=[]), \
             mock.patch.object(detecteurs, "_anomalies_sondes", return_value=[sonde]):
            self.assertEqual([a.source for a in detecteurs.collecter_anomalies()], ["service"])

    def test_commandes_d_enquete_autorisees_par_la_garde_lecture_seule(self):
        inc = {"machine": "runner-devops", "source": "sonde", "empreinte": "sonde:runner-devops:http:80"}
        commandes = agent1._commandes_standard(inc)
        self.assertTrue(any("grep ':80 '" in c for _, c, _ in commandes))
        for _, commande, _ in commandes:
            lecture.valider(commande)


if __name__ == "__main__":
    unittest.main()
