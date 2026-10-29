import unittest
from unittest import mock

import requests

from aiops import detecteurs


def vecteur(valeur, hote="runner-devops"):
    return [{"metric": {"host": hote}, "value": [0, str(valeur)]}]


class TestDetecteurSecurite(unittest.TestCase):
    def _collecter(self, resultats=None, erreur=None):
        def fausse(logql):
            if erreur:
                raise erreur
            for cle, valeur in (resultats or {}).items():
                if cle in logql:
                    return valeur
            return []
        with mock.patch.object(detecteurs, "_requete", return_value=[]), \
             mock.patch.object(detecteurs, "_sonde_ping", return_value=(0.0, 0.5)), \
             mock.patch.object(detecteurs, "_requete_loki", side_effect=fausse):
            return [a.empreinte for a in detecteurs.collecter_anomalies()]

    def test_rien_a_signaler(self):
        self.assertEqual(self._collecter(), [])

    def test_attaque_ssh(self):
        self.assertEqual(self._collecter({"Failed password": vecteur(25)}), ["securite:ssh:runner-devops"])

    def test_ssh_sous_le_seuil(self):
        self.assertEqual(self._collecter({"Failed password": vecteur(4)}), [])

    def test_echecs_sudo(self):
        self.assertEqual(self._collecter({"incorrect password attempts": vecteur(5, "frappe-staging")}),
                         ["securite:sudo:frappe-staging"])

    def test_erreur_critique(self):
        self.assertEqual(self._collecter({"oom-kill": vecteur(1)}), ["logs:critique:runner-devops"])

    def test_loki_injoignable_ne_bloque_rien(self):
        self.assertEqual(self._collecter(erreur=requests.ConnectionError("hors service")), [])

    def test_requetes_loki_ignorent_les_journaux_de_loki(self):
        vues = []
        with mock.patch.object(detecteurs, "_requete", return_value=[]), \
             mock.patch.object(detecteurs, "_sonde_ping", return_value=(0.0, 0.5)), \
             mock.patch.object(detecteurs, "_requete_loki", side_effect=lambda q: vues.append(q) or []):
            detecteurs.collecter_anomalies()
        self.assertEqual(len(vues), 3)
        for requete in vues:
            self.assertIn('!= "org_id=fake"', requete)
        self.assertNotIn('|= "sshd"', vues[0])


if __name__ == "__main__":
    unittest.main()
