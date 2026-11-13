import unittest

import yaml

from aiops import sondes


class TestDecouverteValidee(unittest.TestCase):
    def test_une_page_qui_ne_repond_pas_devient_une_sonde_tcp(self):
        donnees = yaml.safe_load(sondes._yaml([("runner-devops", 80), ("runner-devops", 3100)],
                                              {("runner-devops", 3100)}))["sondes"]
        self.assertEqual([(d["port"], d["type"]) for d in donnees], [(80, "http"), (3100, "tcp")])


if __name__ == "__main__":
    unittest.main()
