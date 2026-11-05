import unittest

from aiops import agent2


class TestMessagesVerification(unittest.TestCase):
    def test_un_message_par_type_d_incident(self):
        self.assertIn("service", agent2._detail_verification("service", True))
        self.assertIn("service", agent2._detail_verification("service", False))
        self.assertIn("attaque", agent2._detail_verification("securite", True))
        self.assertIn("disque", agent2._detail_verification("disque", False))
        self.assertIn("métrique", agent2._detail_verification("inconnu", True))


if __name__ == "__main__":
    unittest.main()
