import unittest

from aiops.securite import CommandeRefusee, masquer_secrets, valider

ACCEPTEES = [
    "systemctl status prometheus-node-exporter --no-pager", "journalctl -u nginx -n 30 --no-pager",
    "journalctl --since=-30min -p err --no-pager", "df -h", "free -m", "ps aux --sort=-%cpu",
    "ss -tlnp", "ip -br a", "du -x -h --max-depth=1 /var", "tail -n 50 /var/log/syslog",
    "ping -c 2 10.10.0.20", "uptime",
]
REFUSEES = [
    "systemctl restart nginx", "systemctl stop prometheus-node-exporter", "cat /etc/shadow",
    "sudo systemctl status x", "journalctl -u nginx; rm -rf /", "ps aux | grep ssh", "df -h /etc/../root",
    "tail -f /var/log/syslog", "tail -n 5 /etc/passwd", "journalctl --vacuum-size=1M", "ls /",
    "echo $(id)", "ping -c 2 8.8.8.8 > /dev/null", "systemctl status x --now", "rm -rf /home",
    "du -h /etc", "ping -c 2 exemple.com", "",
]


class TestSecurite(unittest.TestCase):
    def test_commandes_autorisees(self):
        for c in ACCEPTEES:
            with self.subTest(c=c):
                valider(c)

    def test_commandes_refusees(self):
        for c in REFUSEES:
            with self.subTest(c=c):
                with self.assertRaises(CommandeRefusee):
                    valider(c)

    def test_masquage_des_secrets(self):
        texte = masquer_secrets("cle gsk_abcdefghij1234567890 et password=monsecret et Bearer abc123")
        self.assertNotIn("gsk_abcdefghij", texte)
        self.assertNotIn("monsecret", texte)
        self.assertNotIn("abc123", texte)


if __name__ == "__main__":
    unittest.main()
