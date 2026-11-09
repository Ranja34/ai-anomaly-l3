import os

# Les tests ne sondent jamais le vrai réseau : aucun fichier de sondes par défaut
os.environ["SONDES_FICHIER"] = "/nonexistent/sondes.yml"
