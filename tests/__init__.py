import os

# Les tests ne touchent jamais au vrai réseau ni à la vraie configuration
os.environ["SONDES_FICHIER"] = "/nonexistent/sondes.yml"
os.environ["AIOPS_INVENTAIRE"] = "/nonexistent/inventaire.yml"
