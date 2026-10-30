#!/bin/bash
# Simule une attaque par force brute SSH (faux noms d'utilisateur, sans mot de passe).
# Usage : scripts/simuler_attaque_ssh.sh [adresse_cible] [nombre_de_tentatives]
CIBLE="${1:-10.10.0.20}"
N="${2:-20}"
echo "Simulation : $N tentatives SSH invalides vers $CIBLE"
for i in $(seq 1 "$N"); do
  ssh -o BatchMode=yes -o PubkeyAuthentication=no -o ConnectTimeout=3 "intrus$i@$CIBLE" true 2>/dev/null || true
done
echo "Terminé."
