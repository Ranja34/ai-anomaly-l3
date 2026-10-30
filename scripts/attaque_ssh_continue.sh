#!/bin/bash
# Attaque SSH continue (force brute simulée) depuis une adresse IP source dédiée.
# Usage : scripts/attaque_ssh_continue.sh [cible] [duree_secondes] [ip_source]
CIBLE="${1:-10.10.0.20}"
DUREE="${2:-900}"
SOURCE="${3:-10.10.0.99}"
FIN=$((SECONDS + DUREE))
i=0
while [ "$SECONDS" -lt "$FIN" ]; do
  i=$((i + 1))
  ssh -b "$SOURCE" -o BatchMode=yes -o PubkeyAuthentication=no -o ConnectTimeout=3 "intrus$i@$CIBLE" true 2>/dev/null || true
  sleep 3
done
