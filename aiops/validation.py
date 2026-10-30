"""Validation statique des corrections écrites par l'IA.

Deux modes (variable AGENT2_MODE) :
- « labo » (défaut) : seulement les gestes irréversibles ou qui détruiraient le laboratoire ;
- « strict » : liste noire complète (à réactiver pour le durcissement).
"""
import os
import re
import socket

import yaml


class CorrectionRefusee(Exception):
    """La correction proposée n'est pas acceptable."""


LONGUEUR_MAX = 6000

# Toujours appliqué : la correction doit s'exécuter sur la machine prévue
STRUCTURE = [
    (r"delegate_to|local_action|connection\s*:\s*local|ansible_connection|ansible_host|ansible_become",
     "exécution hors de la machine cible"),
]

# Mode labo : gestes irréversibles ou destructeurs pour le laboratoire
CATASTROPHES = [
    (r"\brm\s+(?:-\S*\s+)*(?:-\w*[rR]\w*|--recursive)\s+(?:-\S+\s+)*(?:--\s+)?"
     r"(?:/|/\*|/etc|/boot|/usr|/bin|/sbin|/lib\w*|/var|/home|/root|/dev|/proc|/sys|~)/?(?:\s|$)",
     "suppression récursive d'un dossier système"),
    (r"--no-preserve-root", "suppression de la racine"),
    (r"\bmkfs(?:\.\w+)?\b|\bwipefs\b", "formatage de disque"),
    (r"\bdd\b[^\n]*\bof=/dev/|>\s*/dev/(?:sd|nvme|vd|xvd)", "écriture brute sur un disque"),
    (r":\(\)\s*\{", "fork bomb"),
    (r"chmod\s+-R\s+[0-7]{3,4}\s+/(?:\s|$)", "permissions sur toute la racine"),
    (r"\b(?:shutdown|poweroff|halt)\b|\binit\s+0\b|systemctl\s+(?:poweroff|halt)", "extinction de la machine"),
    (r"(?:stop|disable|mask|kill)\S*\s+aiops", "arrêt de l'orchestrateur"),
]

REDEMARRAGE = (r"\breboot\b|systemctl\s+(?:reboot|kexec)",
               "redémarrage de la machine qui héberge l'orchestrateur")

# Mode strict : liste noire complète
STRICT = [
    (r"\brm\s+(?:-\S*\s+)*(?:-\w*[rR]\w*|--recursive)(?:\s|$)", "suppression récursive"),
    (r"\bparted\b|\bfdisk\b", "partitionnement de disque"),
    (r"\breboot\b", "redémarrage de la machine"),
    (r"\b(?:passwd|chpasswd|useradd|userdel|usermod|groupadd|visudo)\b|/etc/(?:sudoers|shadow|passwd|group)",
     "gestion des comptes et des privilèges"),
    (r"authorized_keys|\.ssh\b|id_ed25519|id_rsa|sshd?_config", "accès SSH"),
    (r"(?:systemctl|service)\s+\w+\s+sshd?\b|(?:systemctl|service)\s+sshd?\s+\w+|\bname:\s*[\"']?sshd?\b",
     "service SSH"),
    (r"\biptables\b|\bip6tables\b|\bnft\b|\bufw\b|\bfirewall-cmd\b", "pare-feu"),
    (r"\bcurl\b|\bwget\b|\bnc\b|\bncat\b|\bget_url\b|\buri\s*:", "téléchargement ou connexion réseau sortante"),
    (r"chmod\s+(?:-R\s+)?[0-7]?777|chown\s+-R", "permissions étendues"),
    (r"/dev/(?:sd|nvme|vd|xvd)|/boot\b|/etc/fstab|/etc/netplan|/etc/ssh", "périphériques, démarrage ou réseau"),
    (r"\bapt(?:-get)?\s+(?:remove|purge|autoremove)", "désinstallation de paquets"),
    (r"(?m)^\s*(?:-\s+)?(?:ansible\.builtin\.)?(?:user|group|reboot|authorized_key|mount|filesystem)\s*:\s*(?:$|\S+=)",
     "module Ansible interdit"),
]


def mode():
    return "strict" if os.getenv("AGENT2_MODE", "labo").strip().lower() == "strict" else "labo"


def _motifs(machine):
    motifs = list(STRUCTURE) + list(CATASTROPHES)
    if mode() == "strict":
        motifs += STRICT
    elif machine == socket.gethostname():
        motifs.append(REDEMARRAGE)
    return motifs


def valider_correction(type_, machine, contenu):
    """Contrôles statiques. Lève CorrectionRefusee avec une raison lisible."""
    if type_ not in ("playbook", "script"):
        raise CorrectionRefusee("type de correction inconnu (playbook ou script attendu)")
    if not isinstance(contenu, str) or not contenu.strip():
        raise CorrectionRefusee("contenu vide")
    if len(contenu) > LONGUEUR_MAX:
        raise CorrectionRefusee(f"contenu trop long (maximum {LONGUEUR_MAX} caractères)")

    for motif, raison in _motifs(machine):
        if re.search(motif, contenu, re.IGNORECASE):
            raise CorrectionRefusee(f"élément interdit détecté : {raison}")

    if type_ == "script":
        if not contenu.lstrip().startswith("#!"):
            raise CorrectionRefusee("le script doit commencer par un shebang (#!/bin/bash)")
        if re.search(r"\bsudo\b", contenu):
            raise CorrectionRefusee("le script ne doit pas contenir sudo (utiliser sudo_requis)")
        return

    try:
        plays = yaml.safe_load(contenu)
    except yaml.YAMLError:
        raise CorrectionRefusee("YAML invalide")
    if not isinstance(plays, list) or not plays or len(plays) > 3 or not all(isinstance(p, dict) for p in plays):
        raise CorrectionRefusee("un playbook doit être une liste de 1 à 3 plays")
    for play in plays:
        if play.get("hosts") != machine:
            raise CorrectionRefusee(f"le playbook doit cibler uniquement « {machine} »")
        if not isinstance(play.get("tasks"), list) or not play["tasks"]:
            raise CorrectionRefusee("chaque play doit contenir des tâches")
