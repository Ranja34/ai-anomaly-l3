"""Validation statique des corrections écrites par l'IA (2e ligne de défense, après l'approbation humaine)."""
import re

import yaml


class CorrectionRefusee(Exception):
    """La correction proposée n'est pas acceptable."""


LONGUEUR_MAX = 6000

INTERDITS = [
    (r"\brm\s+(?:-\S*\s+)*(?:-\w*[rR]\w*|--recursive|--no-preserve-root)(?:\s|$)", "suppression récursive"),
    (r"\bmkfs(?:\.\w+)?\b|\bwipefs\b|\bparted\b|\bfdisk\b", "formatage ou partitionnement de disque"),
    (r"\bdd\b[^\n]*\bof=", "écriture brute sur un disque"),
    (r"\b(?:shutdown|reboot|poweroff|halt)\b|\binit\s+[06]\b|systemctl\s+(?:reboot|poweroff|halt|kexec)",
     "arrêt ou redémarrage de la machine"),
    (r"\b(?:passwd|chpasswd|useradd|userdel|usermod|groupadd|visudo)\b|/etc/(?:sudoers|shadow|passwd|group)",
     "gestion des comptes et des privilèges"),
    (r"authorized_keys|\.ssh\b|id_ed25519|id_rsa|sshd?_config", "accès SSH"),
    (r"(?:systemctl|service)\s+\w+\s+sshd?\b|(?:systemctl|service)\s+sshd?\s+\w+|\bname:\s*[\"']?sshd?\b",
     "service SSH"),
    (r"\biptables\b|\bip6tables\b|\bnft\b|\bufw\b|\bfirewall-cmd\b", "pare-feu"),
    (r"\bcurl\b|\bwget\b|\bnc\b|\bncat\b|\bget_url\b|\buri\s*:", "téléchargement ou connexion réseau sortante"),
    (r"chmod\s+(?:-R\s+)?[0-7]?777|chown\s+-R", "permissions étendues"),
    (r"/dev/(?:sd|nvme|vd|xvd)|/boot\b|/etc/fstab|/etc/netplan|/etc/ssh", "périphériques, démarrage ou réseau"),
    (r":\(\)\s*\{", "fork bomb"),
    (r"\bapt(?:-get)?\s+(?:remove|purge|autoremove)", "désinstallation de paquets"),
    (r"\b(?:ansible\.builtin\.)?(?:user|group|reboot|authorized_key|mount|filesystem)\s*:", "module Ansible interdit"),
    (r"delegate_to|local_action|connection\s*:\s*local|ansible_connection|ansible_host|ansible_become",
     "exécution hors de la machine cible"),
]


def valider_correction(type_, machine, contenu):
    """Contrôles statiques. Lève CorrectionRefusee avec une raison lisible."""
    if type_ not in ("playbook", "script"):
        raise CorrectionRefusee("type de correction inconnu (playbook ou script attendu)")
    if not isinstance(contenu, str) or not contenu.strip():
        raise CorrectionRefusee("contenu vide")
    if len(contenu) > LONGUEUR_MAX:
        raise CorrectionRefusee(f"contenu trop long (maximum {LONGUEUR_MAX} caractères)")

    for motif, raison in INTERDITS:
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
