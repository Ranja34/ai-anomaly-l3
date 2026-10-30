"""Garde « lecture seule » pour les commandes d'enquête écrites par l'IA.

Ce n'est pas une barrière de sécurité : elle garantit que toute modification passe par l'approbation
de l'administrateur (principe du projet) et non par la phase d'enquête.
"""
import re

from aiops.securite import CommandeRefusee

LONGUEUR_MAX = 600

INTERDITS_CMD = {
    "rm", "mv", "cp", "ln", "mkdir", "rmdir", "touch", "chmod", "chown", "chgrp", "truncate", "shred", "dd",
    "mount", "umount", "swapon", "swapoff", "mkswap", "fsck", "parted", "fdisk", "sfdisk",
    "kill", "pkill", "killall", "reboot", "shutdown", "poweroff", "halt", "init", "telinit",
    "useradd", "userdel", "usermod", "groupadd", "groupdel", "groupmod", "adduser", "deluser", "passwd",
    "chpasswd", "visudo", "su", "sudo", "tee", "xargs", "eval", "exec", "source", ".",
    "ssh", "scp", "sftp", "rsync", "nc", "ncat", "netcat", "telnet", "wget", "ftp",
    "crontab", "at", "batch", "nohup", "setsid", "modprobe", "rmmod", "insmod", "systemd-run",
    "python", "python3", "perl", "ruby", "node", "php", "lua", "bash", "sh", "dash", "zsh", "ksh",
    "install", "patch", "tar", "unzip", "gzip", "gunzip", "bzip2", "xz", "zip",
    "vi", "vim", "nano", "less", "more", "man", "top", "htop", "watch", "screen", "tmux",
}

VERBES = {
    "systemctl": {"start", "stop", "restart", "reload", "try-restart", "reload-or-restart", "enable", "disable",
                  "mask", "unmask", "kill", "reset-failed", "daemon-reload", "isolate", "set-default", "edit",
                  "revert", "link", "preset"},
    "service": {"start", "stop", "restart", "reload", "force-reload", "try-restart"},
    "ufw": {"allow", "deny", "reject", "limit", "delete", "enable", "disable", "reset", "insert", "route",
            "default", "reload", "logging"},
    "iptables": {"-A", "-I", "-D", "-F", "-X", "-P", "-R", "-N", "-Z", "-E", "--append", "--insert", "--delete",
                 "--flush", "--policy", "--delete-chain", "--new-chain", "--zero", "--replace"},
    "nft": {"add", "delete", "flush", "insert", "replace", "create", "destroy", "rename", "-f"},
    "fail2ban-client": {"set", "start", "stop", "reload", "restart", "unban", "add", "flushlogs"},
    "docker": {"run", "rm", "rmi", "stop", "start", "restart", "kill", "prune", "exec", "pull", "push", "create",
               "build", "compose", "cp", "commit", "pause", "unpause", "rename", "update", "load", "import",
               "tag", "login", "logout", "connect", "disconnect"},
    "apt": {"install", "remove", "purge", "upgrade", "full-upgrade", "dist-upgrade", "autoremove", "update",
            "reinstall", "build-dep", "satisfy"},
    "ip": {"add", "del", "delete", "flush", "set", "change", "replace", "append", "prepend", "exec"},
    "resolvectl": {"flush-caches", "reset-statistics", "revert", "dns", "domain", "llmnr", "mdns", "dnssec"},
    "hostnamectl": {"set-hostname", "set-icon-name", "set-chassis", "set-deployment", "set-location"},
    "timedatectl": {"set-time", "set-timezone", "set-ntp", "set-local-rtc"},
    "netplan": {"apply", "try", "generate", "set"},
    "sysctl": {"-w", "--write", "-p", "--load", "--system"},
    "dpkg": {"-i", "--install", "-r", "--remove", "-P", "--purge", "--configure"},
    "loginctl": {"terminate-session", "terminate-user", "kill-session", "kill-user", "lock-session"},
}
for _nom in ("ip6tables", "iptables-restore", "ip6tables-restore"):
    VERBES[_nom] = VERBES["iptables"]
for _nom in ("apt-get", "aptitude", "pip", "pip3", "snap", "npm"):
    VERBES[_nom] = VERBES["apt"] | {"refresh", "revert"}

FIND_INTERDITS = {"-delete", "-exec", "-execdir", "-ok", "-okdir", "-fprint", "-fprintf", "-fls"}
CURL_INTERDITS = {"-o", "-O", "-X", "-d", "-T", "-F", "-K", "-J", "--request", "--data", "--data-raw",
                  "--data-binary", "--data-urlencode", "--upload-file", "--form", "--output", "--remote-name",
                  "--config"}

REDIRECTIONS_SURES = ["2>/dev/null", "&>/dev/null", "1>/dev/null", ">/dev/null", "2>&1", ">&2"]
SEPARATEURS = re.compile(r"\|\||&&|\$\(|[;|\n`()]")


def _verifier_segment(segment):
    mots = segment.split()
    while mots and (re.match(r"^\w+=\S*$", mots[0]) or mots[0] in ("time", "nice")):
        mots = mots[1:]
    if mots and mots[0] == "timeout":
        mots = mots[2:]
    if not mots:
        return
    premier = mots[0]
    if premier.startswith("./") or (premier.startswith("/") and not premier.startswith(("/usr/", "/bin/", "/sbin/"))):
        raise CommandeRefusee("exécution d'un script ou d'un programme non standard")
    nom = premier.rsplit("/", 1)[-1]
    args = [a.strip("'\"") for a in mots[1:]]

    if nom in INTERDITS_CMD or nom.startswith("mkfs"):
        raise CommandeRefusee(f"commande qui modifie le système : {nom}")
    for a in args:
        if a in VERBES.get(nom, ()):
            raise CommandeRefusee(f"« {nom} {a} » modifierait le système")
    if nom == "journalctl" and any(a.startswith("--vacuum") or a in ("--rotate", "--flush", "--sync", "-f", "--follow")
                                   for a in args):
        raise CommandeRefusee("journalctl : option qui modifie ou bloque")
    if nom == "tail" and any(a in ("-f", "-F", "--follow") for a in args):
        raise CommandeRefusee("tail -f bloquerait l'enquête")
    if nom == "sed" and any(a.startswith("-i") or a == "--in-place" for a in args):
        raise CommandeRefusee("sed -i modifie les fichiers")
    if nom == "find" and any(a in FIND_INTERDITS for a in args):
        raise CommandeRefusee("find avec action (-exec, -delete…)")
    if nom in ("awk", "gawk", "mawk") and "system(" in segment:
        raise CommandeRefusee("awk system() interdit")
    if nom == "curl":
        for a in args:
            if a in CURL_INTERDITS or (re.fullmatch(r"-[a-zA-Z]{2,}", a) and any(c in "oOTdFXK" for c in a[1:])):
                raise CommandeRefusee(f"curl {a} écrirait ou enverrait des données")
    if nom == "ping" and "-c" not in args:
        raise CommandeRefusee("ping doit utiliser -c (nombre limité)")
    if nom == "tcpdump" and "-c" not in args:
        raise CommandeRefusee("tcpdump doit utiliser -c (nombre limité)")
    if nom == "dmesg" and any(a in ("-c", "-C", "--clear", "--read-clear") for a in args):
        raise CommandeRefusee("dmesg ne doit pas vider le tampon")


def valider(commande):
    """Accepte une commande d'enquête en lecture seule, sinon lève CommandeRefusee."""
    commande = (commande or "").strip()
    if not commande:
        raise CommandeRefusee("commande vide")
    if len(commande) > LONGUEUR_MAX:
        raise CommandeRefusee(f"commande trop longue (maximum {LONGUEUR_MAX} caractères)")
    if "\n" in commande or "\r" in commande:
        raise CommandeRefusee("une seule ligne par commande")
    propre = commande
    for motif in REDIRECTIONS_SURES:
        propre = propre.replace(motif, " ")
    if ">" in propre:
        raise CommandeRefusee("redirection vers un fichier interdite")
    if re.search(r"(?<![&>])&(?![&>])", propre):
        raise CommandeRefusee("exécution en arrière-plan interdite")
    for segment in SEPARATEURS.split(propre):
        _verifier_segment(segment)
