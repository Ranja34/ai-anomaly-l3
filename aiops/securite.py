"""Garde-fous : seules des commandes d'investigation en lecture seule sont autorisées."""
import re


class CommandeRefusee(Exception):
    """La commande demandée n'est pas autorisée."""


INTERDITS = set(";&|<>`$()\\\"'*?{}[]!~#\n\r")
TOKEN = re.compile(r"^[\w@%.:/=,+\-]+$")

UNITE = r"^[\w@.\-]+$"
NOMBRE = r"^\d{1,4}$"
TEMPS = r"^[-+\w:.]+$"
CHEMIN = r"^/[\w./\-]*$"

SPECS = {
    "systemctl": {
        "sous": {"status", "is-active", "is-enabled", "is-failed", "show", "cat", "list-units", "list-unit-files"},
        "flags": {"--no-pager": None, "--failed": None, "--type": r"^[a-z]+$",
                  "-p": r"^[A-Za-z,]+$", "--property": r"^[A-Za-z,]+$"},
        "positionnel": UNITE,
    },
    "journalctl": {
        "flags": {"--no-pager": None, "-u": UNITE, "--unit": UNITE, "-n": NOMBRE, "--lines": NOMBRE,
                  "-p": r"^[a-z0-9.]+$", "--priority": r"^[a-z0-9.]+$", "--since": TEMPS, "--until": TEMPS,
                  "-b": None, "-k": None, "-o": r"^short(-iso)?$"},
    },
    "df": {"flags": {"-h": None, "-T": None, "-i": None}, "positionnel": CHEMIN},
    "free": {"flags": {"-m": None, "-h": None, "-g": None}},
    "uptime": {"flags": {"-p": None}},
    "hostname": {"flags": {}},
    "uname": {"flags": {"-a": None, "-r": None}},
    "ps": {"flags": {"-e": None, "-ef": None, "-o": r"^[a-z,%]+$", "--sort": r"^[-+]?%?[a-z]+$"},
           "positionnel": r"^(aux|auxf)$"},
    "ss": {"flags": {"-t": None, "-u": None, "-l": None, "-n": None, "-p": None, "-a": None,
                     "-tln": None, "-tlnp": None, "-tuln": None, "-tulnp": None}},
    "ip": {"sous": {"addr", "address", "a", "route", "r", "link"}, "flags": {"-br": None, "-s": None}},
    "du": {"flags": {"-h": None, "-s": None, "-x": None, "--max-depth": r"^[0-3]$"},
           "positionnel": r"^/(var|tmp|opt|srv|home)(/[\w.\-]+)*$"},
    "tail": {"flags": {"-n": NOMBRE}, "positionnel": r"^/var/log/[\w.\-/]+$"},
    "lsblk": {"flags": {"-f": None}},
    "ping": {"flags": {"-c": r"^[1-5]$", "-W": r"^[1-5]$"},
             "positionnel": r"^\d{1,3}(\.\d{1,3}){3}$"},
}


def valider(commande):
    """Retourne la liste des éléments si la commande est autorisée, sinon lève CommandeRefusee."""
    commande = (commande or "").strip()
    if not commande or len(commande) > 200:
        raise CommandeRefusee("commande vide ou trop longue")
    if any(c in INTERDITS for c in commande) or ".." in commande:
        raise CommandeRefusee("caractères interdits")
    elements = commande.split()
    if not all(TOKEN.match(e) for e in elements):
        raise CommandeRefusee("caractères interdits")

    nom, args = elements[0], elements[1:]
    spec = SPECS.get(nom)
    if spec is None:
        raise CommandeRefusee(f"commande non autorisée : {nom}")

    positionnels, i = [], 0
    while i < len(args):
        element = args[i]
        if element.startswith("-"):
            option, egal, valeur = element.partition("=")
            if option not in spec["flags"]:
                raise CommandeRefusee(f"option non autorisée : {option}")
            motif = spec["flags"][option]
            if motif is None:
                if egal:
                    raise CommandeRefusee(f"option sans valeur : {option}")
            else:
                if not egal:
                    i += 1
                    if i >= len(args):
                        raise CommandeRefusee(f"valeur manquante pour {option}")
                    valeur = args[i]
                if not re.match(motif, valeur):
                    raise CommandeRefusee(f"valeur non autorisée pour {option}")
        else:
            positionnels.append(element)
        i += 1

    sous = spec.get("sous")
    if sous:
        if not positionnels or positionnels[0] not in sous:
            raise CommandeRefusee(f"sous-commande non autorisée pour {nom}")
        positionnels = positionnels[1:]
    motif = spec.get("positionnel")
    for p in positionnels:
        if motif is None or not re.match(motif, p):
            raise CommandeRefusee(f"argument non autorisé : {p}")
    return elements


_MOTIFS = [
    (re.compile(r"gsk_[A-Za-z0-9]{10,}"), "[masqué]"),
    (re.compile(r"(?i)\b(password|passwd|secret|token|api[_-]?key)\b(\s*[=:]\s*)\S+"), r"\1\2[masqué]"),
    (re.compile(r"(?i)bearer\s+\S+"), "Bearer [masqué]"),
]


def masquer_secrets(texte):
    for motif, remplacement in _MOTIFS:
        texte = motif.sub(remplacement, texte)
    return texte
