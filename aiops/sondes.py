"""Sondes de disponibilité vues depuis VM1 (ce que verrait un utilisateur) : ports TCP et pages web."""
import argparse
import os
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

import requests
import yaml

from aiops import config

# Le port 9100 (Node Exporter) est déjà couvert par la détection « cible injoignable »
PORTS_COURANTS = [22, 53, 80, 443, 3000, 3100, 5000, 5432, 3306, 8080, 9090]
CHEMINS_HTTP = {80: "/", 8080: "/", 3000: "/api/health", 3100: "/ready", 5000: "/api/etat", 9090: "/-/ready"}


@dataclass(frozen=True)
class Sonde:
    machine: str
    type: str          # "tcp" ou "http"
    port: int
    chemin: str = "/"
    statuts: tuple = ()
    timeout: float = 3.0

    def libelle(self):
        return f"page web (port {self.port})" if self.type == "http" else f"port TCP {self.port}"


def _fichier():
    return Path(os.getenv("SONDES_FICHIER", str(config.RACINE / "sondes.yml")))


def charger():
    """Lit sondes.yml. Retourne [] si le fichier n'existe pas ; lève ValueError s'il est invalide."""
    chemin = _fichier()
    if not chemin.exists():
        return []
    donnees = yaml.safe_load(chemin.read_text(encoding="utf-8")) or {}
    sondes = []
    for i, s in enumerate(donnees.get("sondes") or [], 1):
        if not isinstance(s, dict):
            raise ValueError(f"sonde n°{i} invalide")
        machine, type_, port = s.get("machine"), s.get("type"), s.get("port")
        if machine not in config.ADRESSES:
            raise ValueError(f"sonde n°{i} : machine inconnue ({machine})")
        if type_ not in ("tcp", "http"):
            raise ValueError(f"sonde n°{i} : type inconnu ({type_})")
        if not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError(f"sonde n°{i} : port invalide ({port})")
        sondes.append(Sonde(machine, type_, port, str(s.get("chemin") or "/"),
                            tuple(s.get("statuts") or ()), float(s.get("timeout") or 3)))
    return sondes


def executer(sonde):
    """Retourne (ok, détail, latence en ms)."""
    ip = config.ADRESSES[sonde.machine]
    debut = time.monotonic()

    def ms():
        return (time.monotonic() - debut) * 1000

    try:
        if sonde.type == "tcp":
            with socket.create_connection((ip, sonde.port), timeout=sonde.timeout):
                pass
            return True, "port ouvert", ms()
        rep = requests.get(f"http://{ip}:{sonde.port}{sonde.chemin}", timeout=sonde.timeout, allow_redirects=False)
        ok = rep.status_code in sonde.statuts if sonde.statuts else rep.status_code < 500
        return ok, f"réponse HTTP {rep.status_code}", ms()
    except requests.exceptions.Timeout:
        return False, "délai dépassé (pare-feu ou machine injoignable ?)", ms()
    except requests.exceptions.ConnectionError as e:
        refuse = "refused" in str(e).lower()
        return False, ("connexion refusée (service arrêté ou port fermé)" if refuse else "connexion impossible"), ms()
    except (socket.timeout, TimeoutError):
        return False, "délai dépassé (pare-feu ou machine injoignable ?)", ms()
    except ConnectionRefusedError:
        return False, "connexion refusée (service arrêté ou port fermé)", ms()
    except OSError as e:
        return False, f"erreur réseau ({type(e).__name__})", ms()


def executer_toutes(sondes):
    """Exécute toutes les sondes en parallèle. Retourne une liste de (sonde, ok, détail, ms)."""
    if not sondes:
        return []
    with ThreadPoolExecutor(max_workers=min(8, len(sondes))) as pool:
        return list(pool.map(lambda s: (s,) + executer(s), sondes))


def _ouvert(ip, port):
    try:
        with socket.create_connection((ip, port), timeout=1.5):
            return True
    except OSError:
        return False


def decouvrir():
    """Ports courants actuellement ouverts sur chaque machine : [(machine, port), ...]."""
    taches = [(m, p) for m in sorted(config.ADRESSES) for p in PORTS_COURANTS]
    with ThreadPoolExecutor(max_workers=16) as pool:
        ouverts = list(pool.map(lambda t: _ouvert(config.ADRESSES[t[0]], t[1]), taches))
    return [t for t, ouvert in zip(taches, ouverts) if ouvert]


def _yaml(trouvees):
    lignes = ["# Sondes de disponibilité, vues depuis VM1 comme le verrait un utilisateur du réseau.",
              "# Générées par « python -m aiops.sondes --decouvrir --ecrire » : retire ce qui ne doit pas être surveillé.",
              "# Types : tcp (le port accepte une connexion) ou http (la page répond avec un code inférieur à 500).",
              "sondes:"]
    for machine, port in trouvees:
        lignes.append(f"  - machine: {machine}")
        if port in CHEMINS_HTTP:
            lignes += ["    type: http", f"    port: {port}", f"    chemin: {CHEMINS_HTTP[port]}"]
        else:
            lignes += ["    type: tcp", f"    port: {port}"]
    return "\n".join(lignes) + "\n"


def main():
    parser = argparse.ArgumentParser(description="Sondes de disponibilité")
    parser.add_argument("--decouvrir", action="store_true", help="chercher les ports ouverts sur les machines")
    parser.add_argument("--ecrire", action="store_true", help="avec --decouvrir : écrire sondes.yml")
    parser.add_argument("--force", action="store_true", help="avec --ecrire : remplacer un fichier existant")
    args = parser.parse_args()

    if args.decouvrir:
        trouvees = decouvrir()
        print("Ports ouverts trouvés :")
        for machine, port in trouvees:
            print(f"  {machine:<15} {port}")
        if args.ecrire:
            chemin = _fichier()
            if chemin.exists() and not args.force:
                print(f"{chemin.name} existe déjà : utilise --force pour le remplacer.")
            else:
                chemin.write_text(_yaml(trouvees), encoding="utf-8")
                print(f"{chemin.name} écrit ({len(trouvees)} sondes).")
        return

    sondes = charger()
    if not sondes:
        print("Aucune sonde configurée. Lance : python -m aiops.sondes --decouvrir --ecrire")
        return
    for sonde, ok, detail, ms in executer_toutes(sondes):
        print(f"  {'OK   ' if ok else 'ÉCHEC'}  {sonde.machine:<15} {sonde.libelle():<22} {ms:6.0f} ms  {detail}")


if __name__ == "__main__":
    main()
