"""Détecteurs simples (sans IA) : interrogent Prometheus et ouvrent des incidents confirmés."""
import argparse
import math
import os
import re
import socket
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone

import requests

from aiops import config, db
from aiops.temps import formater_local, maintenant_utc

FS_EXCLUS = "tmpfs|overlay|squashfs|ramfs|devtmpfs"


@dataclass
class Anomalie:
    empreinte: str
    machine: str
    source: str
    gravite: str
    titre: str
    detail: str
    confirmation_s: int


def _reglages():
    return {
        "intervalle": int(os.getenv("DETECT_INTERVALLE_S", "30")),
        "seuil_cpu": float(os.getenv("SEUIL_CPU", "90")),
        "seuil_ram": float(os.getenv("SEUIL_RAM", "90")),
        "seuil_disque": float(os.getenv("SEUIL_DISQUE", "90")),
        "conf_up_s": int(os.getenv("CONFIRM_UP_S", "60")),
        "conf_cpu_s": int(os.getenv("CONFIRM_CPU_S", "120")),
        "conf_ram_s": int(os.getenv("CONFIRM_RAM_S", "120")),
        "conf_disque_s": int(os.getenv("CONFIRM_DISQUE_S", "0")),
        "cooldown_s": int(os.getenv("DETECT_COOLDOWN_S", "600")),
        "cooldown_escalade_s": int(os.getenv("DETECT_COOLDOWN_ESCALADE_S", "3600")),
        "conf_service_s": int(os.getenv("CONFIRM_SERVICE_S", "60")),
        "conf_reseau_s": int(os.getenv("CONFIRM_RESEAU_S", "60")),
        "interfaces": os.getenv("RESEAU_INTERFACES", "ens.*|eth.*|enp.*"),
        "seuil_pertes": float(os.getenv("SEUIL_PERTES_PAQUETS", "5")),
        "seuil_retrans": float(os.getenv("SEUIL_RETRANS_TCP", "5")),
        "seuil_perte_ping": float(os.getenv("SEUIL_PERTE_PING", "20")),
        "seuil_latence_ms": float(os.getenv("SEUIL_LATENCE_MS", "100")),
        "fenetre_logs": os.getenv("LOGS_FENETRE", "2m"),
        "seuil_ssh": int(os.getenv("SEUIL_SSH_ECHECS", "10")),
        "seuil_sudo": int(os.getenv("SEUIL_SUDO_ECHECS", "3")),
        "services_ignores": {s.strip() for s in os.getenv("SERVICES_IGNORES", "").split(",") if s.strip()},
    }


def _requete(promql):
    rep = requests.get(f"{config.PROMETHEUS_URL}/api/v1/query", params={"query": promql}, timeout=10)
    rep.raise_for_status()
    donnees = rep.json()
    if donnees.get("status") != "success":
        raise RuntimeError(f"Réponse Prometheus invalide : {donnees}")
    return donnees["data"]["result"]


def _machine(instance):
    hote = instance.split(":")[0]
    return config.MACHINES.get(hote, hote)


def _gravite(valeur):
    return "haute" if valeur >= 95 else "moyenne"


_ETAT_LOKI = {"ok": True}


def _requete_loki(logql):
    rep = requests.get(f"{config.LOKI_URL}/loki/api/v1/query", params={"query": logql}, timeout=10)
    rep.raise_for_status()
    donnees = rep.json()
    if donnees.get("status") != "success":
        raise RuntimeError(f"Réponse Loki invalide : {donnees}")
    return donnees["data"]["result"]


def _anomalies_loki(r):
    """Détection par les journaux (sécurité et erreurs critiques). Ne bloque jamais le reste de la détection."""
    fen = r["fenetre_logs"]
    base = '{job="systemd-journal"} != "org_id=fake"'
    regles = [
        ("ssh", f'sum by (host) (count_over_time({base} |~ "Failed password for|Invalid user|sshd:auth.: authentication failure|maximum authentication attempts" [{fen}]))',
         r["seuil_ssh"], "securite", "haute",
         "Tentatives de connexion SSH suspectes sur {m}",
         "{n} échecs d'authentification SSH sur {m} en {fen} (seuil : {seuil})."),
        ("sudo", f'sum by (host) (count_over_time({base} |~ "sudo:auth.: authentication failure|incorrect password attempts|NOT in sudoers" [{fen}]))',
         r["seuil_sudo"], "securite", "haute",
         "Échecs d'élévation de privilèges (sudo) sur {m}",
         "{n} échecs sudo sur {m} en {fen} (seuil : {seuil})."),
        ("critique", f'sum by (host) (count_over_time({base} |~ "Out of memory|oom-kill|Killed process|segfault|I/O error|EXT4-fs error|Remounting filesystem read-only|blocked for more than" !~ "sr0|fd0" [{fen}]))',
         0, "logs", "haute",
         "Erreur système critique sur {m}",
         "{n} message(s) d'erreur critique (mémoire saturée, plantage ou erreur disque) sur {m} en {fen}."),
    ]
    anomalies = []
    try:
        for cle, logql, seuil, source, gravite, titre, detail in regles:
            for s in _requete_loki(logql):
                n = float(s["value"][1])
                if n > seuil:
                    m = s["metric"].get("host", "?")
                    anomalies.append(Anomalie(
                        f"{source}:{cle}:{m}", m, source, gravite, titre.format(m=m),
                        detail.format(n=int(n), m=m, fen=fen, seuil=seuil), 0))
    except (requests.RequestException, RuntimeError, ValueError, KeyError, IndexError) as e:
        if _ETAT_LOKI["ok"]:
            print(f"Loki injoignable : détection par les journaux suspendue ({type(e).__name__})", flush=True)
        _ETAT_LOKI["ok"] = False
        return []
    if not _ETAT_LOKI["ok"]:
        print("Loki de nouveau joignable : détection par les journaux rétablie", flush=True)
    _ETAT_LOKI["ok"] = True
    return anomalies


def _sonde_ping(ip, n=5):
    """Ping actif depuis cette machine. Retourne (perte en %, latence moyenne en ms) ou None."""
    try:
        p = subprocess.run(["ping", "-c", str(n), "-i", "0.2", "-W", "1", ip],
                           capture_output=True, text=True, timeout=n * 2 + 5)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None
    perte = re.search(r"([\d.]+)% packet loss", p.stdout)
    if not perte:
        return None
    rtt = re.search(r"= [\d.]+/([\d.]+)/", p.stdout)
    return float(perte.group(1)), (float(rtt.group(1)) if rtt else None)


def collecter_anomalies(r=None):
    """Interroge Prometheus et retourne la liste des anomalies présentes à cet instant."""
    r = r or _reglages()
    anomalies = []

    for s in _requete('up{instance=~".*:9100"}'):
        if float(s["value"][1]) == 0:
            inst = s["metric"]["instance"]
            m = _machine(inst)
            anomalies.append(Anomalie(
                f"up:{inst}", m, "up", "haute",
                f"Cible de supervision injoignable sur {m}",
                f"Prometheus ne parvient plus à joindre {inst} (Node Exporter) : "
                "le service est arrêté ou la machine est inaccessible.",
                r["conf_up_s"]))

    requete_cpu = '100 - (avg by (instance) (rate(node_cpu_seconds_total{mode="idle"}[2m])) * 100)'
    for s in _requete(requete_cpu):
        v = float(s["value"][1])
        if v > r["seuil_cpu"]:
            inst = s["metric"]["instance"]
            m = _machine(inst)
            anomalies.append(Anomalie(
                f"cpu:{inst}", m, "cpu", _gravite(v), f"CPU saturé sur {m}",
                f"Utilisation CPU mesurée : {v:.1f} % (seuil : {r['seuil_cpu']:.0f} %).",
                r["conf_cpu_s"]))

    requete_ram = "(1 - node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes) * 100"
    for s in _requete(requete_ram):
        v = float(s["value"][1])
        if v > r["seuil_ram"]:
            inst = s["metric"]["instance"]
            m = _machine(inst)
            anomalies.append(Anomalie(
                f"ram:{inst}", m, "ram", _gravite(v), f"Mémoire saturée sur {m}",
                f"Utilisation mémoire mesurée : {v:.1f} % (seuil : {r['seuil_ram']:.0f} %).",
                r["conf_ram_s"]))

    filtre = f'{{fstype!~"{FS_EXCLUS}"}}'
    requete_disque = (f"(1 - node_filesystem_avail_bytes{filtre} / "
                      f"node_filesystem_size_bytes{filtre}) * 100")
    for s in _requete(requete_disque):
        v = float(s["value"][1])
        if v > r["seuil_disque"]:
            inst = s["metric"]["instance"]
            point = s["metric"].get("mountpoint", "?")
            m = _machine(inst)
            anomalies.append(Anomalie(
                f"disque:{inst}:{point}", m, "disque", _gravite(v),
                f"Disque presque plein sur {m} ({point})",
                f"Partition {point} remplie à {v:.1f} % (seuil : {r['seuil_disque']:.0f} %).",
                r["conf_disque_s"]))

    requete_services = 'node_systemd_unit_state{state="failed",name=~".+[.]service"} == 1'
    for s in _requete(requete_services):
        nom = s["metric"].get("name", "?")
        if nom in r["services_ignores"]:
            continue
        inst = s["metric"]["instance"]
        m = _machine(inst)
        anomalies.append(Anomalie(
            f"service:{inst}:{nom}", m, "service", "haute",
            f"Service {nom} en échec sur {m}",
            f"Le service {nom} est dans l'état « failed » sur {m} (arrêt anormal ou erreur au démarrage).",
            r["conf_service_s"]))

    iface = r["interfaces"]
    for s in _requete(f'node_network_up{{device=~"{iface}"}} == 0'):
        inst, dev = s["metric"]["instance"], s["metric"].get("device", "?")
        m = _machine(inst)
        anomalies.append(Anomalie(
            f"reseau:interface:{inst}:{dev}", m, "reseau", "haute",
            f"Interface réseau {dev} inactive sur {m}",
            f"L'interface {dev} de {m} n'est pas à l'état « up ».", r["conf_reseau_s"]))

    requete_pertes = (
        f'sum by (instance, device) (rate(node_network_receive_errs_total{{device=~"{iface}"}}[2m]) + '
        f'rate(node_network_transmit_errs_total{{device=~"{iface}"}}[2m]) + '
        f'rate(node_network_receive_drop_total{{device=~"{iface}"}}[2m]) + '
        f'rate(node_network_transmit_drop_total{{device=~"{iface}"}}[2m]))')
    for s in _requete(requete_pertes):
        v = float(s["value"][1])
        if v > r["seuil_pertes"]:
            inst, dev = s["metric"]["instance"], s["metric"].get("device", "?")
            m = _machine(inst)
            anomalies.append(Anomalie(
                f"reseau:erreurs:{inst}:{dev}", m, "reseau", "moyenne",
                f"Erreurs ou pertes de paquets sur l'interface {dev} de {m}",
                f"{v:.1f} paquets en erreur ou perdus par seconde sur {dev} (seuil : {r['seuil_pertes']:.0f}).",
                r["conf_reseau_s"]))

    requete_retrans = "100 * rate(node_netstat_Tcp_RetransSegs[2m]) / (rate(node_netstat_Tcp_OutSegs[2m]) > 20)"
    for s in _requete(requete_retrans):
        v = float(s["value"][1])
        if v > r["seuil_retrans"]:
            inst = s["metric"]["instance"]
            m = _machine(inst)
            anomalies.append(Anomalie(
                f"reseau:retrans:{inst}", m, "reseau", "moyenne",
                f"Retransmissions TCP élevées sur {m}",
                f"{v:.1f} % des segments TCP sont retransmis (seuil : {r['seuil_retrans']:.0f} %).",
                r["conf_reseau_s"]))

    nom_local = socket.gethostname()
    for ip, nom in config.MACHINES.items():
        if nom == nom_local:
            continue
        mesure = _sonde_ping(ip)
        if not mesure:
            continue
        perte, latence = mesure
        if r["seuil_perte_ping"] <= perte < 100:
            anomalies.append(Anomalie(
                f"reseau:perte:{ip}", nom, "reseau", "haute" if perte >= 50 else "moyenne",
                f"Perte de paquets réseau vers {nom}",
                f"Ping de {nom_local} vers {nom} ({ip}) : {perte:.0f} % de paquets perdus "
                f"(seuil : {r['seuil_perte_ping']:.0f} %).", r["conf_reseau_s"]))
        if latence is not None and latence > r["seuil_latence_ms"]:
            anomalies.append(Anomalie(
                f"reseau:latence:{ip}", nom, "reseau", "moyenne",
                f"Latence réseau élevée vers {nom}",
                f"Ping de {nom_local} vers {nom} ({ip}) : latence moyenne de {latence:.0f} ms "
                f"(seuil : {r['seuil_latence_ms']:.0f} ms).", r["conf_reseau_s"]))

    anomalies.extend(_anomalies_loki(r))

    return anomalies


class Detecteur:
    def __init__(self, collecteur=None, reglages=None):
        self.r = {**_reglages(), **(reglages or {})}
        self.collecteur = collecteur or (lambda: collecter_anomalies(self.r))
        self.compteurs = {}
        self.presentes = None

    def _en_pause(self, empreinte):
        """Après un refus ou un échec, on n'ouvre pas immédiatement un nouvel incident."""
        dernier = db.dernier_incident_par_empreinte(empreinte)
        if not dernier or dernier["statut"] not in ("refuse", "echec_escalade"):
            return False
        ecoule = (datetime.now(timezone.utc) - datetime.fromisoformat(dernier["mis_a_jour_le"])).total_seconds()
        limite = self.r["cooldown_escalade_s"] if dernier["statut"] == "echec_escalade" else self.r["cooldown_s"]
        return ecoule < limite

    def cycle(self):
        """Un passage de détection. Retourne la liste des incidents ouverts pendant ce passage."""
        anomalies = self.collecteur()
        presentes = {a.empreinte for a in anomalies}
        self.presentes = presentes

        for empreinte in list(self.compteurs):
            if empreinte not in presentes:
                del self.compteurs[empreinte]

        for incident in db.lister_incidents(statut="ouvert"):
            if incident["empreinte"] not in presentes:
                db.changer_statut(incident["id"], "resolu",
                                  "Le problème a disparu de lui-même avant toute intervention", "resolu")

        ouverts = []
        for a in anomalies:
            self.compteurs[a.empreinte] = self.compteurs.get(a.empreinte, 0) + 1
            requis = max(1, math.ceil(a.confirmation_s / self.r["intervalle"]))
            if self.compteurs[a.empreinte] < requis:
                continue
            if db.incident_actif_par_empreinte(a.empreinte) or self._en_pause(a.empreinte):
                continue
            incident_id = db.creer_incident(a.titre, a.machine, a.source, a.gravite, a.empreinte)
            db.ajouter_evenement(incident_id, "mesure", a.detail)
            ouverts.append(incident_id)
        return ouverts


def main():
    parser = argparse.ArgumentParser(description="Détecteurs d'incidents (sans IA)")
    parser.add_argument("--une-fois", action="store_true", help="un seul passage puis arrêt")
    args = parser.parse_args()

    db.init_db()
    detecteur = Detecteur()
    r = detecteur.r
    print(f"Détection démarrée : Prometheus {config.PROMETHEUS_URL}, passage toutes les {r['intervalle']} s. "
          "Ctrl+C pour arrêter.", flush=True)
    try:
        while True:
            heure = formater_local(maintenant_utc(), avec_date=False)
            try:
                ouverts = detecteur.cycle()
                print(f"[{heure}] anomalies en observation : {len(detecteur.compteurs)} | "
                      f"incidents ouverts : {', '.join(ouverts) if ouverts else 'aucun'}", flush=True)
            except (requests.RequestException, RuntimeError) as e:
                print(f"[{heure}] Prometheus injoignable ou réponse invalide : {e}", flush=True)
            if args.une_fois:
                break
            time.sleep(r["intervalle"])
    except KeyboardInterrupt:
        print("\nDétection arrêtée.")


if __name__ == "__main__":
    main()
