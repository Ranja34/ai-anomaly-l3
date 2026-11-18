"""Détecteurs simples (sans IA) : interrogent Prometheus et ouvrent des incidents confirmés."""
import argparse
import math
import os
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

    return anomalies


class Detecteur:
    def __init__(self, collecteur=None, reglages=None):
        self.r = {**_reglages(), **(reglages or {})}
        self.collecteur = collecteur or (lambda: collecter_anomalies(self.r))
        self.compteurs = {}

    def _en_pause(self, empreinte):
        """Après un refus ou un échec, on n'ouvre pas immédiatement un nouvel incident."""
        dernier = db.dernier_incident_par_empreinte(empreinte)
        if not dernier or dernier["statut"] not in ("refuse", "echec_escalade"):
            return False
        ecoule = (datetime.now(timezone.utc) - datetime.fromisoformat(dernier["mis_a_jour_le"])).total_seconds()
        return ecoule < self.r["cooldown_s"]

    def cycle(self):
        """Un passage de détection. Retourne la liste des incidents ouverts pendant ce passage."""
        anomalies = self.collecteur()
        presentes = {a.empreinte for a in anomalies}

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
