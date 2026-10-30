"""Base SQLite : incidents, chronologie, propositions et compteur d'appels IA."""
import json
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

from aiops import config
from aiops.temps import debut_jour_utc, maintenant_utc

DB_PATH = config.DB_PATH

# Un incident dans l'un de ces statuts est terminé et peut être supprimé.
STATUTS_FINAUX = ("resolu", "refuse", "echec_escalade")

SCHEMA = """
CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY,
    titre TEXT NOT NULL,
    machine TEXT NOT NULL,
    source TEXT NOT NULL,
    gravite TEXT NOT NULL DEFAULT 'moyenne',
    statut TEXT NOT NULL DEFAULT 'ouvert',
    empreinte TEXT NOT NULL,
    resume TEXT,
    cause_probable TEXT,
    tentatives INTEGER NOT NULL DEFAULT 0,
    cree_le TEXT NOT NULL,
    mis_a_jour_le TEXT NOT NULL,
    resolu_le TEXT
);
CREATE INDEX IF NOT EXISTS idx_incidents_empreinte ON incidents(empreinte, statut);

CREATE TABLE IF NOT EXISTS evenements (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    horodatage TEXT NOT NULL,
    type TEXT NOT NULL,
    message TEXT NOT NULL,
    details TEXT
);
CREATE INDEX IF NOT EXISTS idx_evenements_incident ON evenements(incident_id, horodatage);

CREATE TABLE IF NOT EXISTS propositions (
    id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    tentative INTEGER NOT NULL,
    machine TEXT NOT NULL,
    type TEXT NOT NULL,
    contenu TEXT NOT NULL,
    sudo_requis INTEGER NOT NULL DEFAULT 0,
    justification TEXT,
    risque TEXT,
    statut TEXT NOT NULL DEFAULT 'en_attente',
    cree_le TEXT NOT NULL,
    decide_le TEXT,
    code_retour INTEGER,
    sortie TEXT
);

CREATE TABLE IF NOT EXISTS appels_ia (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    horodatage TEXT NOT NULL,
    fournisseur TEXT NOT NULL,
    modele TEXT NOT NULL,
    objet TEXT,
    succes INTEGER NOT NULL,
    erreur TEXT
);
"""

CHAMPS_MODIFIABLES = ("gravite", "resume", "cause_probable", "tentatives", "titre")


@contextmanager
def connexion():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


SCHEMA_ETAT = """
CREATE TABLE IF NOT EXISTS etat (
    cle TEXT PRIMARY KEY,
    valeur TEXT NOT NULL,
    mis_a_jour_le TEXT NOT NULL
);
"""


def init_db():
    with connexion() as c:
        c.executescript(SCHEMA)
        c.executescript(SCHEMA_ETAT)


def _ajouter_evenement(c, incident_id, type_evenement, message, details=None):
    c.execute(
        "INSERT INTO evenements (incident_id, horodatage, type, message, details) VALUES (?, ?, ?, ?, ?)",
        (incident_id, maintenant_utc(), type_evenement, message,
         json.dumps(details, ensure_ascii=False) if details is not None else None),
    )


def ajouter_evenement(incident_id, type_evenement, message, details=None):
    with connexion() as c:
        _ajouter_evenement(c, incident_id, type_evenement, message, details)


# ---------- Incidents ----------

def creer_incident(titre, machine, source, gravite, empreinte):
    incident_id = uuid.uuid4().hex[:8]
    now = maintenant_utc()
    with connexion() as c:
        c.execute(
            "INSERT INTO incidents (id, titre, machine, source, gravite, statut, empreinte, cree_le, mis_a_jour_le) "
            "VALUES (?, ?, ?, ?, ?, 'ouvert', ?, ?, ?)",
            (incident_id, titre, machine, source, gravite, empreinte, now, now),
        )
        _ajouter_evenement(c, incident_id, "detecte", f"Incident détecté sur {machine} : {titre}")
    return incident_id


def incident_actif_par_empreinte(empreinte):
    marqueurs = ",".join("?" * len(STATUTS_FINAUX))
    with connexion() as c:
        ligne = c.execute(
            f"SELECT * FROM incidents WHERE empreinte = ? AND statut NOT IN ({marqueurs}) "
            "ORDER BY cree_le DESC LIMIT 1",
            (empreinte, *STATUTS_FINAUX),
        ).fetchone()
    return dict(ligne) if ligne else None


def changer_statut(incident_id, statut, message=None, type_evenement="info", details=None):
    now = maintenant_utc()
    with connexion() as c:
        c.execute(
            "UPDATE incidents SET statut = ?, mis_a_jour_le = ?, "
            "resolu_le = CASE WHEN ? = 'resolu' THEN ? ELSE resolu_le END WHERE id = ?",
            (statut, now, statut, now, incident_id),
        )
        if message:
            _ajouter_evenement(c, incident_id, type_evenement, message, details)


def mettre_a_jour_incident(incident_id, **champs):
    champs = {k: v for k, v in champs.items() if k in CHAMPS_MODIFIABLES}
    if not champs:
        return
    colonnes = ", ".join(f"{k} = ?" for k in champs)
    with connexion() as c:
        c.execute(
            f"UPDATE incidents SET {colonnes}, mis_a_jour_le = ? WHERE id = ?",
            (*champs.values(), maintenant_utc(), incident_id),
        )


def get_incident(incident_id):
    with connexion() as c:
        incident = c.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
        if not incident:
            return None
        resultat = dict(incident)
        resultat["evenements"] = [dict(r) for r in c.execute(
            "SELECT * FROM evenements WHERE incident_id = ? ORDER BY horodatage, id", (incident_id,))]
        resultat["propositions"] = [dict(r) for r in c.execute(
            "SELECT * FROM propositions WHERE incident_id = ? ORDER BY tentative", (incident_id,))]
    return resultat


def lister_incidents(statut=None, limite=200):
    requete = "SELECT * FROM incidents"
    params = []
    if statut:
        requete += " WHERE statut = ?"
        params.append(statut)
    requete += " ORDER BY cree_le DESC LIMIT ?"
    params.append(limite)
    with connexion() as c:
        return [dict(r) for r in c.execute(requete, params)]


# ---------- Suppression de l'historique ----------

def supprimer_incident(incident_id):
    """Supprime un incident terminé. Refuse si l'incident est encore en cours."""
    marqueurs = ",".join("?" * len(STATUTS_FINAUX))
    with connexion() as c:
        curseur = c.execute(
            f"DELETE FROM incidents WHERE id = ? AND statut IN ({marqueurs})",
            (incident_id, *STATUTS_FINAUX),
        )
        return curseur.rowcount > 0


def supprimer_historique():
    """Supprime tous les incidents terminés. Retourne le nombre supprimé."""
    marqueurs = ",".join("?" * len(STATUTS_FINAUX))
    with connexion() as c:
        curseur = c.execute(f"DELETE FROM incidents WHERE statut IN ({marqueurs})", STATUTS_FINAUX)
        return curseur.rowcount


# ---------- Compteur d'appels IA (jamais effacé par la suppression de l'historique) ----------

def enregistrer_appel_ia(fournisseur, modele, objet, succes, erreur=None):
    with connexion() as c:
        c.execute(
            "INSERT INTO appels_ia (horodatage, fournisseur, modele, objet, succes, erreur) VALUES (?, ?, ?, ?, ?, ?)",
            (maintenant_utc(), fournisseur, modele, objet, 1 if succes else 0, erreur),
        )


def nombre_appels_ia_aujourdhui():
    with connexion() as c:
        return c.execute("SELECT COUNT(*) FROM appels_ia WHERE horodatage >= ?", (debut_jour_utc(),)).fetchone()[0]


def dernier_appel_ia():
    with connexion() as c:
        ligne = c.execute("SELECT horodatage FROM appels_ia ORDER BY id DESC LIMIT 1").fetchone()
    return ligne[0] if ligne else None


def dernier_incident_par_empreinte(empreinte):
    with connexion() as c:
        ligne = c.execute(
            "SELECT * FROM incidents WHERE empreinte = ? ORDER BY cree_le DESC LIMIT 1", (empreinte,)
        ).fetchone()
    return dict(ligne) if ligne else None


# ---------- Propositions de correction ----------

CHAMPS_PROPOSITION = ("statut", "decide_le", "code_retour", "sortie")


def creer_proposition(incident_id, tentative, machine, type_, contenu, sudo_requis, justification, risque):
    proposition_id = uuid.uuid4().hex[:8]
    with connexion() as c:
        c.execute(
            "INSERT INTO propositions (id, incident_id, tentative, machine, type, contenu, sudo_requis, "
            "justification, risque, statut, cree_le) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'en_attente', ?)",
            (proposition_id, incident_id, tentative, machine, type_, contenu,
             1 if sudo_requis else 0, justification, risque, maintenant_utc()),
        )
    return proposition_id


def get_proposition(proposition_id):
    with connexion() as c:
        ligne = c.execute("SELECT * FROM propositions WHERE id = ?", (proposition_id,)).fetchone()
    return dict(ligne) if ligne else None


def decider_proposition(proposition_id, statut):
    """Passe une proposition 'en_attente' à 'approuvee' ou 'refusee'. Retourne False si déjà traitée."""
    with connexion() as c:
        curseur = c.execute(
            "UPDATE propositions SET statut = ?, decide_le = ? WHERE id = ? AND statut = 'en_attente'",
            (statut, maintenant_utc(), proposition_id),
        )
        return curseur.rowcount > 0


def mettre_a_jour_proposition(proposition_id, **champs):
    champs = {k: v for k, v in champs.items() if k in CHAMPS_PROPOSITION}
    if not champs:
        return
    colonnes = ", ".join(f"{k} = ?" for k in champs)
    with connexion() as c:
        c.execute(f"UPDATE propositions SET {colonnes} WHERE id = ?", (*champs.values(), proposition_id))


# ---------- Fonctions pour l'orchestrateur ----------

def set_etat(cle, valeur):
    with connexion() as c:
        c.execute(
            "INSERT INTO etat (cle, valeur, mis_a_jour_le) VALUES (?, ?, ?) "
            "ON CONFLICT(cle) DO UPDATE SET valeur = excluded.valeur, mis_a_jour_le = excluded.mis_a_jour_le",
            (cle, str(valeur), maintenant_utc()),
        )


def get_etat(cle):
    with connexion() as c:
        ligne = c.execute("SELECT valeur, mis_a_jour_le FROM etat WHERE cle = ?", (cle,)).fetchone()
    return dict(ligne) if ligne else None


def propositions_par_statut(statut):
    with connexion() as c:
        return [dict(r) for r in c.execute(
            "SELECT * FROM propositions WHERE statut = ? ORDER BY cree_le", (statut,))]


def demarrer_execution(proposition_id):
    """Passe 'approuvee' à 'en_cours'. Retourne False si déjà prise en charge (évite une double exécution)."""
    with connexion() as c:
        curseur = c.execute(
            "UPDATE propositions SET statut = 'en_cours' WHERE id = ? AND statut = 'approuvee'", (proposition_id,))
        return curseur.rowcount > 0


def annuler_propositions_en_attente(incident_id):
    with connexion() as c:
        c.execute(
            "UPDATE propositions SET statut = 'annulee', decide_le = ? WHERE incident_id = ? AND statut = 'en_attente'",
            (maintenant_utc(), incident_id))


def nombre_appels_ia_depuis(minutes):
    limite = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat(timespec="seconds")
    with connexion() as c:
        return c.execute("SELECT COUNT(*) FROM appels_ia WHERE horodatage >= ?", (limite,)).fetchone()[0]


def compter_evenements(incident_id, type_evenement):
    with connexion() as c:
        return c.execute("SELECT COUNT(*) FROM evenements WHERE incident_id = ? AND type = ?",
                         (incident_id, type_evenement)).fetchone()[0]
