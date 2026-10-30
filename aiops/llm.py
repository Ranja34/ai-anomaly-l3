"""Client IA économe : Groq / Ollama (API compatible OpenAI) ou faux modèle (mock)."""
import json
import os
import re
import time
from datetime import datetime, timezone

import requests

from aiops import config  # noqa: F401  (charge le fichier .env)
from aiops import db


class LLMErreur(Exception):
    """Erreur lors d'un appel au modèle."""


class QuotaDepasse(LLMErreur):
    """Limite d'appels atteinte (locale ou côté fournisseur)."""


CONSIGNE_REPONSE = "\n\nRéponds directement par l'objet JSON dans le contenu de ton message. N'appelle aucun outil ni aucune fonction."


def _recuperer_appel_outil(rep):
    """Quand le modèle tente un « appel d'outil », Groq refuse (HTTP 400) mais renvoie sa génération :
    la réponse JSON voulue s'y trouve souvent. Retourne ce dictionnaire, ou None si inutilisable."""
    try:
        generation = rep.json()["error"]["failed_generation"]
    except (ValueError, KeyError, TypeError):
        return None
    try:
        donnees = extraire_json(generation) if isinstance(generation, str) else generation
    except LLMErreur:
        return None
    if not isinstance(donnees, dict):
        return None
    arguments = donnees.get("arguments")
    if isinstance(arguments, str):
        try:
            arguments = json.loads(arguments)
        except ValueError:
            return None
    if isinstance(arguments, dict) and any(c in arguments for c in ("action", "resume", "type", "contenu")):
        return arguments
    return None


def _reglages():
    return {
        "fournisseur": os.getenv("LLM_PROVIDER", "mock").lower(),
        "modele": os.getenv("LLM_MODEL", "openai/gpt-oss-20b"),
        "url": os.getenv("LLM_BASE_URL", "https://api.groq.com/openai/v1").rstrip("/"),
        "cle": os.getenv("GROQ_API_KEY", ""),
        "max_appels_jour": int(os.getenv("LLM_MAX_APPELS_JOUR", "60")),
        "max_appels_heure": int(os.getenv("LLM_MAX_APPELS_HEURE", "20")),
        "intervalle_min": float(os.getenv("LLM_INTERVALLE_MIN_S", "5")),
        "max_tokens": int(os.getenv("LLM_MAX_TOKENS", "2500")),
        "tentatives": int(os.getenv("LLM_TENTATIVES", "2")),
        "effort": os.getenv("LLM_REASONING_EFFORT", "low"),
        "timeout": int(os.getenv("LLM_TIMEOUT_S", "90")),
        "mode_json": os.getenv("LLM_JSON_MODE", "false").lower() in ("1", "true", "oui"),
    }


def extraire_json(texte):
    """Extrait un objet JSON d'une réponse, même entourée de texte ou de ```."""
    texte = (texte or "").strip()
    texte = re.sub(r"^```(?:json)?\s*|\s*```$", "", texte, flags=re.IGNORECASE)
    try:
        return json.loads(texte)
    except json.JSONDecodeError:
        pass
    debut, fin = texte.find("{"), texte.rfind("}")
    if debut != -1 and fin > debut:
        try:
            return json.loads(texte[debut:fin + 1])
        except json.JSONDecodeError:
            pass
    raise LLMErreur("Réponse IA invalide : JSON introuvable ou tronqué")


def _attendre_intervalle(minimum):
    dernier = db.dernier_appel_ia()
    if not dernier:
        return
    ecoule = (datetime.now(timezone.utc) - datetime.fromisoformat(dernier)).total_seconds()
    if ecoule < minimum:
        time.sleep(minimum - ecoule)


def demander_json(systeme, utilisateur, objet="", reponse_mock=None):
    """Interroge le modèle et retourne un dict. Lève LLMErreur ou QuotaDepasse."""
    r = _reglages()
    if r["fournisseur"] == "mock":
        return reponse_mock if reponse_mock is not None else {"mock": True}
    if r["fournisseur"] == "groq" and not r["cle"]:
        raise LLMErreur("GROQ_API_KEY absente du fichier .env")

    entetes = {"Content-Type": "application/json"}
    if r["cle"]:
        entetes["Authorization"] = f"Bearer {r['cle']}"
    corps = {
        "model": r["modele"],
        "messages": [
            {"role": "system", "content": systeme + CONSIGNE_REPONSE},
            {"role": "user", "content": utilisateur},
        ],
        "temperature": 0.2,
        "max_tokens": r["max_tokens"],
    }
    if r["mode_json"]:
        corps["response_format"] = {"type": "json_object"}
    if r["fournisseur"] == "groq" and "gpt-oss" in r["modele"] and r["effort"]:
        corps["reasoning_effort"] = r["effort"]

    f, m = r["fournisseur"], r["modele"]
    derniere_erreur = "aucune"
    for essai in range(1, r["tentatives"] + 2):
        if db.nombre_appels_ia_aujourdhui() >= r["max_appels_jour"]:
            raise QuotaDepasse(f"Limite locale de {r['max_appels_jour']} appels IA par jour atteinte")
        if db.nombre_appels_ia_depuis(60) >= r["max_appels_heure"]:
            raise QuotaDepasse(f"Limite de {r['max_appels_heure']} appels IA par heure atteinte")
        _attendre_intervalle(r["intervalle_min"])

        try:
            rep = requests.post(f"{r['url']}/chat/completions", headers=entetes,
                                json=corps, timeout=r["timeout"])
        except requests.RequestException as e:
            derniere_erreur = f"erreur réseau ({type(e).__name__})"
            db.enregistrer_appel_ia(f, m, objet, False, derniere_erreur)
            time.sleep(2 * essai)
            continue

        if rep.status_code == 429:
            db.enregistrer_appel_ia(f, m, objet, False, "429 limite du fournisseur")
            raise QuotaDepasse("Limite du fournisseur atteinte (HTTP 429)")
        if rep.status_code >= 500:
            derniere_erreur = f"HTTP {rep.status_code}"
            db.enregistrer_appel_ia(f, m, objet, False, derniere_erreur)
            time.sleep(2 * essai)
            continue
        if rep.status_code == 400 and "tool_use_failed" in rep.text:
            recupere = _recuperer_appel_outil(rep)
            if recupere is not None:
                db.enregistrer_appel_ia(f, m, objet, True)
                return recupere
            derniere_erreur = "le modèle a tenté d'appeler un outil"
            db.enregistrer_appel_ia(f, m, objet, False, derniere_erreur)
            continue
        if rep.status_code != 200:
            db.enregistrer_appel_ia(f, m, objet, False, f"HTTP {rep.status_code}")
            raise LLMErreur(f"Erreur HTTP {rep.status_code} : {rep.text[:300]}")

        try:
            choix = rep.json()["choices"][0]
            texte = choix["message"].get("content") or ""
            fin = choix.get("finish_reason")
        except (ValueError, KeyError, IndexError):
            db.enregistrer_appel_ia(f, m, objet, False, "format de réponse inattendu")
            raise LLMErreur("Format de réponse inattendu du fournisseur")

        if fin == "length":
            db.enregistrer_appel_ia(f, m, objet, False, "réponse tronquée")
            raise LLMErreur("Réponse tronquée : augmenter LLM_MAX_TOKENS")

        try:
            donnees = extraire_json(texte)
        except LLMErreur as e:
            derniere_erreur = str(e)
            db.enregistrer_appel_ia(f, m, objet, False, derniere_erreur)
            continue

        db.enregistrer_appel_ia(f, m, objet, True)
        return donnees

    raise LLMErreur(f"Échec après {r['tentatives'] + 1} tentatives : {derniere_erreur}")


if __name__ == "__main__":
    db.init_db()
    r = _reglages()
    print(f"Fournisseur : {r['fournisseur']} | modèle : {r['modele']}")
    print(f"Appels IA aujourd'hui : {db.nombre_appels_ia_aujourdhui()} / {r['max_appels_jour']}")
    print("Réponse :", demander_json(
        "Tu réponds uniquement en JSON.",
        'Réponds exactement avec {"statut": "ok", "message": "bonjour"}',
        "test de connexion",
    ))
