"""Interface web en français : incidents en direct, décisions, historique."""
import json
import os
import uuid
from datetime import datetime, timezone

from flask import Flask, jsonify, request

from aiops import agent2, config, db, llm, validation
from aiops.temps import formater_local

app = Flask(__name__, static_folder="static", static_url_path="/static")
app.json.ensure_ascii = False

LIBELLES = {
    "ouvert": "Détecté", "diagnostic_en_cours": "Enquête en cours", "diagnostique": "Diagnostiqué",
    "redaction_correction": "Rédaction de la correction", "attente_approbation": "En attente de votre décision",
    "approuve": "Approuvée, exécution imminente", "execution": "Exécution en cours",
    "verification": "Vérification en cours", "verification_manuelle": "À vérifier par vous",
    "nouvelle_tentative": "Nouvelle tentative", "resolu": "Résolu", "refuse": "Refusé",
    "echec_escalade": "Échec : intervention humaine",
}
CLASSES = {
    "attente_approbation": "attente", "verification_manuelle": "attente", "nouvelle_tentative": "warn",
    "resolu": "ok", "refuse": "neutre", "echec_escalade": "bad",
}
GRAVITES = ("faible", "moyenne", "haute", "critique")


def _secondes(debut, fin):
    try:
        return int((datetime.fromisoformat(fin) - datetime.fromisoformat(debut)).total_seconds())
    except (TypeError, ValueError):
        return None


def _duree(secondes):
    minutes, reste = divmod(secondes, 60)
    return f"{minutes} min {reste} s" if minutes else f"{reste} s"


def _resume(i, a_proposition):
    secondes = _secondes(i["cree_le"], i["resolu_le"]) if i.get("resolu_le") else None
    return {
        "id": i["id"], "titre": i["titre"], "machine": i["machine"], "source": i["source"],
        "gravite": i["gravite"], "statut": i["statut"], "statut_libelle": LIBELLES.get(i["statut"], i["statut"]),
        "classe": CLASSES.get(i["statut"], "info"), "finale": i["statut"] in db.STATUTS_FINAUX,
        "tentatives": i["tentatives"], "cree_le": formater_local(i["cree_le"]),
        "a_decision": a_proposition or i["statut"] == "verification_manuelle",
        "duree": f"résolu en {_duree(secondes)}" if secondes is not None else "",
    }


def _details_txt(evenement):
    brut = evenement.get("details")
    if not brut:
        return ""
    try:
        d = json.loads(brut)
    except ValueError:
        return str(brut)[:3000]
    if isinstance(d, dict) and d.get("preuves") and isinstance(d["preuves"][0], dict):
        return "\n\n".join(f"$ {p.get('commande')}  [{p.get('machine')}]\n{p.get('sortie', '')}"
                           for p in d["preuves"])[:6000]
    if isinstance(d, dict) and "sortie" in d:
        return str(d["sortie"])[:6000]
    return json.dumps(d, ensure_ascii=False, indent=2)[:3000]


def _ok():
    return jsonify({"ok": True})


def _action(fonction, *args):
    try:
        fonction(*args)
    except ValueError as e:
        return jsonify({"erreur": str(e)}), 409
    return _ok()


@app.get("/")
def accueil():
    return app.send_static_file("index.html")


@app.get("/api/etat")
def api_etat():
    battement = db.get_etat("battement")
    prometheus = db.get_etat("prometheus")
    age = None
    if battement:
        age = int((datetime.now(timezone.utc) - datetime.fromisoformat(battement["mis_a_jour_le"])).total_seconds())
    r = llm._reglages()
    incidents = db.lister_incidents(limite=500)
    attente = {p["incident_id"] for p in db.propositions_par_statut("en_attente")}
    return jsonify({
        "orchestrateur_ok": age is not None and age < 300, "age_battement": age,
        "prometheus": prometheus["valeur"] if prometheus else None,
        "fournisseur": r["fournisseur"], "modele": r["modele"],
        "appels_jour": db.nombre_appels_ia_aujourdhui(), "max_jour": r["max_appels_jour"],
        "tokens_jour": db.tokens_ia_aujourdhui(), "mode_validation": validation.mode(),
        "actifs": sum(1 for i in incidents if i["statut"] not in db.STATUTS_FINAUX),
        "a_decider": sum(1 for i in incidents if i["id"] in attente or i["statut"] == "verification_manuelle"),
        "machines": sorted(config.ADRESSES),
    })


@app.get("/api/incidents")
def api_incidents():
    attente = {p["incident_id"] for p in db.propositions_par_statut("en_attente")}
    return jsonify([_resume(i, i["id"] in attente) for i in db.lister_incidents(limite=300)])


@app.get("/api/incidents/<incident_id>")
def api_incident(incident_id):
    inc = db.get_incident(incident_id)
    if not inc:
        return jsonify({"erreur": "Incident introuvable"}), 404
    diagnostic = None
    for e in reversed(inc["evenements"]):
        if e["type"] == "diagnostic" and e.get("details"):
            try:
                diagnostic = json.loads(e["details"])
            except ValueError:
                pass
            break
    propositions = []
    for p in inc["propositions"]:
        propositions.append({
            "id": p["id"], "tentative": p["tentative"], "machine": p["machine"], "type": p["type"],
            "contenu": p["contenu"], "sudo_requis": bool(p["sudo_requis"]), "justification": p["justification"],
            "risque": p["risque"], "statut": p["statut"], "code_retour": p["code_retour"],
            "sortie": p["sortie"] or "", "cree_le": formater_local(p["cree_le"], False)})
    resume = _resume(inc, any(p["statut"] == "en_attente" for p in propositions))
    resume.update({
        "resume": inc["resume"], "cause_probable": inc["cause_probable"],
        "max_tentatives": agent2._max_tentatives(), "diagnostic": diagnostic, "propositions": propositions,
        "proposition_attente": next((p for p in propositions if p["statut"] == "en_attente"), None),
        "evenements": [{"id": e["id"], "heure": formater_local(e["horodatage"], False), "type": e["type"],
                        "message": e["message"], "details": _details_txt(e)} for e in inc["evenements"]],
    })
    return jsonify(resume)


@app.post("/api/propositions/<proposition_id>/approuver")
def api_approuver(proposition_id):
    return _action(agent2.approuver, proposition_id)


@app.post("/api/propositions/<proposition_id>/refuser")
def api_refuser(proposition_id):
    return _action(agent2.refuser, proposition_id)


@app.post("/api/incidents/signaler")
def api_signaler():
    d = request.get_json(silent=True) or {}
    description = str(d.get("description", "")).strip()
    if len(description) < 5:
        return jsonify({"erreur": "Décrivez le problème (5 caractères minimum)"}), 400
    machine = d.get("machine")
    if machine not in config.ADRESSES:
        return jsonify({"erreur": "Machine inconnue"}), 400
    gravite = d.get("gravite") if d.get("gravite") in GRAVITES else "moyenne"
    titre = description.splitlines()[0][:90]
    incident_id = db.creer_incident(titre, machine, "manuel", gravite, f"manuel:{uuid.uuid4().hex[:8]}")
    db.ajouter_evenement(incident_id, "signalement", f"Signalé par l'administrateur : {description[:800]}")
    return jsonify({"id": incident_id})


@app.post("/api/incidents/<incident_id>/confirmer")
def api_confirmer(incident_id):
    inc = db.get_incident(incident_id)
    if not inc or inc["statut"] != "verification_manuelle":
        return jsonify({"erreur": "Cet incident n'attend pas de confirmation"}), 409
    db.changer_statut(incident_id, "resolu", "Résolution confirmée par l'administrateur", "resolu")
    return _ok()


@app.post("/api/incidents/<incident_id>/infirmer")
def api_infirmer(incident_id):
    inc = db.get_incident(incident_id)
    if not inc or inc["statut"] != "verification_manuelle":
        return jsonify({"erreur": "Cet incident n'attend pas de confirmation"}), 409
    maxi = agent2._max_tentatives()
    if inc["tentatives"] >= maxi:
        db.changer_statut(incident_id, "echec_escalade",
                          f"Le problème persiste après {maxi} tentatives (constat de l'administrateur). "
                          "Intervention humaine requise.", "escalade")
    else:
        db.changer_statut(incident_id, "nouvelle_tentative",
                          "Le problème persiste selon l'administrateur : nouvelle analyse en cours", "echec")
    return _ok()


@app.post("/api/incidents/<incident_id>/relancer")
def api_relancer(incident_id):
    inc = db.get_incident(incident_id)
    if not inc or inc["statut"] != "echec_escalade":
        return jsonify({"erreur": "Seul un incident en échec peut être relancé"}), 409
    db.mettre_a_jour_incident(incident_id, tentatives=0)
    db.changer_statut(incident_id, "ouvert", "Relancé par l'administrateur : nouvelle analyse complète", "info")
    return _ok()


@app.delete("/api/incidents/<incident_id>")
def api_supprimer(incident_id):
    if db.supprimer_incident(incident_id):
        return _ok()
    return jsonify({"erreur": "Impossible : incident introuvable ou encore en cours"}), 409


@app.post("/api/historique/supprimer")
def api_historique_supprimer():
    d = request.get_json(silent=True) or {}
    if d.get("tout"):
        n = db.supprimer_historique()
    else:
        n = sum(1 for i in d.get("ids", []) if db.supprimer_incident(str(i)))
    return jsonify({"supprimes": n})


def main():
    db.init_db()
    app.run(host=os.getenv("WEB_HOST", "0.0.0.0"), port=int(os.getenv("WEB_PORT", "5000")),
            threaded=True, debug=False)


if __name__ == "__main__":
    main()
