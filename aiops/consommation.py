"""Rapport de consommation de l'IA : appels et tokens du jour, par incident."""
from aiops import db, temps


def main():
    db.init_db()
    print(f"Aujourd'hui : {db.nombre_appels_ia_aujourdhui()} appels, {db.tokens_ia_aujourdhui()} tokens")
    par_incident = {}
    with db.connexion() as c:
        lignes = c.execute("SELECT objet, tokens FROM appels_ia WHERE horodatage >= ?",
                           (temps.debut_jour_utc(),)).fetchall()
    for ligne in lignes:
        mots = (ligne["objet"] or "").split()
        cle = mots[1] if len(mots) > 1 else (ligne["objet"] or "autre")
        n, t = par_incident.get(cle, (0, 0))
        par_incident[cle] = (n + 1, t + ligne["tokens"])
    for incident, (n, t) in sorted(par_incident.items(), key=lambda x: -x[1][1])[:10]:
        print(f"  {incident:<12} {n:>3} appels  {t:>7} tokens")


if __name__ == "__main__":
    main()
