"""Outil en ligne de commande pour décider des corrections en attente (en attendant l'interface web)."""
import sys

from aiops import agent2, db


def main():
    db.init_db()
    args = sys.argv[1:]
    if not args or args[0] == "liste":
        with db.connexion() as c:
            lignes = c.execute(
                "SELECT p.*, i.titre FROM propositions p JOIN incidents i ON i.id = p.incident_id "
                "WHERE p.statut = 'en_attente' ORDER BY p.cree_le").fetchall()
        if not lignes:
            print("Aucune correction en attente.")
            return
        for r in lignes:
            print("=" * 64)
            print(f"Proposition {r['id']} | incident {r['incident_id']} | {r['titre']}")
            print(f"Machine : {r['machine']} | type : {r['type']} | risque : {r['risque']} | "
                  f"sudo : {'OUI' if r['sudo_requis'] else 'non'}")
            print(f"Justification : {r['justification']}\n{'-' * 64}\n{r['contenu']}")
    elif args[0] == "approuver" and len(args) == 2:
        agent2.approuver(args[1])
        print("Correction approuvée : l'orchestrateur va l'exécuter.")
    elif args[0] == "refuser" and len(args) == 2:
        agent2.refuser(args[1])
        print("Correction refusée.")
    else:
        print("Usage : python -m aiops.decision [liste | approuver ID | refuser ID]")


if __name__ == "__main__":
    main()
