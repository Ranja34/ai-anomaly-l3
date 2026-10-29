import json
import sys
from pathlib import Path

from src.agent2_resolver import prepare_correction

BASE_DIR = Path(__file__).resolve().parent.parent
DIAGNOSIS_FILE = BASE_DIR / "data" / "agent1" / "latest_diagnosis.json"


def main():
    if len(sys.argv) > 1:
        diagnosis_path = Path(sys.argv[1]).resolve()
    else:
        diagnosis_path = DIAGNOSIS_FILE.resolve()

    if not diagnosis_path.is_file():
        print(f"Diagnostic introuvable : {diagnosis_path}")
        print("Fournis le chemin d'un fichier JSON produit par l'Agent 1.")
        sys.exit(1)

    try:
        diagnosis_json = diagnosis_path.read_text(encoding="utf-8")
        json.loads(diagnosis_json)
        proposal = prepare_correction(diagnosis_json)
    except Exception as exc:
        print(f"Préparation de la correction impossible : {exc}")
        sys.exit(1)

    print("\n=== Proposition de l'Agent IA 2 ===")
    print(json.dumps(proposal, ensure_ascii=False, indent=2))
    print("\nStatut : en attente de validation humaine.")
    print("Aucune commande n'a été exécutée.")


if __name__ == "__main__":
    main()
