"""Réglages centraux du projet."""
import os
from pathlib import Path

from dotenv import load_dotenv

RACINE = Path(__file__).resolve().parent.parent
load_dotenv(RACINE / ".env")

DB_PATH = Path(os.getenv("AIOPS_DB", RACINE / "data" / "aiops.db"))
FUSEAU = os.getenv("AIOPS_FUSEAU", "Indian/Antananarivo")
