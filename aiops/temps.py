"""Gestion des heures : stockage en UTC, affichage en heure locale."""
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from aiops import config


def maintenant_utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def debut_jour_utc() -> str:
    maintenant = datetime.now(timezone.utc)
    return maintenant.replace(hour=0, minute=0, second=0, microsecond=0).isoformat(timespec="seconds")


def formater_local(iso: str | None, avec_date: bool = True) -> str:
    if not iso:
        return ""
    dt = datetime.fromisoformat(iso).astimezone(ZoneInfo(config.FUSEAU))
    return dt.strftime("%d/%m/%Y %H:%M:%S" if avec_date else "%H:%M:%S")
