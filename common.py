"""
common.py

Kleine Helferlein, die sowohl generate_sample_data.py als auch
detect_portscan.py brauchen (CSV einlesen, Trennlinien fuers Terminal).
Damit steht das nicht in beiden Scripts doppelt.
"""

from __future__ import annotations

import csv
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
DATA_DIR = PROJECT_ROOT / "data"


def load_csv(filename: str) -> list[dict]:
    """Liest eine CSV-Datei aus data/ ein und gibt eine Liste von dicts zurueck.

    Ist die Datei nicht da, kommt eine verstaendliche Fehlermeldung statt
    eines Python-Tracebacks. Meistens heisst das: erst generate_sample_data.py
    laufen lassen.
    """
    path = DATA_DIR / filename
    if not path.exists():
        print(f"[Fehler] {path} existiert nicht.")
        print("Tipp: erst 'python generate_sample_data.py' ausfuehren.")
        sys.exit(1)

    with path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    return rows


def section(title: str) -> None:
    print()
    print(title)
    print("-" * len(title))
