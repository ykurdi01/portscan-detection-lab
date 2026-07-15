# Portscan Detection Lab

Kleines, eigenständiges Python-Projekt zur Erkennung von Portscan-Mustern in Netzwerkverkehr. Kein Fehlerdiagnose-Tool wie mein anderes Wireshark-Projekt, sondern gezielt auf ein sicherheitsrelevantes Muster fokussiert: den klassischen Portscan.

## Worum geht's

Ein Portscan ist der Versuch, in kurzer Zeit möglichst viele Ports eines Zielhosts durchzuprobieren, um herauszufinden, welche Dienste dort laufen (typisches Werkzeug: `nmap`). Das Muster unterscheidet sich deutlich von normalem Nutzerverhalten:

| | Normale Nutzung | Portscan |
| --- | --- | --- |
| Anzahl verschiedener Ports | meist 1–3 | oft zweistellig |
| Zeitfenster | Minuten bis Stunden | Sekunden bis Millisekunden |
| Ports/Sekunde | sehr niedrig | hoch, oft automatisiert konstant |

In Wireshark lässt sich ein SYN-Scan (die gängigste Scan-Art) mit folgendem Filter isolieren:

```text
tcp.flags.syn == 1 && tcp.flags.ack == 0
```

Zusätzlich hilft **Statistics → Conversations**, um pro Quelle zu sehen, wie viele unterschiedliche Zielports in welchem Zeitraum angesprochen wurden – von Hand wird das aber schnell mühsam, sobald mehr als eine Handvoll Pakete zusammenkommen. Genau das übernimmt `detect_portscan.py`.

## Wie die Erkennung funktioniert

`detect_portscan.py` gruppiert alle SYN-Pakete (ohne ACK) nach Quelle-Ziel-Paar und schaut für jede Gruppe:

- wie viele **unterschiedliche** Zielports angesprochen wurden
- innerhalb welcher **Zeitspanne** das passiert ist

Überschreitet eine Quelle beide Schwellwerte gleichzeitig (Standard: mindestens 8 Ports innerhalb von 5 Sekunden), wird sie als verdächtig markiert. Beide Werte lassen sich anpassen:

```bash
python detect_portscan.py --min-ports 5 --window 2.0
```

Die Erkennung ist bewusst einfach gehalten (feste Schwellwerte, kein echtes Sliding-Window, keine Unterscheidung zwischen offenen/geschlossenen Ports). Für den produktiven Einsatz würde man auf etablierte Werkzeuge wie ein IDS/IPS (z. B. Suricata) zurückgreifen – für dieses Lernprojekt reicht die einfache Variante, um das Prinzip nachzuvollziehen.

## Setup & Ausführen

Braucht nur Python selbst (getestet mit 3.10), keine externen Pakete.

```bash
python generate_sample_data.py   # erzeugt data/portscan_capture.csv
python detect_portscan.py        # wertet die Daten aus
```

Beispielausgabe:

```
Portscan-Erkennung
------------------
Schwellwert: ab 8 unterschiedlichen Ports innerhalb von 5.0s

192.168.1.10 -> 93.184.216.34: 2 Ports in 22.020s (~0.1 Ports/s)  [unauffaellig]
203.0.113.200 -> 192.168.1.10: 18 Ports in 0.464s (~38.8 Ports/s)  [VERDAECHTIG]
```

## Woher kommen die Daten

`generate_sample_data.py` erzeugt `data/portscan_capture.csv` mit zwei erfundenen Mustern: normalem Nutzerverhalten (zwei Ports, über fast eine Minute verteilt) und einem simulierten Scan (18 Ports in unter einer halben Sekunde). Es sind **keine echten Mitschnitte** enthalten – aus Datenschutzgründen wird hier grundsätzlich nur mit selbst erzeugten Beispieldaten gearbeitet, keine Mitschnitte aus produktiven oder fremden Netzwerken. Mit `--seed` lässt sich ein anderer Zufalls-Seed setzen, Standard ist `42` für reproduzierbare Ergebnisse.

## Bekannte Einschränkungen

- Alle Daten sind erfunden, kein echter Mitschnitt.
- Feste Schwellwerte statt eines echten Sliding-Window-Verfahrens – ein langsamer, über mehrere Minuten gestreckter Scan würde aktuell nicht auffallen.
- Keine Unterscheidung zwischen offenen und geschlossenen Ports (dafür bräuchte man auch die Antwortpakete, nicht nur die SYN-Anfragen).
- Kein Abgleich mit bekannten Scan-Signaturen (z. B. typische `nmap`-Timing-Profile).

## Ausblick

Sinnvolle nächste Schritte wären ein echtes Sliding-Window-Verfahren statt fester min/max-Zeitstempel, eine Anbindung an `tshark`-JSON-Exports für echte (selbst aufgezeichnete) Mitschnitte, sowie eine Erweiterung um weitere Scan-Typen (z. B. langsame/verteilte Scans, UDP-Scans).
