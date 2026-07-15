"""
generate_sample_data.py

Baut data/portscan_capture.csv: eine Mischung aus ganz normalem TCP-Verkehr
und einem simulierten Portscan. Kein echter Mitschnitt, alle Werte sind
von Hand konstruiert (siehe "Woher kommen die Daten" in der README).

Zwei Muster stecken drin:
  1. Ein Client, der sich ganz normal verhaelt: zwei Ports, ueber fast eine
     Minute verteilt (z.B. kurz HTTPS, spaeter mal SSH).
  2. Eine externe Adresse, die in unter einer halben Sekunde 18 verschiedene
     Ports beim Client durchprobiert - das klassische Muster eines
     automatisierten Scans (z.B. mit nmap).

Mit --seed laesst sich ein anderer Zufalls-Seed setzen, Standard ist 42
fuer reproduzierbare Ergebnisse.
"""

import argparse
import csv
import random
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent / "data"
CLIENT_IP = "192.168.1.10"


def write_csv(filename: str, fieldnames: list[str], rows: list[dict]) -> None:
    path = DATA_DIR / filename
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    print(f"  geschrieben: {path.relative_to(DATA_DIR.parent)}  ({len(rows)} Zeilen)")


def gen_portscan(rng: random.Random) -> list[dict]:
    rows = []
    no = 1
    t = 0.0

    def add(src, dst, port, flags):
        nonlocal no, t
        rows.append({
            "no": no, "timestamp": f"{t:.6f}", "src_ip": src, "dst_ip": dst,
            "dst_port": port, "flags": flags,
        })
        no += 1

    # -- normaler Traffic: Client nutzt ganz gemuetlich zwei Ports,
    #    ueber fast eine Minute verteilt --
    add(CLIENT_IP, "93.184.216.34", 443, "SYN")
    t += 0.02
    add("93.184.216.34", CLIENT_IP, 443, "SYN,ACK")
    t += 22.0
    add(CLIENT_IP, "93.184.216.34", 22, "SYN")
    t += 0.03
    add("93.184.216.34", CLIENT_IP, 22, "SYN,ACK")
    t += 30.0

    # -- Portscan: externe IP klopft in unter einer Sekunde 18 Ports beim
    #    Client ab --
    scan_src = "203.0.113.200"
    scan_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
                  443, 445, 993, 995, 1433, 3306, 3389]
    scan_t = t
    for port in scan_ports:
        rows.append({
            "no": no, "timestamp": f"{scan_t:.6f}", "src_ip": scan_src, "dst_ip": CLIENT_IP,
            "dst_port": port, "flags": "SYN",
        })
        no += 1
        scan_t += rng.uniform(0.01, 0.04)

    # ein paar Antworten fuer den realistischen Eindruck (die meisten Ports
    # sind zu, einer ist offen) - fuer die Erkennung selbst nicht noetig,
    # detect_portscan.py schaut nur auf die SYN-Pakete des Scanners
    rows.append({"no": no, "timestamp": f"{scan_t:.6f}", "src_ip": CLIENT_IP, "dst_ip": scan_src,
                 "dst_port": 443, "flags": "SYN,ACK"})
    no += 1
    scan_t += 0.01
    rows.append({"no": no, "timestamp": f"{scan_t:.6f}", "src_ip": CLIENT_IP, "dst_ip": scan_src,
                 "dst_port": 23, "flags": "RST,ACK"})
    no += 1

    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description="Erzeugt Beispieldaten fuer detect_portscan.py.")
    parser.add_argument("--seed", type=int, default=42, help="Zufalls-Seed (Standard: 42)")
    args = parser.parse_args()

    rng = random.Random(args.seed)
    DATA_DIR.mkdir(exist_ok=True)

    print(f"Erzeuge Beispieldaten (seed={args.seed}) in {DATA_DIR}/ ...")
    write_csv(
        "portscan_capture.csv",
        ["no", "timestamp", "src_ip", "dst_ip", "dst_port", "flags"],
        gen_portscan(rng),
    )
    print("\nFertig. Weiter geht's mit: python detect_portscan.py")


if __name__ == "__main__":
    main()
