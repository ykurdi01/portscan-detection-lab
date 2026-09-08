"""
detect_portscan.py

Sucht in data/portscan_capture.csv nach dem klassischen Muster eines
Portscans: eine Quelle, die in kurzer Zeit auf sehr viele unterschiedliche
Ports derselben Zielmaschine zugreift. Ein einzelner Nutzer, der z.B. kurz
eine Webseite (Port 443) und spaeter mal per SSH (Port 22) draufschaut,
sieht ganz anders aus als ein Scan-Tool, das in unter einer Sekunde 15+
Ports durchprobiert.

Entspricht in Wireshark ungefaehr der Frage: "wie viele verschiedene
tcp.dstport-Werte tauchen fuer dieselbe ip.src -> ip.dst-Kombination in
einem kurzen Zeitfenster auf?" (Filter dafuer: tcp.flags.syn==1 &&
tcp.flags.ack==0) - hier wird das einfach automatisch ausgezaehlt statt
von Hand in der Packet List durchgezaehlt.

Zwei Schwellwerte steuern, ab wann etwas als Scan gilt:
  --min-ports   wie viele unterschiedliche Ports mindestens (Standard 8)
  --window      innerhalb welcher Zeitspanne in Sekunden (Standard 5.0)

Beide sind bewusst simpel gehalten (kein Sliding-Window, sondern min/max
Timestamp je Quelle-Ziel-Paar). Fuer ein Lernprojekt reicht das - in einer
echten Umgebung wuerde man eher eine Sliding-Window-Zaehlung nehmen, damit
auch ein langsamer Scan ueber mehrere Minuten nicht durchrutscht.
"""

import argparse
from collections import defaultdict

from common import load_csv, section


def main() -> None:
    parser = argparse.ArgumentParser(description="Sucht nach Portscan-Mustern in den Beispieldaten.")
    parser.add_argument("--min-ports", type=int, default=8,
                         help="ab wie vielen unterschiedlichen Ports pro Quelle-Ziel-Paar (Standard: 8)")
    parser.add_argument("--window", type=float, default=5.0,
                         help="Zeitfenster in Sekunden, innerhalb dessen die Ports angefragt wurden (Standard: 5.0)")
    args = parser.parse_args()

    rows = load_csv("portscan_capture.csv")

    # nach (src_ip, dst_ip) gruppieren, dabei nur Pakete zaehlen, die
    # tatsaechlich vom "Angreifer" ausgehen (SYN ohne ACK) - Antworten
    # interessieren uns hier nicht
    groups = defaultdict(list)
    for r in rows:
        if "SYN" in r["flags"] and "ACK" not in r["flags"]:
            groups[(r["src_ip"], r["dst_ip"])].append(r)

    section("Portscan-Erkennung")
    print(f"Schwellwert: ab {args.min_ports} unterschiedlichen Ports innerhalb von {args.window}s\n")

    suspicious = []
    for (src, dst), pkts in groups.items():
        ports = {p["dst_port"] for p in pkts}
        timestamps = [float(p["timestamp"]) for p in pkts]
        span = max(timestamps) - min(timestamps)

        flagged = len(ports) >= args.min_ports and span <= args.window
        status = "VERDAECHTIG" if flagged else "unauffaellig"
        rate = len(ports) / span if span > 0 else float(len(ports))

        print(f"{src} -> {dst}: {len(ports)} Ports in {span:.3f}s "
              f"(~{rate:.1f} Ports/s)  [{status}]")

        if flagged:
            suspicious.append((src, dst, sorted(ports, key=int), span))

    if suspicious:
        print("\nDetails zu den auffaelligen Quellen:")
        for src, dst, ports, span in suspicious:
            print(f"  {src} -> {dst}")
            print(f"    Ports: {', '.join(ports)}")
            print(f"    Zeitspanne: {span:.3f}s")
        print("\nHinweis: viele Ports in sehr kurzer Zeit von derselben Quelle "
              "sind ein klassisches Zeichen fuer einen automatisierten Portscan "
              "(z.B. mit nmap). Einzelne, ueber Minuten verteilte Verbindungen "
              "zu verschiedenen Ports sind dagegen meistens normales Nutzerverhalten.")
    else:
        print("\nKeine Quelle ueberschreitet den Schwellwert, keine Scan-Muster gefunden.")


if __name__ == "__main__":
    main()
