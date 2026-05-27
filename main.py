# ============================================================
# OSINT Agent - Main
# Collega tutti i moduli e orchestra il flusso completo
#
# Uso:
#   python main.py tesla.com
#   python main.py --target tesla.com
#   python main.py                     (te lo chiede interattivo)
# ============================================================

import argparse
import json
import os
import sys
from datetime import datetime

# Importiamo le funzioni dai moduli che abbiamo già scritto
# Non duplichiamo il codice — lo richiamiamo
from osint_step1 import trova_sottodomini
from shodan_module import risolvi_ip
from scanner_module import scansiona_tutti


# ============================================================
# ARGPARSE - gestione argomenti da riga di comando
# ============================================================

def leggi_argomenti():
    # ArgumentParser = oggetto che gestisce gli argomenti
    parser = argparse.ArgumentParser(
        description="OSINT Agent — ricognizione automatica di un dominio",
        epilog="Esempio: python main.py tesla.com"
    )

    # Argomento posizionale opzionale — puoi scrivere solo il dominio
    # nargs="?" = zero o uno (opzionale)
    parser.add_argument(
        "dominio",
        nargs="?",
        help="Dominio target (es. tesla.com)"
    )

    # Argomento con flag — alternativa con --target
    parser.add_argument(
        "--target", "-t",
        help="Dominio target (alternativa: python main.py --target tesla.com)"
    )

    # Argomento opzionale: salva report in una cartella specifica
    parser.add_argument(
        "--output", "-o",
        default="report",
        help="Cartella dove salvare i risultati (default: ./report)"
    )

    # Argomento opzionale: salta il port scan (più veloce)
    parser.add_argument(
        "--no-scan",
        action="store_true",
        help="Salta il port scan (solo enumerazione sottodomini)"
    )

    args = parser.parse_args()

    # Priorità: --target > argomento posizionale > chiede interattivo
    target = args.target or args.dominio

    if not target:
        # Nessun argomento passato — chiede interattivamente
        print("\n" + "="*50)
        print("         OSINT Agent v0.1")
        print("="*50)
        target = input("\n[?] Inserisci il dominio target: ").strip()

        if not target:
            print("[!] Nessun dominio inserito. Uscita.")
            sys.exit(1)

    # Pulizia input — rimuove http://, https://, slash finali
    target = target.replace("https://", "").replace("http://", "").rstrip("/")

    return target, args.output, args.no_scan


# ============================================================
# SETUP CARTELLA OUTPUT
# Ogni scan crea una cartella con timestamp — non si sovrascrive
# ============================================================

def crea_cartella_output(base, dominio):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    cartella = os.path.join(base, f"{dominio}_{timestamp}")
    os.makedirs(cartella, exist_ok=True)
    return cartella


# ============================================================
# FUNZIONE PRINCIPALE
# ============================================================

def main():

    # Leggi argomenti
    target, output_base, salta_scan = leggi_argomenti()

    # Intestazione
    print("\n" + "="*50)
    print("         OSINT Agent v0.1")
    print("="*50)
    print(f"  Target  : {target}")
    print(f"  Avvio   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Port scan: {'NO (--no-scan)' if salta_scan else 'SI'}")
    print("="*50)

    # Crea cartella output per questo scan
    cartella = crea_cartella_output(output_base, target)
    print(f"\n[*] Output in: {cartella}\n")

    risultati_completi = {
        "target": target,
        "timestamp": datetime.now().isoformat(),
        "sottodomini": [],
        "ip_map": {},
        "scan": []
    }

    # ============================================================
    # STEP 1: Enumerazione sottodomini
    # ============================================================

    print("\n" + "-"*40)
    print("STEP 1 — Enumerazione sottodomini")
    print("-"*40)

    sottodomini = trova_sottodomini(target)

    if not sottodomini:
        print("[!] Nessun sottodominio trovato. Uscita.")
        sys.exit(1)

    risultati_completi["sottodomini"] = sottodomini

    # Salva risultato intermedio
    with open(os.path.join(cartella, "sottodomini.json"), "w") as f:
        json.dump(sottodomini, f, indent=2)

    # ============================================================
    # STEP 2: Risoluzione IP
    # ============================================================

    print("\n" + "-"*40)
    print("STEP 2 — Risoluzione IP")
    print("-"*40)

    ip_map = risolvi_ip(sottodomini)

    if not ip_map:
        print("[!] Nessun IP risolto. Uscita.")
        sys.exit(1)

    # Converti per JSON (le liste vanno bene, i set no)
    ip_map_serializable = {ip: subs for ip, subs in ip_map.items()}
    risultati_completi["ip_map"] = ip_map_serializable

    with open(os.path.join(cartella, "ip_map.json"), "w") as f:
        json.dump(ip_map_serializable, f, indent=2)

    # ============================================================
    # STEP 3: Port scan (opzionale)
    # ============================================================

    if not salta_scan:
        print("\n" + "-"*40)
        print("STEP 3 — Port scan")
        print("-"*40)

        risultati_scan = scansiona_tutti(ip_map)
        risultati_completi["scan"] = risultati_scan

        with open(os.path.join(cartella, "port_scan.json"), "w") as f:
            json.dump(risultati_scan, f, indent=2)

    else:
        print("\n[*] Port scan saltato (--no-scan)")

    # ============================================================
    # REPORT FINALE
    # ============================================================

    report_path = os.path.join(cartella, "report_completo.json")
    with open(report_path, "w") as f:
        json.dump(risultati_completi, f, indent=2)

    # Riepilogo a schermo
    print("\n" + "="*50)
    print("  SCAN COMPLETATO")
    print("="*50)
    print(f"  Sottodomini trovati : {len(sottodomini)}")
    print(f"  IP unici            : {len(ip_map)}")

    if not salta_scan and risultati_completi["scan"]:
        totale_porte = sum(r["totale_porte"] for r in risultati_completi["scan"])
        ip_con_porte = sum(1 for r in risultati_completi["scan"] if r["totale_porte"] > 0)
        print(f"  IP con porte aperte : {ip_con_porte}")
        print(f"  Porte totali        : {totale_porte}")

    print(f"\n  Report salvato in   : {cartella}/")
    print("="*50 + "\n")

    # Prossimo step — quando aggiungiamo Claude
    print("[*] Prossimo step: analisi AI del report")
    print(f"    python analyze.py {report_path}\n")


if __name__ == "__main__":
    main()
