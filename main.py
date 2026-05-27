# ============================================================
# ReconAI - Main
# Orchestra scan + analisi AI + notifica Telegram
#
# Uso:
#   python main.py tesla.com
#   python main.py --target tesla.com
#   python main.py                        (chiede interattivo)
#   python main.py tesla.com --no-scan    (solo sottodomini)
#   python main.py tesla.com --no-telegram (senza notifica)
# ============================================================

import argparse
import json
import os
import sys
from datetime import datetime

from osint_step1 import trova_sottodomini
from shodan_module import risolvi_ip
from scanner_module import scansiona_tutti


# ============================================================
# ARGPARSE
# ============================================================

def leggi_argomenti():
    parser = argparse.ArgumentParser(
        description="ReconAI — OSINT reconnaissance agent",
        epilog="Esempio: python main.py tesla.com"
    )

    parser.add_argument("dominio", nargs="?", help="Dominio target")
    parser.add_argument("--target", "-t", help="Dominio target (alternativa)")
    parser.add_argument("--output", "-o", default="report",
                        help="Cartella output (default: ./report)")
    parser.add_argument("--no-scan", action="store_true",
                        help="Salta il port scan")
    parser.add_argument("--no-telegram", action="store_true",
                        help="Salta la notifica Telegram")

    args = parser.parse_args()
    target = args.target or args.dominio

    if not target:
        print("\n" + "="*50)
        print("         ReconAI v0.1")
        print("="*50)
        target = input("\n[?] Inserisci il dominio target: ").strip()
        if not target:
            print("[!] Nessun dominio inserito. Uscita.")
            sys.exit(1)

    target = target.replace("https://", "").replace("http://", "").rstrip("/")
    return target, args.output, args.no_scan, args.no_telegram


# ============================================================
# SETUP CARTELLA OUTPUT
# ============================================================

def crea_cartella_output(base, dominio):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    cartella = os.path.join(base, f"{dominio}_{timestamp}")
    os.makedirs(cartella, exist_ok=True)
    return cartella


# ============================================================
# MAIN
# ============================================================

def main():

    target, output_base, salta_scan, salta_telegram = leggi_argomenti()

    print("\n" + "="*50)
    print("         ReconAI v0.1")
    print("="*50)
    print(f"  Target    : {target}")
    print(f"  Avvio     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Port scan : {'NO (--no-scan)' if salta_scan else 'SI'}")
    print(f"  Telegram  : {'NO (--no-telegram)' if salta_telegram else 'SI'}")
    print("="*50)

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
    # STEP 1: Sottodomini
    # ============================================================

    print("\n" + "-"*40)
    print("STEP 1 — Enumerazione sottodomini")
    print("-"*40)

    sottodomini = trova_sottodomini(target)

    if not sottodomini:
        print("[!] Nessun sottodominio trovato. Uscita.")
        sys.exit(1)

    risultati_completi["sottodomini"] = sottodomini

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

    ip_map_serializable = {ip: subs for ip, subs in ip_map.items()}
    risultati_completi["ip_map"] = ip_map_serializable

    with open(os.path.join(cartella, "ip_map.json"), "w") as f:
        json.dump(ip_map_serializable, f, indent=2)

    # ============================================================
    # STEP 3: Port scan
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

    # Salva report completo
    report_path = os.path.join(cartella, "report_completo.json")
    with open(report_path, "w") as f:
        json.dump(risultati_completi, f, indent=2)

    # ============================================================
    # STEP 4: Analisi AI automatica
    # ============================================================

    print("\n" + "-"*40)
    print("STEP 4 — Analisi AI")
    print("-"*40)

    analisi_path = None

    try:
        from analyze import prepara_prompt, chiama_ai, carica_config

        config = carica_config()
        provider = config.get("AI_PROVIDER", "gemini")
        prompt = prepara_prompt(risultati_completi)
        analisi = chiama_ai(prompt, config)

        if analisi:
            analisi_path = os.path.join(cartella, f"analisi_{provider}.txt")
            with open(analisi_path, "w") as f:
                f.write(f"ANALISI OSINT — {target}\n")
                f.write(f"Provider  : {provider.upper()}\n")
                f.write(f"Generata  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("="*50 + "\n\n")
                f.write(analisi)

            print(f"[+] Analisi salvata: {analisi_path}")
        else:
            print("[!] Analisi AI non riuscita")

    except Exception as e:
        print(f"[!] Errore analisi AI: {e}")
        print("[*] Puoi eseguirla manualmente con: python analyze.py")

    # ============================================================
    # RIEPILOGO FINALE
    # ============================================================

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

    print(f"\n  Report in           : {cartella}/")
    print("="*50 + "\n")

    # ============================================================
    # STEP 5: Notifica Telegram
    # ============================================================

    if not salta_telegram:
        print("-"*40)
        print("STEP 5 — Notifica Telegram")
        print("-"*40)

        try:
            from telegram_module import invia_report_telegram
            invia_report_telegram(risultati_completi, analisi_path)
        except Exception as e:
            print(f"[!] Errore Telegram: {e}")
    else:
        print("[*] Notifica Telegram saltata (--no-telegram)")


if __name__ == "__main__":
    main()
