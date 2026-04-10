"""
run_check.py — entry point do monitor multi-região.

Uso:
    python run_check.py exemplo.com
    python run_check.py exemplo.com --regions BR US DE JP CN IR RU
    python run_check.py exemplo.com --json out.json
    python run_check.py exemplo.com --token SEU_TOKEN
"""
import argparse
import os
import sys
from pathlib import Path

from globalping_monitor import diagnose, print_report, save_json

OUTPUT_DIR = Path(__file__).parent / "output"


DEFAULT_REGIONS = [
    "BR",        # Brasil
    "US",        # Estados Unidos
    "DE",        # Alemanha
    "GB",        # Reino Unido
    "JP",        # Japão
    "SG",        # Cingapura
    "AU",        # Austrália
    "ZA",        # África do Sul
    "IN",        # Índia
    "RU",        # Rússia
    "CN",        # China (raro ter probe, mas vale tentar)
    "IR",        # Irã (bom pra detectar censura)
]


def main():
    ap = argparse.ArgumentParser(description="Monitor multi-região via GlobalPing")
    ap.add_argument("target", help="domínio alvo, ex: exemplo.com")
    ap.add_argument("--regions", nargs="+", default=DEFAULT_REGIONS,
                    help="lista de regiões (magic field do GlobalPing)")
    ap.add_argument("--json", dest="json_out", help="salvar resultado em arquivo JSON")
    ap.add_argument("--token", default=os.environ.get("GLOBALPING_TOKEN"),
                    help="OAuth token (opcional — aumenta rate limit)")
    args = ap.parse_args()

    target = args.target.replace("https://", "").replace("http://", "").strip("/")

    try:
        reports = diagnose(target, args.regions, api_token=args.token)
    except Exception as e:
        print(f"[!] erro: {e}", file=sys.stderr)
        sys.exit(1)

    print_report(target, reports)
    if args.json_out:
        OUTPUT_DIR.mkdir(exist_ok=True)
        json_path = args.json_out if os.sep in args.json_out or "/" in args.json_out \
            else str(OUTPUT_DIR / args.json_out)
        save_json(reports, json_path)


if __name__ == "__main__":
    main()
