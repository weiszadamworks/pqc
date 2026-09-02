"""
Command Line Auditor Tool (CLI) for QuantumShield CBOM & Compliance Engine
Allows security auditors to scan endpoints and export CBOM/PDF directly from shell/CI-CD.
"""

import argparse
import json
import re
import sys
from pathlib import Path

from app.core.config import settings
from app.scanner.tls_scanner import TLSScanner
from app.engine.hndl_estimator import HNDLEstimator
from app.engine.compliance_scorer import ComplianceScorer
from app.engine.cbom_generator import CBOMGenerator
from app.reporting.pdf_generator import AuditPDFGenerator

def main():
    parser = argparse.ArgumentParser(
        description="QuantumShield CBOM & DORA/NIS2 Auditor CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Példa használat:\n  python -m app.cli scan cloudflare.com\n  python -m app.cli scan api.bank.hu --output ./audit_out"
    )
    subparsers = parser.add_subparsers(dest="command", help="Végrehajtandó parancs")

    scan_parser = subparsers.add_parser("scan", help="Célpont felmérése és auditálása")
    scan_parser.add_argument("target", help="Cél domain vagy IP cím (pl. api.bank.hu)")
    scan_parser.add_argument("-o", "--output", help="Kimeneti könyvtár (alapértelmezett: ./reports)", default=str(settings.reports_dir))
    scan_parser.add_argument("--no-pdf", action="store_true", help="PDF riport generálásának kihagyása")
    scan_parser.add_argument("--json-only", action="store_true", help="Csak a CycloneDX CBOM JSON kiírása stdout-ra")

    args = parser.parse_args()

    if not args.command or args.command != "scan":
        parser.print_help()
        sys.exit(1)

    target = args.target.strip()
    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)

    if not args.json_only:
        print(f"\n=======================================================")
        print(f"   QUANTUMSHIELD CBOM & COMPLIANCE SCANNER v1.0       ")
        print(f"=======================================================\n")
        print(f"[*] Célpont vizsgálata: {target}")

    try:
        scan_result = TLSScanner.scan_target(target)
    except Exception as e:
        print(f"[!] Hiba a vizsgálat közben: {e}", file=sys.stderr)
        sys.exit(2)

    if not scan_result.get("success"):
        print(f"[!] Sikertelen kapcsolat: {scan_result.get('errors')}", file=sys.stderr)
        sys.exit(2)

    # Compliance calculation
    hndl_info = HNDLEstimator.calculate_hndl_risk(
        scan_result["tls_info"],
        scan_result["certificate_info"],
        scan_result["pqc_info"]
    )
    comp = ComplianceScorer.evaluate(scan_result, hndl_info)
    cbom = CBOMGenerator.generate(scan_result, comp)

    safe_host = re.sub(r'[^a-zA-Z0-9_\-\.]', '_', scan_result["hostname"])
    cbom_file = out_dir / f"cbom_{safe_host}.json"
    pdf_file = out_dir / f"audit_report_{safe_host}.pdf"

    # Save CBOM
    with open(cbom_file, "w", encoding="utf-8") as f:
        json.dump(cbom, f, indent=2, ensure_ascii=False)

    if args.json_only:
        print(json.dumps(cbom, indent=2, ensure_ascii=False))
        return

    # PDF generation
    if not args.no_pdf:
        AuditPDFGenerator.generate_report(scan_result, comp, pdf_file)

    # Print summary
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    print(f"[+] Sikeres audit!")
    print(f"-------------------------------------------------------")
    print(f" [>] Celpont IP:            {scan_result.get('resolved_ip')}")
    print(f" [>] Protokoll:             {scan_result['tls_info'].get('version')} ({scan_result['tls_info'].get('cipher_name')})")
    print(f" [>] PQC Hibrid Vedelem:    {'IGEN (' + scan_result['pqc_info'].get('group_name') + ')' if scan_result['pqc_info'].get('pqc_supported') else 'NEM (Klasszikus)'}")
    print(f" [>] HNDL Kockazat:         {hndl_info.get('risk_level')}")
    print(f"-------------------------------------------------------")
    print(f" [*] DORA Index:            {comp.get('dora_score')}/100 pont")
    print(f" [*] NIS2 Index:            {comp.get('nis2_score')}/100 pont")
    print(f" [*] Kvantum Ellenallas:    {comp.get('quantum_resilience_score')}%")
    print(f" [*] Audit Minosites:       {comp.get('grade')} ({comp.get('audit_status')})")
    print(f"-------------------------------------------------------")
    print(f" [OK] CycloneDX 1.6 CBOM:   {cbom_file}")
    if not args.no_pdf:
        print(f" [OK] Vezetoi PDF Riport:   {pdf_file}")
    print(f"=======================================================\n")

if __name__ == "__main__":
    main()
