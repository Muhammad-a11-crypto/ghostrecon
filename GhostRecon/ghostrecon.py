#!/usr/bin/env python3
"""
GhostRecon v2.0 — Passive Web Intelligence & Security Correlation Engine
Author : 0xdzubair
GitHub : https://github.com/0xdzubair/ghostrecon
Type   : Passive Reconnaissance | No Exploits | No Noise
Legal  : Authorized targets only
"""

import sys
import os
import json
import argparse
import time
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent))

from ghostrecon.engine import GhostReconEngine, Finding
from ghostrecon.reporting.html_reporter import HTMLReportGenerator

# ── ANSI ──────────────────────────────────────────────────────────────────────
R  = "\033[0m"
B  = "\033[1m"
D  = "\033[2m"
G  = "\033[92m"       # green
C  = "\033[96m"       # cyan
Y  = "\033[93m"       # yellow
RE = "\033[91m"       # red
BL = "\033[94m"       # blue
M  = "\033[95m"       # magenta
GR = "\033[90m"       # grey

SEV = {
    "Critical": RE,
    "High":     Y,
    "Medium":   "\033[33m",
    "Low":      BL,
    "Info":     GR,
}

# ── BANNER ────────────────────────────────────────────────────────────────────
BANNER = f"""{G}
  ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗
 ██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝
 ██║  ███╗███████║██║   ██║███████╗   ██║
 ██║   ██║██╔══██║██║   ██║╚════██║   ██║
 ╚██████╔╝██║  ██║╚██████╔╝███████║   ██║
  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝{R}
{G}
 ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
 ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
 ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
 ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
 ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
 ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝{R}
{GR}
 ╔════════════════════════════════════════════════════════════╗
 ║  Passive Web Intelligence & Security Correlation Engine    ║
 ║  Version  : 2.0.0                                         ║
 ║  Author   : 0xdzubair                                     ║
 ║  LinkedIn : linkedin.com/in/muhammad09-zubair-aa592430b                     ║
 ║  GitHub   : github.com/0xdzubair/ghostrecon               ║
 ║  Type     : Passive Recon  |  No Exploits  |  No Noise    ║
 ╚════════════════════════════════════════════════════════════╝{R}
"""


def ts():
    return f"{GR}[{datetime.now().strftime('%H:%M:%S')}]{R}"


def log(icon, msg, color=C):
    print(f"  {ts()} {color}[{icon}]{R} {msg}")


def divider(label="", color=G):
    w = 65
    if label:
        pad = w - len(label) - 4
        print(f"\n  {color}┌── {B}{label}{R}{color} {'─'*pad}┐{R}")
    else:
        print(f"  {color}{'─'*w}{R}")


def print_summary(result):
    sev_order = ["Critical", "High", "Medium", "Low", "Info"]
    score     = result.risk_score

    divider("SCAN RESULTS")
    print(f"\n  {GR}Target   :{R}  {C}{B}{result.target.raw_url}{R}")
    print(f"  {GR}Host     :{R}  {result.target.host}")
    print(f"  {GR}Path     :{R}  {result.target.path}")
    print(f"  {GR}Scanned  :{R}  {result.scan_time}")
    print(f"  {GR}Duration :{R}  {result.duration_seconds:.2f}s")

    # Risk bar
    filled    = int(score / 100 * 42)
    rc        = RE if score >= 66 else Y if score >= 46 else "\033[33m" if score >= 26 else BL
    bar       = f"{rc}{'█'*filled}{GR}{'░'*(42-filled)}{R}"
    print(f"\n  {B}Risk Score:{R}  {rc}{B}{score}/100{R}  {rc}▶ {result.risk_label}{R}")
    print(f"  [{bar}]")

    # Findings table
    print(f"\n  {B}Findings by Severity:{R}")
    print(f"  {GR}{'─'*34}{R}")
    counts = result.summary.get("by_severity", {})
    for sev in sev_order:
        cnt   = counts.get(sev, 0)
        color = SEV.get(sev, "")
        dot   = "●" if cnt > 0 else "○"
        mini  = f"{color}{'▌'*min(cnt,25)}{R}" if cnt else ""
        print(f"  {color}{dot} {sev:<12}{R}  {B}{cnt:>3}{R}  {mini}")

    print(f"\n  {GR}Total: {len(result.findings)} findings  |  "
          f"Chains: {len(result.correlation_insights)}{R}")

    # Correlation Insights
    if result.correlation_insights:
        divider("CORRELATION INSIGHTS — Attack Chains")
        for ins in result.correlation_insights:
            sev   = ins.get("severity", "Info")
            color = SEV.get(sev, "")
            print(f"\n  {color}╔═ [{sev}]{R}")
            print(f"  {color}║{R}  {B}{ins.get('title','')}{R}")
            desc  = ins.get("description", "")
            short = desc[:150] + "…" if len(desc) > 150 else desc
            print(f"  {color}╚►{R}  {GR}{short}{R}")

    # Top findings
    divider("TOP FINDINGS")
    top = sorted(result.findings, key=lambda f: sev_order.index(f.severity))[:15]
    for f in top:
        color = SEV.get(f.severity, "")
        loc   = getattr(f, "location", "") or ""
        print(f"\n  {color}[{f.severity:<8}]{R}  {B}{f.title}{R}")
        if loc:
            print(f"  {GR}  📍 {loc[:85]}{R}")
        if f.evidence:
            print(f"  {GR}  Evidence: {f.evidence[:85]}{R}")
        if f.cwe:
            print(f"  {GR}  CWE: {f.cwe}{R}")

    # Tech stack
    if result.tech_stack:
        divider("DETECTED TECHNOLOGIES")
        for t in result.tech_stack:
            ver = f" {Y}v{t.get('version','')}{R}" if t.get("version") else ""
            print(f"  {G}◆{R} {B}{t.get('name','?')}{R}{ver}  {GR}[{t.get('category','')}]{R}")


def parse_args():
    p = argparse.ArgumentParser(
        prog="ghostrecon",
        description="GhostRecon v2.0 — Passive Web Intelligence & Security Correlation Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{G}Examples:{R}
  python ghostrecon.py -u https://example.com
  python ghostrecon.py -u https://example.com -o reports/report.html
  python ghostrecon.py -u https://example.com --json reports/scan.json
  python ghostrecon.py -u https://target.com --timeout 30 --quiet

{G}Author:{R}
  0xdzubair
  LinkedIn : https://www.linkedin.com/in/muhammad09-zubair-aa592430b
  GitHub   : https://github.com/0xdzubair/ghostrecon

{Y}Legal Notice:{R}
  Only scan targets you own or have explicit written permission to test.
  This tool performs PASSIVE analysis only — no exploits, no attacks, no noise.
        """,
    )
    p.add_argument("-u", "--url",          required=True,            help="Target URL to scan")
    p.add_argument("-o", "--output",       default=None,             help="HTML report path (default: reports/ghostrecon_<host>.html)")
    p.add_argument("--json",               default=None, metavar="F",help="Also export raw findings as JSON")
    p.add_argument("--timeout",            type=int, default=15,     help="Request timeout seconds (default: 15)")
    p.add_argument("--no-redirects",       action="store_true",      help="Do not follow HTTP redirects")
    p.add_argument("--no-banner",          action="store_true",      help="Suppress ASCII banner")
    p.add_argument("--quiet",              action="store_true",      help="Suppress all progress output")
    return p.parse_args()


def main():
    args = parse_args()

    if not args.no_banner:
        print(BANNER)

    if not args.quiet:
        log("+", f"Target    : {C}{args.url}{R}", G)
        log("+", f"Timeout   : {args.timeout}s", G)
        log("+", f"Redirects : {'Enabled' if not args.no_redirects else 'Disabled'}", G)
        print(f"\n  {GR}  Ghost mode active — passive only, no exploits, no noise.{R}\n")

    engine = GhostReconEngine(
        timeout=args.timeout,
        follow_redirects=not args.no_redirects,
    )

    try:
        result = engine.scan(args.url)
    except KeyboardInterrupt:
        print(f"\n\n  {Y}[!] Interrupted by user.{R}\n")
        sys.exit(1)
    except Exception as e:
        print(f"\n  {RE}[✗] Scan failed: {e}{R}\n")
        sys.exit(1)

    if not args.quiet:
        print_summary(result)

    # Output paths
    safe_host = result.target.host.replace(":", "_").replace("/", "_")
    os.makedirs("reports", exist_ok=True)
    html_path = args.output or f"reports/ghostrecon_{safe_host}.html"
    json_path = args.json

    if args.output:
        os.makedirs(os.path.dirname(html_path) if os.path.dirname(html_path) else ".", exist_ok=True)

    # Write HTML report
    reporter     = HTMLReportGenerator()
    html_content = reporter.generate(result)
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    print(f"\n  {G}[✓] HTML report saved :{R}  {B}{html_path}{R}")

    # Write JSON if requested
    if json_path:
        os.makedirs(os.path.dirname(json_path) if os.path.dirname(json_path) else ".", exist_ok=True)
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(result.to_dict(), f, indent=2, default=str)
        print(f"  {G}[✓] JSON report saved  :{R}  {B}{json_path}{R}")

    print(f"\n  {GR}  Open {html_path} in your browser to view the full interactive report.{R}")
    print(f"  {GR}  GhostRecon by 0xdzubair — ethical hacking starts with knowledge.{R}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
