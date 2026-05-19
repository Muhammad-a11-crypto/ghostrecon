# GhostRecon 👻

> **Passive Web Intelligence & Security Correlation Engine**  
> No exploits. No payloads. No noise. Just intelligence.

```
  ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗    ██████╗ ███████╗ ██████╗ ██████╗ ███╗
 ██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝    ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗
 ██║  ███╗███████║██║   ██║███████╗   ██║       ██████╔╝█████╗  ██║     ██║   ██║██╔██╗
 ██║   ██║██╔══██║██║   ██║╚════██║   ██║       ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗
 ╚██████╔╝██║  ██║╚██████╔╝███████║   ██║       ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████╗
  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝       ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚══╝
```

[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-3776ab?logo=python&logoColor=white)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-22c55e)](LICENSE)
[![Type: Passive Recon](https://img.shields.io/badge/Type-Passive%20Recon-00e5ff)](https://github.com/0xdzubair/ghostrecon)
[![Author: 0xdzubair](https://img.shields.io/badge/Author-0xdzubair-7c3aed)](https://www.linkedin.com/in/muhammad09-zubair-aa592430b)

---

## What is GhostRecon?

GhostRecon is a **professional-grade passive web security analysis tool** that performs deep reconnaissance against web applications without sending any exploits, payloads, or attack traffic. It works purely by analyzing the responses a normal browser would receive.

### Key Differentiator — Correlation Intelligence

Unlike tools that just list findings, GhostRecon **cross-correlates them** to identify compound **attack chains** — combinations of weaknesses that are far more dangerous together than individually.

**Example:** A missing `HttpOnly` flag is Low risk. An XSS sink in JavaScript is Medium. Together, they form a **Critical session hijack chain** — and GhostRecon tells you exactly that.

---

## Features

| Feature | Description |
|---------|-------------|
| 🔍 **6 Analysis Modules** | Headers, Cookies, HTML, JavaScript, Tech Fingerprint, Parameters |
| 🔗 **Correlation Engine** | 8 built-in attack chain detection rules |
| 📊 **Risk Scoring** | Weighted 0–100 risk score with qualitative label |
| 🌐 **HTML Report** | Self-contained, interactive report — filterable findings |
| 📍 **Location Tracking** | Every finding includes the exact URL/path it was found at |
| ⬇ **Export** | Download findings as JSON or CSV directly from the report |
| 👤 **Author Card** | LinkedIn profile integrated in the report |
| 🖥️ **Hacker Terminal UI** | Full ANSI color output with matrix-style aesthetic |

---

## Folder Structure

```
GhostRecon/
├── ghostrecon.py                        ← CLI entry point (run this)
├── requirements.txt
├── README.md
├── .gitignore
├── reports/                             ← HTML/JSON reports saved here
└── ghostrecon/                          ← Main package
    ├── __init__.py
    ├── engine.py                        ← Core orchestration engine
    ├── modules/
    │   ├── __init__.py
    │   ├── header_analyzer.py           ← HTTP security header analysis
    │   ├── cookie_inspector.py          ← Cookie attribute checks
    │   ├── html_parser.py               ← HTML content analysis
    │   ├── js_analyzer.py               ← JavaScript file analysis
    │   ├── tech_fingerprinter.py        ← Technology stack detection
    │   └── param_detector.py            ← URL/form parameter analysis
    ├── correlation/
    │   ├── __init__.py
    │   └── correlator.py                ← Attack chain correlation engine
    └── reporting/
        ├── __init__.py
        ├── risk_scorer.py               ← 0-100 risk scoring
        └── html_reporter.py             ← HTML report generator
```

---

## Installation

### Step 1 — Clone the repository

```bash
git clone https://github.com/0xdzubair/ghostrecon.git
cd ghostrecon
```

### Step 2 — Install dependencies

```bash
pip install -r requirements.txt
```

> No virtual environment required, but recommended:
> ```bash
> python -m venv venv
> source venv/bin/activate      # Linux/Mac
> venv\Scripts\activate         # Windows
> pip install -r requirements.txt
> ```

### Step 3 — Run

```bash
python ghostrecon.py -u https://example.com
```

---

## Usage

```bash
# Basic passive scan
python ghostrecon.py -u https://example.com

# Save report to specific path
python ghostrecon.py -u https://example.com -o my_report.html

# Also export JSON
python ghostrecon.py -u https://example.com --json reports/findings.json

# Adjust timeout
python ghostrecon.py -u https://example.com --timeout 30

# Quiet mode (report only, no terminal output)
python ghostrecon.py -u https://example.com --quiet

# No banner
python ghostrecon.py -u https://example.com --no-banner
```

### CLI Options

| Flag | Default | Description |
|------|---------|-------------|
| `-u`, `--url` | required | Target URL |
| `-o`, `--output` | `reports/ghostrecon_<host>.html` | HTML report path |
| `--json FILE` | — | Also export JSON to this path |
| `--timeout N` | 15 | Request timeout in seconds |
| `--no-redirects` | — | Don't follow HTTP redirects |
| `--no-banner` | — | Suppress ASCII art banner |
| `--quiet` | — | Suppress terminal output |

---

## Analysis Modules

| Module | What it analyzes | Key findings |
|--------|-----------------|--------------|
| **HeaderAnalyzer** | HTTP response headers | Missing HSTS, CSP, X-Frame-Options, CORS misconfig |
| **CookieInspector** | Set-Cookie headers | Missing HttpOnly, Secure, SameSite; JWT detection |
| **HTMLParser** | Page HTML | Hardcoded secrets, missing CSRF, admin links, mixed content |
| **JSAnalyzer** | JavaScript files | API endpoints, secrets in JS, dangerous sinks |
| **TechFingerprinter** | Headers + HTML + Cookies | Stack identification (20+ signatures), version disclosure |
| **ParamDetector** | URL + Form + JS params | IDOR candidates, open redirect params, tokens in URL |

---

## Correlation Attack Chains

| Chain | Trigger Conditions | Risk Boost |
|-------|-------------------|------------|
| Session Hijack | Missing HttpOnly + XSS Sink | +15 pts |
| XSS Defense Gap | Weak/Missing CSP + XSS Vectors | +10 pts |
| CSRF Triple Threat | No SameSite + No CSRF Token | +12 pts |
| Admin Downgrade | Admin Panel + No HSTS | +12 pts |
| **JS Secret + CORS** | Secret in JS + Wildcard CORS | **+20 pts (Critical)** |
| API Exposure | JS API Endpoints + No Rate Limiting | +7 pts |
| Info Overload | 4+ Disclosure findings | +8 pts |
| CVE Fingerprint | Version Disclosure + Tech Stack | +5 pts |

---

## Sample Terminal Output

```
  ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗
 ...

 ╔════════════════════════════════════════════════╗
 ║  Author   : 0xdzubair                          ║
 ║  LinkedIn : linkedin.com/in/muhammad09-zubair-aa592430b          ║
 ╚════════════════════════════════════════════════╝

  Risk Score:  74/100  ▶ Very High
  [████████████████████████████░░░░░░░░░░░░░░░░]

  Findings by Severity:
  ● Critical      2   ▌▌
  ● High          5   ▌▌▌▌▌
  ● Medium        7   ▌▌▌▌▌▌▌
  ● Low           4   ▌▌▌▌
  ● Info          3   ▌▌▌

  ╔═ [Critical]
  ║  JavaScript Secret + CORS Wildcard = Credential Theft
  ╚►  A secret/key was found hardcoded in JavaScript AND CORS is wildcard...
```

---

## Risk Score Reference

| Score | Label | Action |
|-------|-------|--------|
| 0–10 | Minimal | Excellent posture |
| 11–25 | Low | Minor issues |
| 26–45 | Medium | Review recommended |
| 46–65 | High | Significant vulnerabilities |
| 66–80 | Very High | Multiple exploitable issues |
| 81–100 | Critical | Immediate remediation required |

---

## Legal

> ⚠️ **This tool is for authorized security testing ONLY.**  
> Only scan targets you own or have explicit written permission to test.  
> GhostRecon performs **passive analysis only** — it sends no exploits, no payloads, no fuzzing.  
> The author assumes no liability for unauthorized or illegal use.

---

## Author

**0xdzubair** — Ethical Hacker & Security Researcher

- 🔗 LinkedIn: [linkedin.com/in/muhammad09-zubair-aa592430b](https://www.linkedin.com/in/muhammad09-zubair-aa592430b)
- 🐙 GitHub: [github.com/0xdzubair](https://github.com/0xdzubair)

---

## License

MIT License — see [LICENSE](LICENSE) for details.
