"""
GhostRecon — HTML Report Generator
Professional, self-contained security report with:
  - Download findings as JSON/CSV
  - LinkedIn author card
  - Location path for every finding
  - Network-aware: opens on same host the tool runs on
Author: 0xdzubair
"""

import json
from datetime import datetime


class HTMLReportGenerator:

    SEVERITY_COLORS = {
        "Critical": "#ff3860",
        "High":     "#ff6b35",
        "Medium":   "#f5a623",
        "Low":      "#4a9fd4",
        "Info":     "#7b8ea0",
    }

    RISK_COLORS = {
        "Critical": "#ff3860",
        "Very High":"#ff6b35",
        "High":     "#ff6b35",
        "Medium":   "#f5a623",
        "Low":      "#4a9fd4",
        "Minimal":  "#27ae60",
        "Unknown":  "#7b8ea0",
    }

    def generate(self, result) -> str:
        data        = result.to_dict()
        findings    = result.findings
        insights    = result.correlation_insights
        sev_counts  = data["summary"]["by_severity"]
        risk_color  = self.RISK_COLORS.get(result.risk_label, "#7b8ea0")

        findings_html   = self._render_findings(findings)
        insights_html   = self._render_insights(insights)
        tech_html       = self._render_tech_stack(result.tech_stack)
        summary_cards   = self._render_summary_cards(sev_counts)
        scan_data_json  = json.dumps(data, indent=2, default=str)
        generated_date  = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
        total_findings  = data["summary"]["total_findings"]
        duration        = data["meta"]["duration_seconds"]
        scan_time       = data["meta"]["scan_time"]

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>GhostRecon Report — {result.target.host}</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;600;700&family=Syne:wght@400;600;700;800&family=Inter:wght@300;400;500;600&display=swap');

:root {{
  --bg:        #080b10;
  --bg2:       #0d1117;
  --surface:   #0f1520;
  --surface2:  #141b2e;
  --surface3:  #1a2236;
  --border:    #1e2a3a;
  --border2:   #253044;
  --text:      #c9d3e0;
  --text-dim:  #5a6a80;
  --text-mid:  #8898aa;
  --accent:    #00e5ff;
  --accent2:   #7c3aed;
  --green:     #00e676;
  --critical:  #ff1744;
  --high:      #ff6d00;
  --medium:    #ffab00;
  --low:       #2196f3;
  --info:      #607d8b;
  --success:   #00c853;
}}

*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}

html {{ scroll-behavior: smooth; }}

body {{
  background: var(--bg);
  color: var(--text);
  font-family: 'Inter', sans-serif;
  font-size: 14px;
  line-height: 1.65;
  min-height: 100vh;
}}

/* ── SCROLLBAR ── */
::-webkit-scrollbar {{ width: 6px; }}
::-webkit-scrollbar-track {{ background: var(--bg); }}
::-webkit-scrollbar-thumb {{ background: var(--border2); border-radius: 3px; }}

/* ── HEADER ── */
.gr-header {{
  background: linear-gradient(160deg, #0a0f1a 0%, #0d1520 60%, #0a0f1a 100%);
  border-bottom: 1px solid var(--border);
  padding: 0;
  position: relative;
  overflow: hidden;
}}

.gr-header::before {{
  content:'';
  position:absolute;inset:0;
  background:
    radial-gradient(ellipse 60% 80% at 5% 50%, rgba(0,229,255,.055) 0%, transparent 70%),
    radial-gradient(ellipse 40% 60% at 90% 20%, rgba(124,58,237,.04) 0%, transparent 60%);
  pointer-events:none;
}}

/* matrix rain canvas */
#matrix-canvas {{
  position:absolute;top:0;left:0;width:100%;height:100%;
  opacity:0.06;pointer-events:none;
}}

.header-inner {{
  position:relative;
  max-width:1280px;
  margin:0 auto;
  padding:44px 64px 40px;
  display:grid;
  grid-template-columns:1fr auto;
  gap:40px;
  align-items:center;
}}

/* ASCII logo in header */
.ascii-logo {{
  font-family:'JetBrains Mono',monospace;
  font-size:9.5px;
  line-height:1.25;
  color:var(--accent);
  opacity:.7;
  white-space:pre;
  margin-bottom:18px;
}}

.tool-badge {{
  display:inline-flex;align-items:center;gap:8px;
  background:rgba(0,229,255,.07);
  border:1px solid rgba(0,229,255,.18);
  border-radius:6px;
  padding:4px 14px;
  font-family:'JetBrains Mono',monospace;
  font-size:10px;color:var(--accent);
  letter-spacing:.1em;text-transform:uppercase;
  margin-bottom:14px;
}}
.tool-badge::before{{content:'◈';font-size:9px;}}

.report-title {{
  font-family:'Syne',sans-serif;
  font-size:34px;font-weight:800;
  color:#fff;letter-spacing:-.03em;line-height:1.15;
  margin-bottom:10px;
}}
.report-title span {{
  background:linear-gradient(135deg,var(--accent),var(--accent2));
  -webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;
}}

.target-line {{
  font-family:'JetBrains Mono',monospace;font-size:13px;
  color:var(--text-dim);margin-top:6px;
}}
.target-line strong{{color:var(--accent);}}

.meta-row {{
  display:flex;gap:12px;flex-wrap:wrap;margin-top:22px;
}}
.meta-chip {{
  background:rgba(255,255,255,.03);
  border:1px solid var(--border);border-radius:8px;
  padding:10px 16px;
}}
.meta-chip .lbl {{
  font-size:9.5px;text-transform:uppercase;letter-spacing:.1em;
  color:var(--text-dim);margin-bottom:3px;
}}
.meta-chip .val {{
  font-family:'JetBrains Mono',monospace;font-size:13px;
  color:var(--text);font-weight:600;
}}

/* Risk gauge */
.risk-gauge {{
  text-align:center;
  background:var(--surface);
  border:1px solid var(--border);
  border-radius:20px;padding:28px 36px;
  min-width:210px;
}}
.risk-gauge .lbl {{
  font-size:10px;text-transform:uppercase;letter-spacing:.12em;
  color:var(--text-dim);margin-bottom:8px;
}}
.risk-score-num {{
  font-family:'Syne',sans-serif;font-size:58px;font-weight:800;line-height:1;
  margin-bottom:4px;
}}
.risk-level-pill {{
  display:inline-block;padding:5px 18px;border-radius:20px;
  font-size:12px;font-weight:600;letter-spacing:.05em;margin-top:10px;
}}

/* ── NAV ── */
.gr-nav {{
  background:var(--surface);
  border-bottom:1px solid var(--border);
  position:sticky;top:0;z-index:100;
  backdrop-filter:blur(12px);
}}
.gr-nav-inner {{
  max-width:1280px;margin:0 auto;padding:0 64px;
  display:flex;align-items:center;gap:6px;overflow-x:auto;
}}
.nav-btn {{
  background:none;border:none;
  padding:14px 18px;cursor:pointer;
  font-family:'JetBrains Mono',monospace;
  font-size:12px;color:var(--text-dim);
  border-bottom:2px solid transparent;
  transition:all .15s;white-space:nowrap;
}}
.nav-btn:hover,.nav-btn.active {{
  color:var(--accent);border-bottom-color:var(--accent);
}}
.nav-badge {{
  background:var(--surface3);border-radius:10px;
  padding:1px 7px;font-size:10px;margin-left:6px;
}}

/* ── CONTENT ── */
.gr-content {{
  max-width:1280px;margin:0 auto;padding:52px 64px;
}}
.section {{ margin-bottom:56px; }}

.section-head {{
  display:flex;align-items:center;gap:14px;
  margin-bottom:24px;padding-bottom:14px;
  border-bottom:1px solid var(--border);
}}
.section-icon {{
  width:34px;height:34px;border-radius:9px;
  display:flex;align-items:center;justify-content:center;
  font-size:15px;
  background:rgba(0,229,255,.08);
  border:1px solid rgba(0,229,255,.18);
}}
.section-title {{
  font-family:'Syne',sans-serif;font-size:20px;font-weight:700;color:#fff;
}}
.section-count {{
  margin-left:auto;
  background:var(--surface2);border:1px solid var(--border);
  border-radius:20px;padding:3px 13px;
  font-size:11px;color:var(--text-dim);
  font-family:'JetBrains Mono',monospace;
}}

/* ── SUMMARY GRID ── */
.summary-grid {{
  display:grid;grid-template-columns:repeat(5,1fr);gap:14px;
  margin-bottom:48px;
}}
.sev-card {{
  background:var(--surface);border:1px solid var(--border);
  border-radius:14px;padding:22px 16px;text-align:center;
  position:relative;overflow:hidden;
  transition:transform .2s,border-color .2s;cursor:default;
}}
.sev-card::before {{
  content:'';position:absolute;top:0;left:0;right:0;height:3px;
}}
.sev-card::after {{
  content:'';position:absolute;inset:0;
  background:linear-gradient(180deg,rgba(255,255,255,.02) 0%,transparent 100%);
}}
.sev-card:hover{{transform:translateY(-3px);border-color:var(--border2);}}
.sev-count {{
  font-family:'Syne',sans-serif;font-size:40px;font-weight:800;
  line-height:1;margin-bottom:6px;
}}
.sev-name {{
  font-size:11px;text-transform:uppercase;letter-spacing:.1em;color:var(--text-dim);
}}

/* ── TOOLBAR ── */
.toolbar {{
  display:flex;gap:10px;flex-wrap:wrap;align-items:center;
  margin-bottom:20px;
}}
.filter-btn {{
  background:var(--surface2);border:1px solid var(--border);
  border-radius:6px;padding:6px 15px;
  font-size:11px;color:var(--text-dim);cursor:pointer;
  font-family:'JetBrains Mono',monospace;transition:all .15s;
}}
.filter-btn:hover,.filter-btn.active {{
  background:rgba(0,229,255,.09);
  border-color:rgba(0,229,255,.28);color:var(--accent);
}}
.dl-btn {{
  display:inline-flex;align-items:center;gap:8px;
  background:rgba(0,230,118,.08);
  border:1px solid rgba(0,230,118,.25);
  border-radius:6px;padding:6px 15px;
  font-size:11px;color:var(--green);cursor:pointer;
  font-family:'JetBrains Mono',monospace;transition:all .15s;
  margin-left:auto;
}}
.dl-btn:hover{{background:rgba(0,230,118,.14);}}

/* ── FINDING CARD ── */
.finding-card {{
  background:var(--surface);border:1px solid var(--border);
  border-radius:13px;margin-bottom:10px;overflow:hidden;
  transition:border-color .2s;
}}
.finding-card:hover{{border-color:var(--border2);}}
.finding-header {{
  display:flex;align-items:center;gap:12px;
  padding:15px 20px;cursor:pointer;user-select:none;
}}
.sev-badge {{
  display:inline-flex;align-items:center;
  padding:3px 10px;border-radius:5px;
  font-size:10px;font-weight:700;letter-spacing:.08em;
  text-transform:uppercase;white-space:nowrap;
  font-family:'JetBrains Mono',monospace;
}}
.finding-title {{font-weight:500;color:#e2eaf4;font-size:14px;flex:1;}}
.finding-cat {{
  font-size:10px;color:var(--text-dim);
  background:var(--surface2);padding:2px 9px;
  border-radius:4px;font-family:'JetBrains Mono',monospace;
}}
.finding-loc {{
  font-size:10px;color:var(--accent);opacity:.6;
  font-family:'JetBrains Mono',monospace;
  max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;
}}
.chevron {{color:var(--text-dim);font-size:11px;transition:transform .2s;margin-left:6px;}}
.chevron.open{{transform:rotate(90deg);}}

.finding-body {{
  display:none;padding:0 20px 20px;
  border-top:1px solid var(--border);
}}
.finding-body.open{{display:block;}}

.detail-grid {{
  display:grid;grid-template-columns:110px 1fr;gap:9px 18px;margin-top:16px;
}}
.dl{{
  font-size:10px;text-transform:uppercase;letter-spacing:.08em;
  color:var(--text-dim);padding-top:2px;font-family:'JetBrains Mono',monospace;
}}
.dv{{font-size:13px;color:var(--text);line-height:1.55;}}
.evidence-block {{
  background:rgba(0,0,0,.35);border:1px solid var(--border);
  border-radius:7px;padding:9px 13px;
  font-family:'JetBrains Mono',monospace;font-size:12px;
  color:#9cb0c8;word-break:break-all;
}}
.location-block {{
  background:rgba(0,229,255,.04);border:1px solid rgba(0,229,255,.12);
  border-radius:7px;padding:7px 12px;
  font-family:'JetBrains Mono',monospace;font-size:11px;
  color:var(--accent);word-break:break-all;
}}
.cwe-pill {{
  display:inline-block;
  background:rgba(124,58,237,.14);border:1px solid rgba(124,58,237,.3);
  color:#a78bfa;border-radius:5px;padding:2px 9px;
  font-family:'JetBrains Mono',monospace;font-size:11px;
}}

/* ── INSIGHTS ── */
.insight-card {{
  background:var(--surface);border:1px solid var(--border);
  border-radius:13px;padding:22px 26px;margin-bottom:12px;
  position:relative;overflow:hidden;
}}
.insight-card::before {{
  content:'';position:absolute;left:0;top:0;bottom:0;width:4px;
}}
.insight-type {{
  font-size:10px;text-transform:uppercase;letter-spacing:.12em;
  margin-bottom:6px;font-family:'JetBrains Mono',monospace;opacity:.7;
}}
.insight-title {{
  font-family:'Syne',sans-serif;font-size:17px;font-weight:700;
  color:#fff;margin-bottom:10px;
}}
.insight-desc {{
  color:var(--text-mid);font-size:13px;line-height:1.6;margin-bottom:14px;
}}
.comp-tags{{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:14px;}}
.comp-tag {{
  background:rgba(255,255,255,.04);border:1px solid var(--border);
  border-radius:4px;padding:2px 10px;font-size:11px;
  color:var(--text-dim);font-family:'JetBrains Mono',monospace;
}}
.insight-rec {{
  background:rgba(0,200,83,.06);border:1px solid rgba(0,200,83,.15);
  border-radius:8px;padding:12px 16px;
  font-size:12px;color:#69f0ae;
  font-family:'JetBrains Mono',monospace;white-space:pre-line;
}}

/* ── TECH STACK ── */
.tech-grid{{display:flex;flex-wrap:wrap;gap:10px;}}
.tech-pill {{
  display:flex;align-items:center;gap:10px;
  background:var(--surface2);border:1px solid var(--border);
  border-radius:9px;padding:9px 16px;
}}
.tech-dot{{width:8px;height:8px;border-radius:50%;flex-shrink:0;}}
.tech-name{{font-size:13px;font-weight:500;color:var(--text);}}
.tech-cat{{font-size:11px;color:var(--text-dim);}}
.tech-ver{{font-size:11px;color:var(--medium);font-family:'JetBrains Mono',monospace;margin-left:4px;}}

/* ── AUTHOR CARD ── */
.author-card {{
  background:linear-gradient(135deg,var(--surface) 0%,var(--surface2) 100%);
  border:1px solid var(--border2);border-radius:16px;
  padding:32px 36px;
  display:flex;align-items:center;gap:28px;flex-wrap:wrap;
}}
.author-avatar {{
  width:72px;height:72px;border-radius:50%;
  background:linear-gradient(135deg,var(--accent),var(--accent2));
  display:flex;align-items:center;justify-content:center;
  font-family:'JetBrains Mono',monospace;font-size:24px;font-weight:700;
  color:#fff;flex-shrink:0;
  box-shadow:0 0 24px rgba(0,229,255,.2);
}}
.author-info{{flex:1;min-width:200px;}}
.author-name {{
  font-family:'Syne',sans-serif;font-size:22px;font-weight:800;color:#fff;
  margin-bottom:4px;
}}
.author-tagline {{font-size:13px;color:var(--text-mid);margin-bottom:16px;}}
.author-links{{display:flex;gap:10px;flex-wrap:wrap;}}
.author-link {{
  display:inline-flex;align-items:center;gap:8px;
  background:rgba(10,102,194,.15);border:1px solid rgba(10,102,194,.3);
  border-radius:7px;padding:8px 16px;
  font-size:12px;color:#70b5f9;text-decoration:none;
  font-family:'JetBrains Mono',monospace;transition:all .15s;
}}
.author-link:hover{{background:rgba(10,102,194,.25);color:#93c5fd;}}
.author-link.github {{
  background:rgba(255,255,255,.05);border-color:rgba(255,255,255,.12);
  color:var(--text-mid);
}}
.author-link.github:hover{{color:#fff;background:rgba(255,255,255,.1);}}
.author-stats{{display:flex;gap:20px;margin-top:20px;flex-wrap:wrap;}}
.a-stat{{text-align:center;}}
.a-stat .num {{
  font-family:'Syne',sans-serif;font-size:26px;font-weight:800;color:var(--accent);
}}
.a-stat .lbl {{font-size:10px;color:var(--text-dim);text-transform:uppercase;letter-spacing:.08em;}}

/* ── FOOTER ── */
.gr-footer {{
  border-top:1px solid var(--border);
  padding:28px 64px;max-width:1280px;margin:0 auto;
  display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:16px;
}}
.footer-brand {{
  font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--text-dim);
}}
.footer-brand strong{{color:var(--accent);}}
.footer-legal {{font-size:11px;color:var(--text-dim);}}

/* ── TAB CONTENT ── */
.tab-section{{display:none;}}
.tab-section.active{{display:block;}}

@media(max-width:900px){{
  .header-inner{{padding:24px;grid-template-columns:1fr;}}
  .gr-nav-inner{{padding:0 16px;}}
  .gr-content{{padding:32px 16px;}}
  .summary-grid{{grid-template-columns:repeat(3,1fr);}}
  .gr-footer{{padding:20px 16px;}}
}}
</style>
</head>
<body>

<!-- HEADER -->
<header class="gr-header">
  <canvas id="matrix-canvas"></canvas>
  <div class="header-inner">
    <div>
      <pre class="ascii-logo">
  ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗    ██████╗ ███████╗ ██████╗ ██████╗ ███╗
 ██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝    ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗
 ██║  ███╗███████║██║   ██║███████╗   ██║       ██████╔╝█████╗  ██║     ██║   ██║██╔██╗
 ██║   ██║██╔══██║██║   ██║╚════██║   ██║       ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗
 ╚██████╔╝██║  ██║╚██████╔╝███████║   ██║       ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████╗
  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝       ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚══╝</pre>
      <div class="tool-badge">GhostRecon v2.0 · Passive Web Intelligence Engine</div>
      <h1 class="report-title">Security Assessment<br><span>Intelligence Report</span></h1>
      <p class="target-line">Target: <strong>{result.target.raw_url}</strong></p>
      <p class="target-line" style="margin-top:4px">Host: <strong>{result.target.host}</strong> &nbsp;|&nbsp; Path: <strong>{result.target.path}</strong></p>
      <div class="meta-row">
        <div class="meta-chip"><div class="lbl">Scan Time</div><div class="val">{scan_time}</div></div>
        <div class="meta-chip"><div class="lbl">Duration</div><div class="val">{duration}s</div></div>
        <div class="meta-chip"><div class="lbl">Total Findings</div><div class="val">{total_findings}</div></div>
        <div class="meta-chip"><div class="lbl">Scan Type</div><div class="val">Passive Recon</div></div>
      </div>
    </div>
    <div class="risk-gauge">
      <div class="lbl">Overall Risk Score</div>
      <div class="risk-score-num" style="color:{risk_color}">{result.risk_score}</div>
      <div style="font-size:13px;color:var(--text-dim)">/100</div>
      <div class="risk-level-pill"
           style="background:{risk_color}20;color:{risk_color};border:1px solid {risk_color}44">
        {result.risk_label}
      </div>
    </div>
  </div>
</header>

<!-- NAV -->
<nav class="gr-nav">
  <div class="gr-nav-inner">
    <button class="nav-btn active" onclick="showTab('findings')">⚠ Findings <span class="nav-badge">{total_findings}</span></button>
    <button class="nav-btn" onclick="showTab('insights')">🔗 Correlations <span class="nav-badge">{len(insights)}</span></button>
    <button class="nav-btn" onclick="showTab('tech')">🔬 Fingerprint</button>
    <button class="nav-btn" onclick="showTab('author')">👤 Author</button>
    <button class="nav-btn" onclick="showTab('export')">⬇ Export</button>
  </div>
</nav>

<!-- MAIN CONTENT -->
<main class="gr-content">

  <!-- Summary always visible -->
  <div id="summary-section">
    <div class="section-head">
      <div class="section-icon">📊</div>
      <h2 class="section-title">Findings Overview</h2>
    </div>
    {summary_cards}
  </div>

  <!-- FINDINGS TAB -->
  <div id="tab-findings" class="tab-section active section">
    <div class="section-head">
      <div class="section-icon">⚠</div>
      <h2 class="section-title">Security Findings</h2>
      <span class="section-count">{total_findings} total</span>
    </div>

    <div class="toolbar">
      <button class="filter-btn active" onclick="filterFindings('all',this)">All</button>
      <button class="filter-btn" onclick="filterFindings('Critical',this)" style="color:#ff1744">Critical</button>
      <button class="filter-btn" onclick="filterFindings('High',this)" style="color:#ff6d00">High</button>
      <button class="filter-btn" onclick="filterFindings('Medium',this)" style="color:#ffab00">Medium</button>
      <button class="filter-btn" onclick="filterFindings('Low',this)" style="color:#2196f3">Low</button>
      <button class="filter-btn" onclick="filterFindings('Info',this)" style="color:#607d8b">Info</button>
      <button class="dl-btn" onclick="downloadFindings('json')">⬇ JSON</button>
      <button class="dl-btn" onclick="downloadFindings('csv')">⬇ CSV</button>
    </div>

    <div id="findingsContainer">
      {findings_html}
    </div>
  </div>

  <!-- INSIGHTS TAB -->
  <div id="tab-insights" class="tab-section section">
    <div class="section-head">
      <div class="section-icon" style="background:rgba(124,58,237,.1);border-color:rgba(124,58,237,.2)">🔗</div>
      <h2 class="section-title">Correlation Intelligence</h2>
      <span class="section-count">{len(insights)} attack chains</span>
    </div>
    {insights_html if insights_html else '<p style="color:var(--text-dim);padding:32px 0;text-align:center">No compound attack chains detected.</p>'}
  </div>

  <!-- TECH TAB -->
  <div id="tab-tech" class="tab-section section">
    <div class="section-head">
      <div class="section-icon">🔬</div>
      <h2 class="section-title">Technology Fingerprint</h2>
    </div>
    {tech_html if tech_html else '<p style="color:var(--text-dim);padding:32px 0;text-align:center">No technologies fingerprinted.</p>'}
  </div>

  <!-- AUTHOR TAB -->
  <div id="tab-author" class="tab-section section">
    <div class="section-head">
      <div class="section-icon">👤</div>
      <h2 class="section-title">About the Author</h2>
    </div>
    <div class="author-card">
      <div class="author-avatar">0x</div>
      <div class="author-info">
        <div class="author-name">0xdzubair</div>
        <div class="author-tagline">Ethical Hacker · Security Researcher · Passive Recon Specialist</div>
        <div class="author-links">
          <a class="author-link" href="https://www.linkedin.com/in/muhammad09-zubair-aa592430b" target="_blank" rel="noopener">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor">
              <path d="M20.447 20.452h-3.554v-5.569c0-1.328-.027-3.037-1.852-3.037-1.853 0-2.136 1.445-2.136 2.939v5.667H9.351V9h3.414v1.561h.046c.477-.9 1.637-1.85 3.37-1.85 3.601 0 4.267 2.37 4.267 5.455v6.286zM5.337 7.433c-1.144 0-2.063-.926-2.063-2.065 0-1.138.92-2.063 2.063-2.063 1.14 0 2.064.925 2.064 2.063 0 1.139-.925 2.065-2.064 2.065zm1.782 13.019H3.555V9h3.564v11.452zM22.225 0H1.771C.792 0 0 .774 0 1.729v20.542C0 23.227.792 24 1.771 24h20.451C23.2 24 24 23.227 24 22.271V1.729C24 .774 23.2 0 22.222 0h.003z"/>
            </svg>
            LinkedIn — Muhammad Zubair
          </a>
          <a class="author-link github" href="https://github.com/0xdzubair" target="_blank" rel="noopener">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor">
              <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/>
            </svg>
            GitHub — 0xdzubair
          </a>
        </div>
      </div>
      <div class="author-stats">
        <div class="a-stat"><div class="num">{total_findings}</div><div class="lbl">Findings<br>This Scan</div></div>
        <div class="a-stat"><div class="num">{len(insights)}</div><div class="lbl">Attack<br>Chains</div></div>
        <div class="a-stat"><div class="num">6</div><div class="lbl">Analysis<br>Modules</div></div>
      </div>
    </div>
  </div>

  <!-- EXPORT TAB -->
  <div id="tab-export" class="tab-section section">
    <div class="section-head">
      <div class="section-icon">⬇</div>
      <h2 class="section-title">Export Findings</h2>
    </div>
    <div style="display:flex;gap:16px;flex-wrap:wrap;">
      <button class="dl-btn" onclick="downloadFindings('json')" style="font-size:14px;padding:14px 28px;">
        ⬇ Download JSON Report
      </button>
      <button class="dl-btn" onclick="downloadFindings('csv')" style="font-size:14px;padding:14px 28px;">
        ⬇ Download CSV Report
      </button>
    </div>
    <p style="color:var(--text-dim);margin-top:24px;font-size:13px;font-family:'JetBrains Mono',monospace;">
      JSON includes full metadata, correlations, and tech stack.<br>
      CSV is a flat findings sheet for spreadsheet analysis.
    </p>
  </div>

</main>

<!-- FOOTER -->
<footer>
  <div class="gr-footer">
    <div class="footer-brand">
      <strong>GhostRecon</strong> v2.0 · Passive Web Intelligence Engine<br>
      by <strong>0xdzubair</strong> ·
      <a href="https://www.linkedin.com/in/muhammad09-zubair-aa592430b" style="color:var(--accent);text-decoration:none">LinkedIn</a> ·
      <a href="https://github.com/0xdzubair" style="color:var(--accent);text-decoration:none">GitHub</a>
    </div>
    <div class="footer-legal">
      For authorized security testing only. Passive analysis — no exploits, no attacks.<br>
      Generated: {generated_date}
    </div>
  </div>
</footer>

<script>
// ── SCAN DATA ──────────────────────────────────────────────────────────────
const SCAN_DATA = {scan_data_json};

// ── MATRIX RAIN ────────────────────────────────────────────────────────────
(function(){{
  const canvas = document.getElementById('matrix-canvas');
  const ctx = canvas.getContext('2d');
  function resize() {{
    canvas.width = canvas.offsetWidth;
    canvas.height = canvas.offsetHeight;
  }}
  resize();
  window.addEventListener('resize', resize);
  const chars = '0123456789ABCDEF><|/\\\\!@#$%^&*()[]{{}}';
  const fontSize = 12;
  let cols = Math.floor(canvas.width / fontSize);
  let drops = Array(cols).fill(1);
  function draw() {{
    ctx.fillStyle = 'rgba(8,11,16,0.04)';
    ctx.fillRect(0,0,canvas.width,canvas.height);
    ctx.fillStyle = '#00e5ff';
    ctx.font = fontSize + 'px JetBrains Mono, monospace';
    for (let i=0;i<drops.length;i++) {{
      ctx.fillText(chars[Math.floor(Math.random()*chars.length)], i*fontSize, drops[i]*fontSize);
      if (drops[i]*fontSize > canvas.height && Math.random() > 0.975) drops[i]=0;
      drops[i]++;
    }}
  }}
  setInterval(draw,55);
}})();

// ── TABS ───────────────────────────────────────────────────────────────────
function showTab(name) {{
  document.querySelectorAll('.tab-section').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(btn => btn.classList.remove('active'));
  document.getElementById('tab-' + name).classList.add('active');
  event.currentTarget.classList.add('active');
}}

// ── FINDING TOGGLE ─────────────────────────────────────────────────────────
document.querySelectorAll('.finding-header').forEach(h => {{
  h.addEventListener('click', () => {{
    const body    = h.nextElementSibling;
    const chevron = h.querySelector('.chevron');
    body.classList.toggle('open');
    chevron.classList.toggle('open');
  }});
}});

// ── FILTER ─────────────────────────────────────────────────────────────────
function filterFindings(sev, btn) {{
  document.querySelectorAll('.finding-card').forEach(c => {{
    c.style.display = (sev === 'all' || c.dataset.severity === sev) ? '' : 'none';
  }});
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
}}

// ── DOWNLOADS ──────────────────────────────────────────────────────────────
function downloadFindings(fmt) {{
  const host = SCAN_DATA.meta.target.replace(/https?:\\/\\//, '').replace(/[^a-zA-Z0-9.-]/g,'_');
  if (fmt === 'json') {{
    const blob = new Blob([JSON.stringify(SCAN_DATA, null, 2)], {{type:'application/json'}});
    _dl(blob, 'ghostrecon_' + host + '.json');
  }} else {{
    const rows = [['Title','Severity','Category','Description','Evidence','Location','CWE','Recommendation']];
    SCAN_DATA.findings.forEach(f => rows.push([
      f.title, f.severity, f.category, f.description,
      f.evidence||'', f.location||'', f.cwe||'', f.recommendation
    ]));
    const csv = rows.map(r => r.map(v => '"'+String(v).replace(/"/g,'""')+'"').join(',')).join('\\n');
    const blob = new Blob([csv], {{type:'text/csv'}});
    _dl(blob, 'ghostrecon_' + host + '.csv');
  }}
}}
function _dl(blob, name) {{
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}}
</script>
</body>
</html>"""

    # ── RENDER HELPERS ─────────────────────────────────────────────────────────

    def _render_summary_cards(self, sev_counts) -> str:
        styles = {
            "Critical": "#ff1744",
            "High":     "#ff6d00",
            "Medium":   "#ffab00",
            "Low":      "#2196f3",
            "Info":     "#607d8b",
        }
        html = '<div class="summary-grid">'
        for sev, color in styles.items():
            count = sev_counts.get(sev, 0)
            html += f"""
            <div class="sev-card" style="border-top-color:{color}">
              <div class="sev-count" style="color:{color}">{count}</div>
              <div class="sev-name">{sev}</div>
            </div>"""
        html += "</div>"
        return html

    def _render_findings(self, findings) -> str:
        if not findings:
            return '<p style="color:var(--text-dim);text-align:center;padding:48px">No findings detected.</p>'
        sev_order = ["Critical", "High", "Medium", "Low", "Info"]
        colors = self.SEVERITY_COLORS
        html = ""
        for f in sorted(findings, key=lambda x: sev_order.index(x.severity)):
            color = colors.get(f.severity, "#7b8ea0")
            loc   = getattr(f, "location", None) or ""
            cwe   = getattr(f, "cwe", None) or ""
            ev    = getattr(f, "evidence", None) or ""
            loc_html = f'<div class="location-block">📍 {loc}</div>' if loc else ""
            ev_html  = f'<div class="evidence-block">{ev}</div>' if ev else ""
            cwe_html = f'<span class="cwe-pill">{cwe}</span>' if cwe else ""
            loc_disp = (loc[:55] + "…") if len(loc) > 58 else loc

            html += f"""
            <div class="finding-card" data-severity="{f.severity}">
              <div class="finding-header">
                <span class="sev-badge" style="background:{color}22;color:{color};border:1px solid {color}44">{f.severity}</span>
                <span class="finding-title">{f.title}</span>
                <span class="finding-cat">{f.category}</span>
                {f'<span class="finding-loc" title="{loc}">📍 {loc_disp}</span>' if loc else ""}
                <span class="chevron">▶</span>
              </div>
              <div class="finding-body">
                <div class="detail-grid">
                  <span class="dl">Description</span><span class="dv">{f.description}</span>
                  <span class="dl">Remediation</span><span class="dv">{f.recommendation}</span>
                  {"<span class='dl'>Evidence</span><span class='dv'>" + ev_html + "</span>" if ev else ""}
                  {"<span class='dl'>Location</span><span class='dv'>" + loc_html + "</span>" if loc else ""}
                  {"<span class='dl'>CWE</span><span class='dv'>" + cwe_html + "</span>" if cwe else ""}
                </div>
              </div>
            </div>"""
        return html

    def _render_insights(self, insights) -> str:
        if not insights:
            return ""
        colors = self.SEVERITY_COLORS
        html = ""
        for ins in insights:
            color = colors.get(ins.get("severity", "Info"), "#7b8ea0")
            comps = "".join(f'<span class="comp-tag">{c}</span>' for c in ins.get("components", []))
            html += f"""
            <div class="insight-card" style="border-left-color:{color}">
              <div class="insight-type" style="color:{color}">{ins.get('type','Pattern')} · {ins.get('severity','Info')}</div>
              <div class="insight-title">{ins.get('title','')}</div>
              <p class="insight-desc">{ins.get('description','')}</p>
              <div class="comp-tags">{comps}</div>
              <div class="insight-rec">💡 {ins.get('recommendation','')}</div>
            </div>"""
        return html

    def _render_tech_stack(self, tech_stack) -> str:
        if not tech_stack:
            return ""
        cat_colors = {
            "Web Server":              "#4a9fd4",
            "Backend Language":        "#00c48c",
            "Backend Framework":       "#00c48c",
            "CMS":                     "#f5a623",
            "Frontend Framework":      "#ff6b35",
            "CDN/WAF":                 "#7c3aed",
            "CDN":                     "#7c3aed",
            "Database (Error Disclosure)": "#ff3860",
        }
        html = '<div class="tech-grid">'
        for t in tech_stack:
            color = cat_colors.get(t.get("category", ""), "#7b8ea0")
            ver   = t.get("version", "")
            html += f"""
            <div class="tech-pill">
              <div class="tech-dot" style="background:{color}"></div>
              <div>
                <div class="tech-name">{t['name']}{f'<span class="tech-ver">v{ver}</span>' if ver else ''}</div>
                <div class="tech-cat">{t.get('category','')}</div>
              </div>
            </div>"""
        html += "</div>"
        return html
