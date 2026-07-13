# Threat Lookup

Threat Lookup is a multi-source IOC triage tool that includes:

- A Streamlit dashboard for analyst workflows
- A CLI for single IOC and batch analysis

It enriches indicators from multiple threat intelligence providers, computes a composite risk score, and returns a verdict with source-level evidence.

## Features
- Multi-source IOC enrichment from:
  - VirusTotal
  - AlienVault OTX
  - AbuseIPDB (for IP indicators)
  - ThreatFox
  - Silent Push APIs:
    - Explore API (risk score plus best-effort WHOIS/DNS/enrichment pivots)
    - Context Graph Search API via `POST /api/v1/meta-api/explore/spql/search`
    - Enrich Indicator via Explore enrichment endpoints
    - Live Scan API via `POST /api/v2/live-scan/scan-on-demand`
    - Threat Ranking API via `/api/v2/iocs/threat-ranking`
  - Spur Context API (for IP indicators)
  - ReversingLabs Spectra Analyze (for IPs, domains, URLs, and hashes)
    - Best-effort WHOIS / registration context surfacing when returned by the Spectra instance
- IOC types supported:
  - IP
  - Domain
  - URL
  - Hash (MD5, SHA1, SHA256)
- Weighted scoring with clear verdict classes:
  - Malicious
  - Suspicious
  - Low Risk
  - Benign
- Fast concurrent batch processing with configurable workers and pacing.
- Streamlit dashboard with:
  - Source toggles per provider
  - API health indicators in sidebar and landing view
  - Upload or paste IOC input
  - Clickable result rows and detail pane
  - Per-source evidence display
  - KPI cards and summary charts
  - CSV and JSON export
- CLI with:
  - Single IOC analysis or file-based batch mode
  - TXT and Excel input support
  - JSON, CSV, and XLSX output
  - Batch size, cooldown, deduplication, and max IOC controls

## Project Structure
- app.py: Streamlit dashboard.
- threat_lookup.py: Core scoring engine and API integrations.
- run_gui.py: Local launcher for Streamlit.
- launch_dashboard.bat: One-click Windows launch helper.
- setup.ps1: Environment setup script.
- requirements.txt: Python dependencies.
- data/: Sample IOC input files.
- docs/: Setup guide, UML/DFD, and SDLC.
- .env.example: Template for environment configuration.

Note: outputs are generated when you export or run CLI commands with output paths.

## Requirements
- Windows 10 or 11
- Python 3.10+
- Internet access for API calls
- API keys for intelligence providers

## Quick Start
1. Run setup (creates .venv and installs dependencies):
   - PowerShell: `./setup.ps1`
2. Copy `.env.example` to `.env` and add API keys.
3. Launch dashboard:
   - Double-click `launch_dashboard.bat`
   - Or run: `python run_gui.py`
4. Open the UI at:
   - `http://localhost:8501`

## Environment Variables
Required core keys:
- VT_API_KEY
- OTX_API_KEY
- ABUSE_API_KEY
- THREATFOX_API_KEY
- SILENTPUSH_API_KEY
- SPUR_API_KEY
- RL_SPECTRA_BASE_URL
- RL_SPECTRA_TOKEN

Optional and advanced settings:
- SILENTPUSH_API_BASE_URL
- SILENTPUSH_META_API_BASE_URL
- SILENTPUSH_V2_API_BASE_URL
- SILENTPUSH_MAX_ENRICH_CALLS
- SILENTPUSH_MAX_NON_EXPLORE_CALLS
- SILENTPUSH_ENABLE_CONTEXT_GRAPH_SEARCH
- SILENTPUSH_ENABLE_ENRICH_INDICATOR
- SILENTPUSH_ENABLE_LIVE_SCAN
- SILENTPUSH_ENABLE_THREAT_RANKING
- SILENTPUSH_ENABLE_PADNS_LOOKUP
- SILENTPUSH_ENABLE_BULK_ENRICH
- SILENTPUSH_ENABLE_THREAT_CHECK
- SILENTPUSH_THREAT_CHECK_BASE_URL
- SILENTPUSH_BPH_SUSPECTED_DOMAIN_COUNT
- SILENTPUSH_BPH_LIKELY_DOMAIN_COUNT
- SILENTPUSH_VERBOSE_NON_EXPLORE_ERRORS
- SILENTPUSH_VERBOSE_EXPLORE_ERRORS
- SILENTPUSH_SPQL_PAYLOAD_MODE
- SILENTPUSH_SPQL_QUERY_TEMPLATE
- SILENTPUSH_SPQL_QUERY_TEMPLATE_ALT

Notes for Context Graph Search SPQL:
- `SILENTPUSH_SPQL_PAYLOAD_MODE` controls JSON key for the SPQL body (`auto`, `query`, `spql`, or `statement`).
- `SILENTPUSH_SPQL_QUERY_TEMPLATE` and `SILENTPUSH_SPQL_QUERY_TEMPLATE_ALT` support placeholders: `{indicator}`, `{ioc}`, `{query}`, `{type}`, `{ioc_type}`.
- In `auto` mode, the app attempts common documented payload-key shapes but reports only concise per-family status unless verbose errors are enabled.
- Live Scan is attempted for URL IOCs only; non-URL indicators are marked as skipped to avoid noisy server-side errors.
- Explore enrichment output defaults to concise status (`explore_enrichment_status`), with detailed failed endpoint attempts only when `SILENTPUSH_VERBOSE_EXPLORE_ERRORS=true`.

## CLI Usage
Single IOC:
- `python threat_lookup.py 8.8.8.8`

Batch input file:
- `python threat_lookup.py --file data/iocs.txt --format json --output results.json`

Supported input files:
- TXT (one IOC per line)
- XLSX/XLS (first column)

Output formats:
- json
- csv
- xlsx (requires `--output`)

Useful runtime options:
- `--workers`
- `--delay`
- `--jitter`
- `--batch-size`
- `--batch-cooldown`
- `--max-iocs`

## Scoring Model
Threat Lookup calculates a composite risk score from source-specific evidence, then maps that score to a verdict.

Weighted per-source contribution :
- AlienVault OTX: up to 25 points.
  - Formula: min((pulse_count / 10) * 25, 25), rounded.
  - Example: 4 pulses -> 10 points.
- AbuseIPDB (IP indicators only): up to 20 points.
  - Formula: (abuse_confidence_score / 100) * 20, rounded.
  - Example: 80/100 confidence -> 16 points.
- ThreatFox: up to 20 points.
  - Uses ThreatFox confidence-derived score from the API integration.
- Silent Push Explore API: up to 20 points.
  - Formula: `sp_risk_score` mapped from 0-100 into 0-20 points.
  - Normalized verdict: `Malicious` at `sp_risk_score >= 80`, `Suspicious` at `50-79`, `Low Risk` at `1-49`, else `Benign`.
  - Additional Explore endpoint data is collected as context and exported when available; scoring remains driven by risk score for consistent weighting.
  - Additional Silent Push API families (Context Graph Search, Enrich Indicator, Live Scan, Threat Ranking) are queried using documented endpoints and exported as analyst context when available.
- Spur Context API (IP only): up to 20 points.
  - Formula: risk/tunnel/proxy signals in Spur context are mapped to a capped score.
  - Normalized verdict: `Malicious` when Spur returns one or more risk signals; `Suspicious` when it returns tunnels or proxies without explicit risks; else `Benign`.
- ReversingLabs Spectra Analyze: up to 20 points.
  - Formula: classification, risk score, and malicious indicators from Spectra Analyze responses are mapped to a capped score.

Final verdict thresholds:
- 70 and above: Malicious
- 40 to 69: Suspicious
- 15 to 39: Low Risk
- Below 15: Benign

Early high-confidence override:
- The IOC is immediately labeled Malicious (score 100) if any of these triggers fire:
  - Silent Push returns a normalized `Malicious` verdict
  - Spur returns a normalized `Malicious` verdict
  - ReversingLabs returns `rl_verdict=Malicious`
  - AbuseIPDB abuse score > 90
  - ThreatFox has a match with max confidence >= 90

## Using the App
1. Upload a TXT or Excel IOC file, or paste IOCs line-by-line.
2. Set runtime options (workers, delay, jitter).
3. Run analysis.
4. Click rows in the results table to inspect detailed source evidence.
5. Export results to CSV or JSON.

## Documentation
- docs/setup.md: Installation and troubleshooting.
- docs/uml.md: UML component and sequence diagrams, plus DFD.
- docs/sdlc.md: Project SDLC for governance and supervisor review.

## Future Improvements
<!-- - Add more IOC intelligence sources to improve evidence coverage and reduce dependence on any single provider. -->
<!-- - Move from free-tier API usage to higher-capacity commercial tiers where justified, to reduce rate-limiting and timeout inefficiencies. -->
<!-- - Introduce source-specific rate limiting, retry strategy tuning, and caching to improve performance and stability. -->
<!-- - Expand AI-assisted analysis by using a retained internal evidence store or analyst knowledge base rather than only live per-run context. -->
- Add richer incident context such as first-seen/last-seen timelines, related infrastructure pivots, and stronger campaign correlation.
- Add  integration with SIEM, EDR, MISP or case-management tooling for validation against internal telemetry.


## Notes
- This tool provides triage intelligence and confidence-based context.
- It does not guarantee exact incident attribution for every IOC.
