# Threat Lookup

Threat Lookup is a Streamlit-based IOC triage dashboard that checks indicators against multiple threat intelligence providers and returns a scored verdict with analyst-friendly evidence.

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
- Weighted scoring with clear verdict classes:
  - Malicious
  - Suspicious
  - Low Risk
  - Benign
- Fast concurrent batch processing with configurable workers and pacing.
- Streamlit dashboard with:
  - Upload or paste IOC input
  - Clickable result rows and detail pane
  - Per-source evidence display
  - CSV and JSON export

## Project Structure
- app.py: Streamlit dashboard.
- threat_lookup.py: Core scoring engine and API integrations.
- run_gui.py: Local launcher for Streamlit.
- launch_dashboard.bat: One-click Windows launch helper.
- setup.ps1: Environment setup script.
- requirements.txt: Python dependencies.
- data/: Sample IOC input files.
- outputs/: Generated benchmark and result files.
- docs/: Setup guide, UML/DFD, and SDLC.
- threat_lookup_final/: Curated package for supervisor handoff.

## Requirements
- Windows 10 or 11
- Python 3.10+
- Internet access for API calls
- API keys for intelligence providers

## Quick Start
1. Run setup:
   - PowerShell: `./setup.ps1`
2. Configure environment variables in `.env` (or copy from `.env.example`).
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

Optional Silent Push setting:
- SILENTPUSH_API_BASE_URL=https://api.silentpush.com/api/v1/merge-api
- SILENTPUSH_META_API_BASE_URL=https://api.silentpush.com/api/v1/meta-api
- SILENTPUSH_V2_API_BASE_URL=https://api.silentpush.com/api/v2
- SILENTPUSH_MAX_ENRICH_CALLS=2
- SILENTPUSH_MAX_NON_EXPLORE_CALLS=4
- SILENTPUSH_ENABLE_CONTEXT_GRAPH_SEARCH=true
- SILENTPUSH_ENABLE_ENRICH_INDICATOR=true
- SILENTPUSH_ENABLE_LIVE_SCAN=true
- SILENTPUSH_ENABLE_THREAT_RANKING=true
- SILENTPUSH_VERBOSE_NON_EXPLORE_ERRORS=false
- SILENTPUSH_VERBOSE_EXPLORE_ERRORS=false
- SILENTPUSH_SPQL_PAYLOAD_MODE=auto
- SILENTPUSH_SPQL_QUERY_TEMPLATE=SELECT * FROM scandata WHERE query='{indicator}' LIMIT 25
- SILENTPUSH_SPQL_QUERY_TEMPLATE_ALT=SELECT * FROM scandata WHERE indicator='{indicator}' LIMIT 25

Notes for Context Graph Search SPQL:
- `SILENTPUSH_SPQL_PAYLOAD_MODE` controls JSON key for the SPQL body (`auto`, `query`, `spql`, or `statement`).
- `SILENTPUSH_SPQL_QUERY_TEMPLATE` and `SILENTPUSH_SPQL_QUERY_TEMPLATE_ALT` support placeholders: `{indicator}`, `{ioc}`, `{query}`, `{type}`, `{ioc_type}`.
- In `auto` mode, the app attempts common documented payload-key shapes but reports only concise per-family status unless verbose errors are enabled.
- Live Scan is attempted for URL IOCs only; non-URL indicators are marked as skipped to avoid noisy server-side errors.
- Explore enrichment output defaults to concise status (`explore_enrichment_status`), with detailed failed endpoint attempts only when `SILENTPUSH_VERBOSE_EXPLORE_ERRORS=true`.

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

## Supervisor Handoff
Use the threat_lookup_final folder when sharing with your supervisor. It includes the runnable app, setup scripts, docs, and sample IOC data in one place.

## Notes
- This tool provides triage intelligence and confidence-based context.
- It does not guarantee exact incident attribution for every IOC.
