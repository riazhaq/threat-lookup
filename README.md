# Threat Lookup

Threat Lookup is a multi-source IOC triage tool with both:

- A Streamlit dashboard for analyst-friendly investigation
- A CLI for batch processing and exports

The project obtains indicators from several intelligence providers, builds a composite risk score, and returns a final verdict with supporting evidence.

## What It Supports

Indicator types:

- IP
- Domain
- URL
- Hash (MD5, SHA1, SHA256)

Integrated providers:

- VirusTotal
- AlienVault OTX
- AbuseIPDB (IP only)
- ThreatFox
- Silent Push
  - Explore risk score
  - Context Graph Search (SPQL)
  - Enrich Indicator
  - Live Scan (URL only)
  - Threat Ranking
- Spur Context API (IP only)
- ReversingLabs Spectra Analyze

## Project Layout

- `app.py` - Streamlit dashboard
- `threat_lookup.py` - core analysis engine and provider integrations
- `run_gui.py` - local Streamlit launcher
- `launch_dashboard.bat` - one-click Windows launcher
- `setup.ps1` - environment bootstrap script
- `requirements.txt` - Python dependencies
- `data/` - sample IOC input files
- `outputs/` - generated result artifacts
- `docs/` - setup, architecture, and SDLC docs
- `threat_lookup_final/` - packaged handoff copy

## Requirements

- Windows 10/11
- Python 3.10+
- Internet access
- API credentials for enabled providers

## Quick Start (Windows)

1. Install dependencies:

   ```powershell
   ./setup.ps1
   ```

2. Create local config:

   ```powershell
   Copy-Item .env.example .env
   ```

3. Add your API keys to `.env`.

4. Start the dashboard:

   ```powershell
   python run_gui.py
   ```

   Or double-click `launch_dashboard.bat`.

5. Open:

   `http://localhost:8501`

## CLI Usage

Single IOC:

```powershell
python threat_lookup.py 8.8.8.8
```

Bulk file input:

```powershell
python threat_lookup.py --file data/iocs.txt --format json --output outputs/results.json
```

Common bulk tuning options:

- `--workers` concurrent IOC workers (default `10`)
- `--delay` minimum seconds between IOC starts (minimum/default `0.01`)
- `--jitter` random extra delay to reduce burst patterns (default `0.0`)
- `--batch-size` IOC chunk size before cooldown (default `150`)
- `--batch-cooldown` pause between batches in seconds (default `30`)
- `--max-iocs` optional cap after deduplication (default `0`, no cap)

Output formats:

- `json` (default)
- `csv`
- `xlsx` (requires `--output`)

## Environment Variables

Copy from `.env.example` and populate values.

Core keys:

- `VT_API_KEY`
- `OTX_API_KEY`
- `ABUSE_API_KEY`
- `THREATFOX_API_KEY`
- `SILENTPUSH_API_KEY`
- `SPUR_API_KEY`
- `RL_SPECTRA_BASE_URL`
- `RL_SPECTRA_TOKEN`

Spur Context API options:

- `SPUR_CONTEXT_DT` (format `YYYYmmdd`, enterprise historical access required)
- `SPUR_USE_MAXMIND_GEO` (`true`/`false`, maps to `mmgeo=1`)
- `SPUR_ENABLE_TAG_METADATA` (`true`/`false`, enables `/v2/metadata/tags/:tag` enrichment)
- `SPUR_MAX_TAG_METADATA` (max tag metadata lookups per IOC)

Silent Push tuning and endpoint controls:

- `SILENTPUSH_API_BASE_URL`
- `SILENTPUSH_META_API_BASE_URL`
- `SILENTPUSH_V2_API_BASE_URL`
- `SILENTPUSH_MAX_ENRICH_CALLS`
- `SILENTPUSH_MAX_NON_EXPLORE_CALLS`
- `SILENTPUSH_ENABLE_CONTEXT_GRAPH_SEARCH`
- `SILENTPUSH_ENABLE_ENRICH_INDICATOR`
- `SILENTPUSH_ENABLE_LIVE_SCAN`
- `SILENTPUSH_ENABLE_THREAT_RANKING`
- `SILENTPUSH_VERBOSE_NON_EXPLORE_ERRORS`
- `SILENTPUSH_VERBOSE_EXPLORE_ERRORS`
- `SILENTPUSH_SPQL_PAYLOAD_MODE`
- `SILENTPUSH_SPQL_QUERY_TEMPLATE`
- `SILENTPUSH_SPQL_QUERY_TEMPLATE_ALT`

SPQL notes:

- `SILENTPUSH_SPQL_PAYLOAD_MODE` supports `auto`, `query`, `spql`, and `statement`.
- Query templates support placeholders including `{indicator}`, `{ioc}`, `{query}`, `{type}`, and `{ioc_type}`.

## Scoring and Verdicts

Threat Lookup computes a composite score from source evidence, then maps it to a verdict.

Verdict thresholds:

- `>= 70` -> Malicious
- `40-69` -> Suspicious
- `15-39` -> Low Risk
- `< 15` -> Benign

High-confidence override:

The IOC is immediately labeled Malicious (score 100) when one of these triggers is present:

- Silent Push normalized verdict is Malicious
- Spur normalized verdict is Malicious
- ReversingLabs verdict is Malicious
- AbuseIPDB abuse score > 90
- ThreatFox max confidence >= 90

## Dashboard Workflow

1. Upload TXT/XLSX input or paste IOCs
2. Run analysis with worker and pacing controls
3. Select a row to inspect source-level evidence
4. Export results to CSV or JSON

## Security Notes

- Keep secrets in `.env` only.
- Do not commit `.env` to source control.
- `.env.example` is safe to commit and share.

## Documentation

- `docs/setup.md` - setup and troubleshooting
- `docs/uml.md` - architecture and data-flow diagrams
- `docs/sdlc.md` - SDLC and governance notes

## Handoff

Use `threat_lookup_final/` when sharing with a new developer. It contains a runnable package with code, docs, and sample input.

## Disclaimer

This tool is for triage and enrichment. It does not guarantee attribution or definitive incident classification on its own.
