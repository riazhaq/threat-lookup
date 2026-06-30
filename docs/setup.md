# Threat Lookup Setup Guide

## One-time setup (easiest)
1. Run `setup.ps1`
2. Wait for dependency install to finish
3. If prompted, add API keys in `.env`
4. Run `launch_dashboard.bat`
5. Dashboard starts at `http://localhost:8501`

## Daily use
1. Double-click `launch_dashboard.bat`
2. Upload IOC file and run analysis

## Script-based usage (no frontend required)
To use threat_lookup.py directly:
```powershell
Python threat_lookup.py <ioc>
```
Or batch mode:
```python
python -c "from threat_lookup import *; results = asyncio.run(analyze_bulk(['192.168.1.1', 'example.com'], workers=4, delay=0.2, jitter=0.1)); print(results)"
```
Results are returned as dicts and can be exported to CSV or JSON by the calling script. No Streamlit or GUI required.

## API keys
- Core keys are read from `.env`
- Template is in `.env.example`
- If `.env` does not exist, setup creates it automatically

## Troubleshooting
- If setup says Python missing: install Python 3.10+ and rerun setup
- If dashboard does not start: rerun `setup.ps1`
- If a key is invalid: check `.env` and restart dashboard