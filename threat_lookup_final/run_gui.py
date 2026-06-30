import subprocess, sys, os
from pathlib import Path

python = Path(sys.executable)
# Streamlit may install into the --user scripts dir on Windows
scripts_dirs = [
    python.parent / "Scripts",
    Path(os.environ.get("APPDATA", "")) / "Python" / f"Python{sys.version_info.major}{sys.version_info.minor}" / "Scripts",
]
streamlit_exe = None
for d in scripts_dirs:
    candidate = d / "streamlit.exe"
    if candidate.exists():
        streamlit_exe = candidate
        break

if not streamlit_exe:
    sys.exit("Could not find streamlit.exe. Run: python -m pip install streamlit")

app = Path(__file__).parent / "app.py"
print(f"Launching dashboard at http://localhost:8501")
subprocess.run([str(streamlit_exe), "run", str(app), "--server.port", "8501"])
