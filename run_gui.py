import subprocess
import sys
from pathlib import Path

app = Path(__file__).parent / "app.py"
print("Launching dashboard at http://localhost:8501")

# Use module execution to avoid brittle streamlit.exe path detection on Windows.
subprocess.run([sys.executable, "-m", "streamlit", "run", str(app), "--server.port", "8501"])
