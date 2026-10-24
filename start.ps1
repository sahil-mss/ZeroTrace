# Runs the ZeroTrace unified launcher (Backend + Frontend)
if (Test-Path ".venv\Scripts\python.exe") {
    & ".venv\Scripts\python.exe" launch.py
} else {
    python launch.py
}
